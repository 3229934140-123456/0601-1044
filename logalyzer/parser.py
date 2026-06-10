from datetime import datetime
from typing import List, Optional, TextIO, Tuple, Dict
import os
import glob
from .models import LogEntry
from .config import LOG_PATTERNS, ERROR_CODE_PATTERNS, DURATION_PATTERNS, TRACE_ID_PATTERN, REQUEST_ID_PATTERNS, SPAN_ID_PATTERNS, SESSION_ID_PATTERNS
from .utils import parse_timestamp


class LogParser:
    def __init__(self, custom_patterns: Optional[list] = None):
        self.patterns = LOG_PATTERNS + (custom_patterns or [])

    def parse_line(self, line: str, source_file: Optional[str] = None) -> Optional[LogEntry]:
        line = line.rstrip("\n").rstrip("\r")
        if not line.strip():
            return None

        for pattern in self.patterns:
            match = pattern.match(line)
            if match:
                return self._create_entry(match.groupdict(), line, source_file)

        entry = self._parse_fallback(line, source_file)
        return entry

    def _create_entry(self, data: dict, raw_line: str, source_file: Optional[str]) -> LogEntry:
        timestamp = parse_timestamp(data.get("timestamp", "")) or datetime.now()
        level = data.get("level", "INFO").upper()
        service = data.get("service", "unknown")
        trace_id = data.get("trace_id", "")
        message = data.get("message", raw_line)

        error_code = self._extract_error_code(raw_line)
        duration_ms = self._extract_duration(raw_line)
        metadata = self._extract_metadata(raw_line)

        if duration_ms:
            message = self._clean_duration_from_message(message, duration_ms)

        return LogEntry(
            timestamp=timestamp,
            level=level,
            service=service,
            trace_id=trace_id,
            message=message,
            raw_line=raw_line,
            metadata=metadata,
            error_code=error_code,
            duration_ms=duration_ms,
            source_file=source_file,
        )

    def _parse_fallback(self, line: str, source_file: Optional[str]) -> Optional[LogEntry]:
        timestamp = self._extract_timestamp(line)
        if timestamp is None:
            return None

        trace_id = self._extract_trace_id(line) or ""
        level = self._extract_level(line)
        error_code = self._extract_error_code(line)
        duration_ms = self._extract_duration(line)
        metadata = self._extract_metadata(line)

        return LogEntry(
            timestamp=timestamp,
            level=level,
            service="unknown",
            trace_id=trace_id,
            message=line,
            raw_line=line,
            metadata=metadata,
            error_code=error_code,
            duration_ms=duration_ms,
            source_file=source_file,
        )

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        for pattern in self.patterns:
            match = pattern.match(line)
            if match and "timestamp" in match.groupdict():
                return parse_timestamp(match.group("timestamp"))
        return parse_timestamp(line[:30])

    def _extract_level(self, line: str) -> str:
        levels = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"]
        upper_line = line.upper()
        for level in levels:
            if level in upper_line:
                return level
        return "INFO"

    def _extract_trace_id(self, line: str) -> Optional[str]:
        match = TRACE_ID_PATTERN.search(line)
        if match:
            return match.group(1)
        return None

    def extract_id(self, line: str, id_type: str = "trace_id") -> Optional[str]:
        if id_type == "trace_id":
            return self._extract_trace_id(line)
        pattern_map = {
            "request_id": REQUEST_ID_PATTERNS,
            "span_id": SPAN_ID_PATTERNS,
            "session_id": SESSION_ID_PATTERNS,
        }
        patterns = pattern_map.get(id_type, [])
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                return match.group(1)
        return None

    def _extract_error_code(self, line: str) -> Optional[str]:
        for pattern in ERROR_CODE_PATTERNS:
            match = pattern.search(line)
            if match:
                return match.group(1)
        return None

    def _extract_duration(self, line: str) -> Optional[float]:
        for pattern in DURATION_PATTERNS:
            match = pattern.search(line)
            if match:
                value = float(match.group(1))
                if len(match.groups()) >= 2 and match.group(2):
                    unit = match.group(2).lower()
                    if unit == "s":
                        value *= 1000
                    elif unit == "m":
                        value *= 60000
                return value
        return None

    def _extract_metadata(self, line: str) -> Dict[str, str]:
        metadata = {}
        import re
        kv_pattern = re.compile(r'(\w+)=["\']([^"\']+)["\']')
        for match in kv_pattern.finditer(line):
            metadata[match.group(1)] = match.group(2)
        for id_type, patterns in [
            ("request_id", REQUEST_ID_PATTERNS),
            ("span_id", SPAN_ID_PATTERNS),
            ("session_id", SESSION_ID_PATTERNS),
        ]:
            if id_type not in metadata:
                for pattern in patterns:
                    m = pattern.search(line)
                    if m:
                        metadata[id_type] = m.group(1)
                        break
        return metadata

    def _clean_duration_from_message(self, message: str, duration_ms: float) -> str:
        import re
        result = message
        patterns = [
            re.compile(r'\s*\[\d+ms\]\s*$'),
            re.compile(r'\s*duration\s*[=:]\s*[\d.]+\s*(?:ms|s|m)?\s*', re.IGNORECASE),
            re.compile(r'\s*cost\s*[=:]\s*[\d.]+\s*(?:ms|s|m)?\s*', re.IGNORECASE),
            re.compile(r'\s*耗时\s*[:：]\s*[\d.]+\s*(?:ms|s|m)?\s*'),
        ]
        for pattern in patterns:
            result = pattern.sub(' ', result)
        return result.strip()

    def parse_file(self, filepath: str, follow: bool = False) -> Tuple[List[LogEntry], int]:
        entries = []
        line_count = 0
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_count += 1
                entry = self.parse_line(line, source_file=filepath)
                if entry:
                    entries.append(entry)
        return entries, line_count

    def parse_files(self, file_patterns: List[str]) -> Tuple[List[LogEntry], Dict[str, int]]:
        all_entries = []
        file_stats = {}
        for pattern in file_patterns:
            matched_files = glob.glob(pattern, recursive=True)
            if not matched_files and os.path.exists(pattern):
                matched_files = [pattern]
            for filepath in matched_files:
                if os.path.isfile(filepath):
                    entries, line_count = self.parse_file(filepath)
                    all_entries.extend(entries)
                    file_stats[filepath] = line_count
        all_entries.sort(key=lambda e: e.timestamp)
        return all_entries, file_stats
