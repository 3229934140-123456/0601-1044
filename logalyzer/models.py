from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List
import re


@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    service: str
    trace_id: str
    message: str
    raw_line: str
    metadata: Dict[str, str] = field(default_factory=dict)
    error_code: Optional[str] = None
    duration_ms: Optional[float] = None
    source_file: Optional[str] = None

    @property
    def is_error(self) -> bool:
        return self.level in ("ERROR", "FATAL", "CRITICAL")

    @property
    def is_warn(self) -> bool:
        return self.level in ("WARN", "WARNING")

    def matches_keywords(self, keywords: List[str], case_sensitive: bool = False) -> bool:
        if not keywords:
            return True
        text = self.raw_line if case_sensitive else self.raw_line.lower()
        for kw in keywords:
            kw_text = kw if case_sensitive else kw.lower()
            if kw_text not in text:
                return False
        return True

    def in_time_range(self, start: Optional[datetime], end: Optional[datetime]) -> bool:
        if start and self.timestamp < start:
            return False
        if end and self.timestamp > end:
            return False
        return True


@dataclass
class TraceContext:
    trace_id: str
    entries: List[LogEntry]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    service_path: List[str] = field(default_factory=list)
    has_error: bool = False
    total_duration_ms: float = 0.0

    def __post_init__(self):
        if self.entries:
            sorted_entries = sorted(self.entries, key=lambda e: e.timestamp)
            self.start_time = sorted_entries[0].timestamp
            self.end_time = sorted_entries[-1].timestamp
            self.has_error = any(e.is_error for e in self.entries)
            services = []
            for e in sorted_entries:
                if e.service and e.service not in services:
                    services.append(e.service)
            self.service_path = services
            durations = [e.duration_ms for e in self.entries if e.duration_ms]
            self.total_duration_ms = sum(durations) if durations else 0.0
