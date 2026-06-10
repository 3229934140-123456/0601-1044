import re

SENSITIVE_PATTERNS = [
    (re.compile(r'"password"\s*:\s*"[^"]+"', re.IGNORECASE), '"password":"***"'),
    (re.compile(r"'password'\s*:\s*'[^']+'", re.IGNORECASE), "'password':'***'"),
    (re.compile(r'password\s*=\s*[^\s&]+', re.IGNORECASE), 'password=***'),
    (re.compile(r'"token"\s*:\s*"[^"]+"', re.IGNORECASE), '"token":"***"'),
    (re.compile(r"'token'\s*:\s*'[^']+'", re.IGNORECASE), "'token':'***'"),
    (re.compile(r'token\s*=\s*[^\s&]+', re.IGNORECASE), 'token=***'),
    (re.compile(r'"authorization"\s*:\s*"[^"]+"', re.IGNORECASE), '"authorization":"***"'),
    (re.compile(r'"api[_-]?key"\s*:\s*"[^"]+"', re.IGNORECASE), '"api_key":"***"'),
    (re.compile(r'"secret"\s*:\s*"[^"]+"', re.IGNORECASE), '"secret":"***"'),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '***-**-****'),
    (re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'), '**** **** **** ****'),
    (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), '***@***.com'),
    (re.compile(r'\b1[3-9]\d{9}\b'), '1**********'),
]

TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
]

LOG_PATTERNS = [
    re.compile(
        r'^(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
        r'\s+(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)'
        r'\s+(?P<service>[\w-]+)'
        r'\s+(?P<trace_id>[a-f0-9-]{8,})'
        r'\s*:\s*(?P<message>.*)$'
    ),
    re.compile(
        r'^(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
        r'\s+(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)'
        r'\s+\[(?P<service>[^\]]+)\]'
        r'\s+\[(?P<trace_id>[^\]]+)\]'
        r'\s*(?P<message>.*)$'
    ),
    re.compile(
        r'^(?P<timestamp>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})'
        r'\s+(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)'
        r'\s+(?P<service>[\w-]+)'
        r'\s+(?P<trace_id>[a-f0-9-]{8,})'
        r'\s*:\s*(?P<message>.*)$'
    ),
]

ERROR_CODE_PATTERNS = [
    re.compile(r'error[_-]?code["\s:=]+["\']?(\w+[-_]?\d*)["\']?', re.IGNORECASE),
    re.compile(r'"code"\s*:\s*(\d+)'),
    re.compile(r'code\s*=\s*(\d+)'),
    re.compile(r'ErrCode\[(\w+)\]'),
    re.compile(r'状态码\s*[:：]\s*(\d+)'),
]

DURATION_PATTERNS = [
    re.compile(r'duration["\s:=]+["\']?([\d.]+)\s*(ms|s|m)?["\']?', re.IGNORECASE),
    re.compile(r'cost["\s:=]+["\']?([\d.]+)\s*(ms|s|m)?["\']?', re.IGNORECASE),
    re.compile(r'耗时\s*[:：]\s*([\d.]+)\s*(ms|s|m)?'),
    re.compile(r'\[(\d+)ms\]'),
]

TRACE_ID_PATTERN = re.compile(r'\b([a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12})\b', re.IGNORECASE)
