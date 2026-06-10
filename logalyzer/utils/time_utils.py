from datetime import datetime, timedelta
from typing import Optional, Tuple
from ..config import TIME_FORMATS


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    ts_str = ts_str.strip()
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        pass
    return None


def format_timestamp(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    return dt.strftime(fmt)


def parse_time_range(
    start_str: Optional[str] = None,
    end_str: Optional[str] = None,
    last: Optional[str] = None,
) -> Tuple[Optional[datetime], Optional[datetime]]:
    now = datetime.now()
    start = None
    end = None

    if last:
        delta = _parse_duration(last)
        if delta:
            start = now - delta
            end = now
        return start, end

    if start_str:
        start = parse_timestamp(start_str)
        if start is None:
            delta = _parse_duration(start_str)
            if delta:
                start = now - delta
    if end_str:
        end = parse_timestamp(end_str)

    return start, end


def _parse_duration(duration_str: str) -> Optional[timedelta]:
    duration_str = duration_str.strip().lower()
    units = {
        "m": ("minute", 60),
        "h": ("hour", 3600),
        "d": ("day", 86400),
        "s": ("second", 1),
    }
    for suffix, (unit, multiplier) in units.items():
        if duration_str.endswith(suffix):
            try:
                value = int(duration_str[:-1])
                return timedelta(seconds=value * multiplier)
            except ValueError:
                return None
    try:
        value = int(duration_str)
        return timedelta(minutes=value)
    except ValueError:
        return None
