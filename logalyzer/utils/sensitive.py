from typing import List
from ..config import SENSITIVE_PATTERNS


def mask_sensitive_data(text: str, custom_patterns: List[tuple] = None) -> str:
    result = text
    patterns = SENSITIVE_PATTERNS + (custom_patterns or [])
    for pattern, replacement in patterns:
        result = pattern.sub(replacement, result)
    return result
