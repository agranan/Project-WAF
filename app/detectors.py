
import re
from urllib.parse import unquote

SQL_INJECTION_PATTERNS = [
    re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    re.compile(r"\bOR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.IGNORECASE),
    re.compile(r";\s*(DROP|DELETE|UPDATE|INSERT)\b", re.IGNORECASE),
]


def detect_sql_injection(value: str) -> bool:
    decoded_value = unquote(value)

    return any(
        pattern.search(decoded_value)
        for pattern in SQL_INJECTION_PATTERNS
    )
