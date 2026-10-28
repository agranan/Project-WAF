
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

XSS_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"\bon\w+\s*=", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
]


def detect_xss(value: str) -> bool:
    decoded_value = unquote(value)

    return any(
        pattern.search(decoded_value)
        for pattern in XSS_PATTERNS
    )

def detect_path_traversal(value: str) -> bool:
    """
    Detect path traversal patterns such as:
    ../, ..\\, encoded traversal, and double-encoded traversal.
    """
    decoded_value = value

    # Decode repeatedly to catch common encoding variations.
    for _ in range(5):
        new_value = unquote(decoded_value)
        if new_value == decoded_value:
            break
        decoded_value = new_value

    # Treat Windows separators as path separators too.
    normalized_value = decoded_value.replace("\\", "/")

    # Match '..' only when it forms a complete path segment.
    return any(
        segment == ".."
        for segment in normalized_value.split("/")
    )
