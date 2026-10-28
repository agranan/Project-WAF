
import time
from collections import defaultdict, deque

from starlette.requests import Request

MAX_REQUESTS = 100
WINDOW_SECONDS = 60

MAX_VIOLATIONS = 3
BAN_SECONDS = 300  # 5 minutes

_requests: dict[str, deque[float]] = defaultdict(deque)
_violations: dict[str, int] = defaultdict(int)
_banned_until: dict[str, float] = {}


def get_client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def is_ip_banned(request: Request) -> bool:
    ip = get_client_ip(request)
    banned_until = _banned_until.get(ip)

    if banned_until is None:
        return False

    if time.monotonic() >= banned_until:
        del _banned_until[ip]
        _violations.pop(ip, None)
        return False

    return True


def is_rate_limited(request: Request) -> bool:
    ip = get_client_ip(request)
    now = time.monotonic()
    timestamps = _requests[ip]

    while timestamps and now - timestamps[0] >= WINDOW_SECONDS:
        timestamps.popleft()

    if len(timestamps) >= MAX_REQUESTS:
        return True

    timestamps.append(now)
    return False


def record_rate_limit_violation(request: Request) -> bool:
    """Record a violation and return True if a ban is applied."""
    ip = get_client_ip(request)
    _violations[ip] += 1

    if _violations[ip] >= MAX_VIOLATIONS:
        _banned_until[ip] = time.monotonic() + BAN_SECONDS
        return True

    return False
