import time
from collections import defaultdict, deque

from starlette.requests import Request

MAX_REQUESTS = 10
WINDOW_SECONDS = 30

_requests: dict[str, deque[float]] = defaultdict(deque)


def is_rate_limited(request: Request) -> bool:
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    timestamps = _requests[client_ip]

    while timestamps and now - timestamps[0] > WINDOW_SECONDS:
        timestamps.popleft()

    if len(timestamps) >= MAX_REQUESTS:
        return True

    timestamps.append(now)
    return False