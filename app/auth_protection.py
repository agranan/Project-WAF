
import time
from collections import defaultdict, deque

MAX_FAILED_ATTEMPTS = 5
WINDOW_SECONDS = 60
LOCKOUT_SECONDS = 300

_failed_attempts: dict[str, deque[float]] = defaultdict(deque)
_locked_until: dict[str, float] = {}


def is_locked(username: str) -> bool:
    now = time.monotonic()
    locked_until = _locked_until.get(username)

    if locked_until is None:
        return False

    if now >= locked_until:
        _locked_until.pop(username, None)
        _failed_attempts.pop(username, None)
        return False

    return True


def record_failed_login(username: str) -> bool:
    """Record a failed attempt; return True if the account is locked."""
    now = time.monotonic()
    attempts = _failed_attempts[username]

    while attempts and now - attempts[0] >= WINDOW_SECONDS:
        attempts.popleft()

    attempts.append(now)

    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        _locked_until[username] = now + LOCKOUT_SECONDS
        return True

    return False


def reset_failed_logins(username: str) -> None:
    _failed_attempts.pop(username, None)
    _locked_until.pop(username, None)
