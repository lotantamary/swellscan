"""V2.S14: per-user rate limiter for /score.

In-memory sliding-window counter. Caps each authorized user to
DAILY_LIMIT calls per WINDOW_SECONDS. The check runs at the auth boundary
in `verify_request` so it gates the expensive detector pipeline AND the
LLM call AND the external-API quotas all at once.

Known limitation: Cloud Run scales horizontally. Each instance has its own
in-memory dict. A user could get up to (DAILY_LIMIT x active_instances)
effective calls during a burst that spreads across instances. With
max-instances capped at 10 and DAILY_LIMIT=100, the worst-case ceiling is
1000 calls/user/day - still bounded and far below abuse levels. A
production-grade exact-limit would use Redis / Memorystore (documented as
Future Work in the README).
"""
from collections import defaultdict, deque
import time

DAILY_LIMIT = 100
WINDOW_SECONDS = 24 * 60 * 60

_call_log: dict[str, deque] = defaultdict(deque)


def check_and_record(email: str, now: float | None = None) -> bool:
    """Returns True if call is allowed; False if the user is over their cap.

    Records the call timestamp on accept. Uses a sliding 24h window: stale
    timestamps drop out of the bucket automatically as new calls arrive.
    """
    timestamp = time.time() if now is None else now
    bucket = _call_log[email]
    while bucket and timestamp - bucket[0] > WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= DAILY_LIMIT:
        return False
    bucket.append(timestamp)
    return True


def reset_for_tests() -> None:
    """Clear all per-user state. Test-only helper; not called from prod code."""
    _call_log.clear()
