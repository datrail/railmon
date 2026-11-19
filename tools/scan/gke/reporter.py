"""Pod mode's reporter (RC-513): the sidecar's post to gke-scan, retried safely.

The sidecar posts each scan's bundle to gke-scan, which relays it to Rail
Center and passes Rail Center's answer back (502/503 when Rail Center is
unreachable or refuses gke-scan's own credential, since that is not the
sidecar's to fix). What this module decides is what to do with each answer:

- 2xx: accepted, or a duplicate of bytes already sent. Done.
- 429, 5xx, or no answer at all (a refused connection, a timeout, a TLS
  failure): retried, 5 seconds after the first failure, then doubling each
  time with +/-20% jitter, up to 5 minutes. A `Retry-After` gke-scan passes
  on is honored: the retry is never sooner than it asks (up to an hour).
- Any other answer (401, 403, 409, 413, 422, another 4xx, a refused redirect)
  is final for that bundle: the same bytes would get the same answer. It is
  logged and dropped, and the next scan sends its own bundle.
- Anything that fails before a request is sent (a token file that can't be
  read, say) is final too: nothing is ever sent anonymously instead.

Nothing is queued without bound: one bundle at most waits for a retry. A
scan that finishes while one is waiting replaces it, and goes at the waiting
one's scheduled time, so the newest view is what reaches Rail Center and
gke-scan's backoff is still honored. The first attempt for each bundle is
made by the scan itself, so the scan reports what gke-scan answered; retries
run on one background thread, only in a scanner that keeps running
(`--interval`). A single scan makes its one attempt and exits.

This module imports nothing of railmon's, so it loads by path without a
cycle. The caller passes the post and the error class to raise.
"""

from __future__ import annotations

import random
import sys
import threading
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Callable

# The post to gke-scan, which covers gke-scan's own 15-second post to Rail Center.
POST_TIMEOUT_SECONDS = 30.0
RETRY_FIRST_SECONDS = 5.0
RETRY_MAX_SECONDS = 300.0
RETRY_JITTER = 0.2
# A Retry-After past this is read as this: a newer bundle still replaces the
# waiting one, but a value of days would leave the sidecar silent for days.
RETRY_AFTER_MAX_SECONDS = 3600.0


def is_retryable(status: int | None) -> bool:
    """429 and 5xx are retried; None (no answer) is too. Everything else is final."""
    return status is None or status == 429 or 500 <= status <= 599


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Seconds to wait from a `Retry-After` header: delta-seconds or an
    HTTP-date. None when absent or unreadable; never negative."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    # isdigit() alone takes '²' and other non-ASCII digits, which float() refuses.
    if value.isascii() and value.isdigit():
        return min(float(value), RETRY_AFTER_MAX_SECONDS)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None or when.tzinfo is None:
        return None
    seconds = when.timestamp() - (time.time() if now is None else now)
    return min(max(seconds, 0.0), RETRY_AFTER_MAX_SECONDS)


def backoff_delay(failures: int, rand: Callable[[], float] = random.random) -> float:
    """The wait before the next attempt after `failures` failures in a row
    (1 for the first): 5 s doubling, +/-20% jitter, never past 5 minutes."""
    base = min(RETRY_FIRST_SECONDS * (2 ** max(failures - 1, 0)), RETRY_MAX_SECONDS)
    jittered = base * (1.0 + RETRY_JITTER * (2.0 * rand() - 1.0))
    return min(max(jittered, 0.0), RETRY_MAX_SECONDS)


@dataclass
class _Pending:
    """The one bundle waiting for a retry: how to send it, and what to do with
    the answer once it is accepted."""

    send: Callable[[], dict[str, Any]]
    on_success: Callable[[dict[str, Any]], None]
    generation: int


def _log(message: str) -> None:
    print(f"[agent-environment-scanner] {message}", file=sys.stderr)


class Reporter:
    """Sends bundles to gke-scan, keeping at most the latest one for a retry.

    `send` callables raise on failure; the exception's `status` (int or None)
    and `retry_after` (seconds or None) say what gke-scan answered, and an
    exception without a `sent` attribute set to True is taken to have failed
    before any request left (final). `error` is the exception class `report`
    raises for the caller, so the scanner's own handling applies.
    """

    def __init__(
        self,
        error: type[Exception],
        *,
        background: bool = True,
        clock: Callable[[], float] = time.monotonic,
        rand: Callable[[], float] = random.random,
        log: Callable[[str], None] = _log,
    ) -> None:
        self._error = error
        self._background = background
        self._clock = clock
        self._rand = rand
        self._log = log
        self._cond = threading.Condition()
        # Held for the length of each request: one post to gke-scan at a time.
        self._sending = threading.Lock()
        self._pending: _Pending | None = None
        self._next_at = 0.0
        self._failures = 0
        self._generation = 0
        self._thread: threading.Thread | None = None
        self._closed = False

    # -- the scan's side -------------------------------------------------

    def report(
        self,
        send: Callable[[], dict[str, Any]],
        on_success: Callable[[dict[str, Any]], None] = lambda response: None,
    ) -> dict[str, Any]:
        """Send this scan's bundle now, or leave it waiting in place of an older one.

        Returns gke-scan's answer when it accepted the bundle. Raises `error`
        otherwise, saying whether it will be retried. `on_success` runs only
        for an answer a background retry got; for one returned here, the
        caller handles it.
        """
        with self._cond:
            self._generation += 1
            generation = self._generation
            if self._pending is not None:
                # In backoff: this bundle takes the waiting one's place and its time.
                self._pending = _Pending(send, on_success, generation)
                wait = max(self._next_at - self._clock(), 0.0)
                self._cond.notify_all()
                raise self._error(
                    f"gke-scan registration queued: replaces the bundle waiting for a retry, "
                    f"sent in {wait:.0f}s"
                )
        with self._sending:
            with self._cond:
                if self._pending is not None:
                    # A retry was scheduled while this one waited for the lock.
                    self._pending = _Pending(send, on_success, generation)
                    self._cond.notify_all()
                    raise self._error("gke-scan registration queued: replaces the bundle waiting for a retry")
            try:
                response = send()
            except Exception as exc:  # noqa: BLE001 - classified below, then re-raised as `error`
                self._after_failure(exc, _Pending(send, on_success, generation))
                raise self._error(self._describe(exc, generation)) from exc
        with self._cond:
            self._failures = 0
        return response

    def close(self) -> None:
        """Stop the retry thread; a bundle still waiting is dropped."""
        with self._cond:
            self._closed = True
            self._pending = None
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def wake(self) -> None:
        """Have the retry thread look at the clock again now (for a clock
        that is not time.monotonic, as in the tests)."""
        with self._cond:
            self._cond.notify_all()

    @property
    def waiting(self) -> bool:
        with self._cond:
            return self._pending is not None

    def next_retry_in(self) -> float | None:
        with self._cond:
            if self._pending is None:
                return None
            return max(self._next_at - self._clock(), 0.0)

    # -- classification ----------------------------------------------------

    @staticmethod
    def _status(exc: BaseException) -> int | None:
        status = getattr(exc, "status", None)
        return status if isinstance(status, int) else None

    @staticmethod
    def _was_sent(exc: BaseException) -> bool:
        return getattr(exc, "sent", False) is True

    def _retryable(self, exc: BaseException) -> bool:
        return self._was_sent(exc) and is_retryable(self._status(exc))

    def _after_failure(self, exc: BaseException, attempted: _Pending) -> None:
        """Keep `attempted` for a retry, or drop it, by what gke-scan answered."""
        with self._cond:
            if not self._retryable(exc):
                self._failures = 0
                return
            if not self._background or self._closed:
                return
            self._schedule(exc)
            if self._pending is None or self._pending.generation < attempted.generation:
                self._pending = attempted
            self._ensure_thread()
            self._cond.notify_all()

    def _schedule(self, exc: BaseException) -> float:
        """Count one more failure in a row and set the next attempt's time:
        the backoff, or gke-scan's Retry-After when that is later. Called
        with `_cond` held. Returns the wait."""
        self._failures += 1
        delay = backoff_delay(self._failures, self._rand)
        retry_after = getattr(exc, "retry_after", None)
        if isinstance(retry_after, str):
            retry_after = parse_retry_after(retry_after)
        if isinstance(retry_after, (int, float)) and not isinstance(retry_after, bool) and retry_after > delay:
            delay = min(float(retry_after), RETRY_AFTER_MAX_SECONDS)
        self._next_at = self._clock() + delay
        return delay

    def _describe(self, exc: BaseException, generation: int) -> str:
        status = self._status(exc)
        answer = f"HTTP {status}" if status is not None else "no answer"
        if not self._was_sent(exc):
            return f"{exc}; not sent, not retried"
        if not self._retryable(exc):
            return f"{exc}; {answer} is final for this bundle, not resent"
        wait = self.next_retry_in()
        if wait is None:
            return f"{exc}; {answer}, not retried by a single scan"
        return f"{exc}; {answer}, retrying in {wait:.0f}s"

    # -- the retry thread --------------------------------------------------

    def _ensure_thread(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, name="gke-scan-reporter", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        # The thread is started only from `_after_failure`, and a bundle left
        # waiting makes every later scan queue behind it: if the thread died,
        # nothing would be sent again until a restart. So nothing ends it but
        # `close`: an unexpected error is logged and the bundle backs off.
        while True:
            try:
                if not self._run_once():
                    return
            except Exception as exc:  # noqa: BLE001 - logged, never raised from the thread
                with self._cond:
                    self._failures += 1
                    delay = backoff_delay(self._failures, self._rand)
                    self._next_at = self._clock() + delay
                try:
                    self._log(f"gke-scan registration retry hit an unexpected error: {exc!r}; retrying in {delay:.0f}s")
                except Exception:  # noqa: BLE001 - a failing log must not end the thread either
                    pass

    def _run_once(self) -> bool:
        """Wait for the waiting bundle's time and make one attempt.
        False once the reporter is closed."""
        while True:
            with self._cond:
                while not self._closed:
                    if self._pending is not None:
                        wait = self._next_at - self._clock()
                        if wait <= 0:
                            break
                        self._cond.wait(timeout=min(wait, 1.0))
                    else:
                        self._cond.wait(timeout=1.0)
                if self._closed:
                    return False
            with self._sending:
                with self._cond:
                    item = self._pending
                    if item is None or self._closed:
                        continue
                    if self._next_at > self._clock():
                        continue  # rescheduled while waiting for the lock
                try:
                    response = item.send()
                except Exception as exc:  # noqa: BLE001 - classified and logged, never raised from the thread
                    self._retry_failed(item, exc)
                    return True
            self._retry_succeeded(item, response)
            return True

    def _retry_failed(self, item: _Pending, exc: BaseException) -> None:
        with self._cond:
            replaced = self._pending is not None and self._pending.generation != item.generation
            if self._retryable(exc):
                delay = self._schedule(exc)
                self._log(f"gke-scan registration retry failed: {exc}; retrying in {delay:.0f}s")
                return
            # Final for that bundle. A newer one that replaced it goes now.
            self._failures = 0
            self._next_at = self._clock()
            if not replaced:
                self._pending = None
            self._log(f"gke-scan registration retry failed: {exc}; final for this bundle, not resent")

    def _retry_succeeded(self, item: _Pending, response: dict[str, Any]) -> None:
        with self._cond:
            self._failures = 0
            self._next_at = self._clock()
            if self._pending is not None and self._pending.generation == item.generation:
                self._pending = None
        try:
            item.on_success(response)
        except Exception as exc:  # noqa: BLE001 - the bundle was accepted; only the local state failed
            self._log(f"gke-scan accepted the retried bundle, but keeping its state failed: {exc}")


_REPORTER: Reporter | None = None


def reporter(error: type[Exception], background: bool) -> Reporter:
    """This process's reporter, made on first use. `background` is whether
    the scanner keeps running (`--interval`), so a retry has somewhere to run."""
    global _REPORTER
    if _REPORTER is None:
        _REPORTER = Reporter(error, background=background)
    return _REPORTER
