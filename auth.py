"""Authorization gate for LucidPilot's my_browser_* tools.

Chrome control is **locked by default**. The agent can never grant itself access:
authorization is a human action (CLI: ``/lp authorize``; web-ui: an explicit
UI button/confirm that calls this module). The one standing form of that consent
is the LUCIDPILOT_AUTO_AUTHORIZE env var: a human setting it in their own
environment is the same power-user opt-out as ``authorize indefinite``, and it
makes every fresh ``ChromeAuth`` grant itself that duration at construction so
new sessions start unlocked. ``ChromeAuth`` is otherwise a pure state holder:
it records *until when* control is granted; the responsibility for obtaining human
consent belongs to the caller.

Two-layer gate (mirrors the original design):
  * visibility layer: ``is_authorized`` is used as each my_browser_* tool's ``check_fn``
    so the tools do not even appear in the agent's context while locked.
  * runtime layer: ``require_authorized`` is called inside every tool handler
    before talking to the bridge (defense in depth).

Expiry is lazy: there is no timer; ``is_authorized`` compares the stored deadline
against the current time on every call.

A grant carries two clocks, both lazy:
  * the hard cap - the deadline set at authorize time (default 8 hours);
  * the idle lock - IDLE_LOCK_S (1 hour) since the last actual use.
``require_authorized`` stamps last-use on every successful call, so an agent
actively driving Chrome never idle-locks; only true inactivity does. A grant of
``indefinite`` is an explicit power-user opt-out and skips BOTH clocks -
idle-locking it would make the word a lie.

The grant PERSISTS across processes (``~/.hermes/lucidpilot/auth.json``).
It used to be memory-only, which meant every agent restart - and each restart
is frequent - dropped the grant and made the human authorize again, several
times an hour. What the human actually consented to was "Chrome control for
the next 8 hours on this machine", not "until this particular process exits".
Both clocks still apply to a restored grant, so persistence widens nothing:
an 8h grant is still 8h from when it was given, still idle-locks after an
hour unused, and ``revoke`` still kills it instantly for every process.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time

_INDEFINITE = "indefinite"

# Idle window: a still-unexpired grant locks anyway after this much time with
# no require_authorized() call. Keeps an 8h grant from sitting open unattended
# while never interrupting active work (every my_browser_* call refreshes it).
IDLE_LOCK_S = 3600

# Same directory licensing.py uses (and the same env override), so all of
# LucidPilot's per-machine state lives in one place a user can inspect or wipe.
_STATE_DIR = os.path.expanduser(os.environ.get("LUCIDPILOT_LICENSE_DIR", "~/.hermes/lucidpilot"))
_STATE_FILE = os.path.join(_STATE_DIR, "auth.json")


def command_hint(subcommand: str = "") -> str:
    """How the human actually types the /lp command on THIS host.

    Hermes registers it bare (``/lp``); Claude Code namespaces plugin commands
    by plugin id, so the same command is ``/lucidpilot:lp`` there. Every
    user-facing string said ``/lp``, which silently sent Claude Code users to a
    command that answers "Unknown command". Derived from bridge.AGENT (set by
    whichever host loaded the package) rather than guessed.
    """
    try:
        from .bridge import AGENT
    except ImportError:  # standalone/self-check import of this module alone
        AGENT = "hermes"
    base = "/lucidpilot:lp" if AGENT == "claude" else "/lp"
    return f"{base} {subcommand}".strip()


class ChromeAuthError(RuntimeError):
    """Raised by require_authorized when Browser control is locked."""


def _read_state() -> dict:
    try:
        with open(_STATE_FILE, encoding="utf-8") as fh:
            state = json.load(fh)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        # Missing, unreadable, or corrupt: locked. Fail closed, always.
        return {}


def _write_state(state: dict) -> None:
    """Atomic replace, so a crash mid-write can never leave a half-written
    file that _read_state would treat as 'locked' - or worse, as a grant."""
    try:
        os.makedirs(_STATE_DIR, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=_STATE_DIR, prefix=".auth-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, _STATE_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        # Read-only home, full disk, sandbox: the in-memory grant still works
        # for this process. Losing persistence must never break authorizing.
        pass


class ChromeAuth:
    def __init__(self, default_timeout_minutes: int = 480) -> None:
        # None = locked; float = epoch seconds deadline; "indefinite" = until revoked.
        self._authorized_until: float | str | None = None
        # Epoch seconds of the last successful require_authorized() (or the
        # authorize() itself) - drives the idle lock.
        self._last_used: float = 0.0
        self._default_timeout_minutes = default_timeout_minutes
        self._lock = threading.Lock()
        self._restore()
        self._auto_authorize()

    def _restore(self) -> None:
        """Adopt a still-valid grant left by an earlier process.

        Both clocks are re-applied here rather than trusted: a stored grant
        whose cap has passed, or that has sat unused past the idle window, is
        simply not restored - so a file that outlives its validity grants
        nothing, even if it is stale by weeks.
        """
        state = _read_state()
        until = state.get("authorized_until")
        last_used = state.get("last_used")
        if not isinstance(last_used, (int, float)):
            return
        if until == _INDEFINITE:
            self._authorized_until = _INDEFINITE
            self._last_used = float(last_used)
            return
        if not isinstance(until, (int, float)):
            return
        now = time.time()
        if until <= now or now - last_used > IDLE_LOCK_S:
            return
        self._authorized_until = float(until)
        self._last_used = float(last_used)

    def _auto_authorize(self) -> None:
        """Standing consent via LUCIDPILOT_AUTO_AUTHORIZE=<duration|indefinite|1>.

        Only fires when no grant is live, so it never extends an existing
        window; the grant it issues is an ordinary one - both clocks apply
        unless the value is "indefinite". Unset, falsy, or unparseable values
        grant nothing (fail closed, same as everywhere else in this module).
        """
        raw = os.environ.get("LUCIDPILOT_AUTO_AUTHORIZE", "").strip()
        if not raw or raw.lower() in ("0", "false", "no", "off") or self.is_authorized():
            return
        self.authorize(None if raw.lower() in ("1", "true", "yes", "on") else raw)

    def _persist(self) -> None:
        """Caller must hold self._lock."""
        _write_state({"authorized_until": self._authorized_until, "last_used": self._last_used})

    # -- queries -----------------------------------------------------------

    def is_authorized(self) -> bool:
        """True while a grant is active. Lazily clears an expired grant.

        Used as the ``check_fn`` for every my_browser_* tool, so it must be cheap and
        side-effect-light (the only mutation is the same lazy clear-on-expiry
        it always had, now for the idle clock too).
        """
        with self._lock:
            until = self._authorized_until
            if until == _INDEFINITE:
                return True
            now = time.time()
            if isinstance(until, (int, float)) and until > now:
                if now - self._last_used <= IDLE_LOCK_S:
                    return True
                # Idle-locked: still inside the hard cap, but unused for over
                # an hour. Clear it, same lazy pattern as deadline expiry.
                self._authorized_until = None
                self._persist()
                return False
            if until is not None:
                # Expired, clear it so status reflects reality.
                self._authorized_until = None
                self._persist()
            return False

    def require_authorized(self) -> None:
        if not self.is_authorized():
            raise ChromeAuthError(
                f"Chrome control locked. Ask the user to run {command_hint('authorize')} "
                "(or authorize from the extension popup) before using my_browser_* tools."
            )
        # Stamp last-use so active driving keeps the idle clock wound. Written
        # through at most once a minute: this runs on EVERY tool call, and the
        # idle window is an hour - a per-call disk write would buy nothing.
        with self._lock:
            now = time.time()
            was = self._last_used
            self._last_used = now
            if now - was > 60:
                self._persist()

    def authorized_until(self) -> float | str | None:
        """Raw grant deadline for machine consumers (the bridge's /status):
        epoch seconds, "indefinite", or None when locked. Runs the same lazy
        expiry as is_authorized so a stale grant never leaks out."""
        if not self.is_authorized():
            return None
        with self._lock:
            return self._authorized_until

    def summary(self) -> str:
        with self._lock:
            until = self._authorized_until
        if until == _INDEFINITE:
            return "authorized indefinitely"
        if isinstance(until, (int, float)):
            remaining = until - time.time()
            if remaining > 0:
                return f"authorized for ~{max(1, round(remaining / 60))}m"
        return "locked"

    # -- mutations (caller is responsible for human consent) ---------------

    def authorize(self, minutes: int | str | None = None) -> str:
        """Grant Chrome control. Pure state setter: does NOT prompt for consent.

        ``minutes`` accepts an int, a string like ``"30m"`` / ``"45"`` /
        ``"indefinite"`` / ``"forever"``, or None (uses the default window).
        Returns a human-readable status message.
        """
        label, until = self._parse_duration(minutes)
        if until is None:
            return (
                "Unknown authorize duration. Use minutes (30m, 480, 8h default) "
                "or 'indefinite' (alias: 'yolo')."
            )
        with self._lock:
            self._authorized_until = until
            self._last_used = time.time()
            self._persist()
        if until == _INDEFINITE:
            return f"Browser control authorized {label}."
        return (
            f"Browser control authorized for {label} "
            f"(auto-locks after {IDLE_LOCK_S // 60} minutes of inactivity). "
            "Survives agent restarts."
        )

    def revoke(self) -> str:
        with self._lock:
            self._authorized_until = None
            self._persist()
        return (
            f"Chrome control locked. Run {command_hint('authorize')} to allow "
            "my_browser_* tools again."
        )

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _minutes_label(minutes: float) -> str:
        if minutes >= 60 and minutes % 60 == 0:
            hours = int(minutes // 60)
            return "1 hour" if hours == 1 else f"{hours} hours"
        minutes_label = int(minutes) if minutes == int(minutes) else minutes
        return f"{minutes_label} minutes"

    def _parse_duration(
        self, arg: int | str | None
    ) -> tuple[str, float | str | None]:
        """Returns (label, until) where until is an epoch float, "indefinite", or None on parse failure."""
        if arg is None or (isinstance(arg, str) and not arg.strip()):
            minutes = self._default_timeout_minutes
            return self._minutes_label(minutes), time.time() + minutes * 60

        if isinstance(arg, str):
            normalized = arg.strip().lower()
            if normalized in ("indefinite", "forever", "yolo"):
                return "indefinitely", _INDEFINITE
            raw = normalized[:-1] if normalized.endswith(("m", "h")) else normalized
            try:
                minutes = float(raw)
            except ValueError:
                return "", None
            if normalized.endswith("h"):
                minutes *= 60
        else:
            minutes = float(arg)

        if minutes <= 0:
            return "", None
        return self._minutes_label(minutes), time.time() + minutes * 60
