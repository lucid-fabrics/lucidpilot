"""Authorization gate for LucidPilot's my_browser_* tools.

1.2.0 model: licence activation IS the consent moment for browser control.
``auto_authorize_from_license(True)`` is called by the bridge on every
licence assertion (typed key + server check + signed token). There is no
separate ``/lp authorize`` step - typing a 24+ char licence key into the
extension popup and having it verify against the licence server is a
stronger consent signal than typing ``/lp authorize`` once.

The agent CANNOT grant itself access: the licence server is the
authority. ``/lp revoke`` stays as a manual kill switch for the user.
License server-side revocation (refund / chargeback / ban) propagates
to the bridge on the next licence assertion (≤25s typical) and the
auto-grant is automatically revoked - see auto_authorize_from_license.

Two-layer gate:
  * visibility layer: ``is_authorized`` is used as each my_browser_* tool's ``check_fn``
    so the tools do not even appear in the agent's context while locked.
  * runtime layer: ``require_authorized`` is called inside every tool handler
    before talking to the bridge (defense in depth).

Expiry is lazy: there is no timer; ``is_authorized`` compares the stored deadline
against the current time on every call.

A grant carries two clocks, both lazy:
  * the hard cap - the deadline set at authorize time (default 24 hours);
  * the idle lock - IDLE_LOCK_S (1 hour) since the last actual use.
``require_authorized`` stamps last-use on every successful call, so an agent
actively driving Chrome never idle-locks; only true inactivity does. The
default licence auto-grant (auto_authorize_from_license) has no hard cap but
STILL idle-locks after IDLE_LOCK_S unused, so an abandoned session cannot keep
driving. Only an explicit power-user opt-out (``LUCIDPILOT_AUTO_AUTHORIZE=
indefinite``, or ``authorize 'indefinite'``) skips both clocks; those grants
are ``_auto_granted`` False, which is how is_authorized/summary tell the two
apart.

The grant PERSISTS across processes (``~/.hermes/lucidpilot/auth.json``).
It used to be memory-only, which meant every agent restart - and each restart
is frequent - dropped the grant and made the human authorize again, several
times an hour. What the human actually consented to was "Chrome control for
the next 24 hours on this machine", not "until this particular process exits".
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


def _file_stamp() -> tuple | None:
    """(mtime_ns, inode, size) of auth.json, or None when absent/unreadable.

    The inode is what makes the stamp collision-proof: _write_state goes
    through os.replace, so every write is a fresh inode even when two states
    are byte-identical in size and land in the same mtime bucket (coarse
    filesystems; revoke() vs auto-grant differ only by true/false swapped).

    Cheap change detector: is_authorized() stats the file on every call and
    re-reads it only when the stamp moved. This is what makes revoke() in one
    process actually lock every OTHER live process - state used to be read
    once at construction, so a sibling session kept its in-memory grant until
    restart, contradicting the module docstring's "kills it instantly for
    every process".
    """
    try:
        st = os.stat(_STATE_FILE)
        return (st.st_mtime_ns, st.st_ino, st.st_size)
    except OSError:
        return None


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
    def __init__(self, default_timeout_minutes: int = 1440) -> None:
        # None = locked; float = epoch seconds deadline; "indefinite" = until revoked.
        self._authorized_until: float | str | None = None
        # Epoch seconds of the last successful require_authorized() (or the
        # authorize() itself) - drives the idle lock.
        self._last_used: float = 0.0
        # True iff the current grant was issued by auto_authorize_from_license
        # (i.e. as a side-effect of licence activation, not an explicit
        # /lp authorize or operator action). License server-side revocation
        # only revokes AUTO grants - explicit grants (which an operator made
        # for a reason) survive a licence lapse. Cleared on revoke(), on a
        # subsequent explicit authorize() (operator took over), and on
        # license loss.
        self._auto_granted: bool = False
        # True iff the user explicitly ran /lp revoke - the killswitch.
        # While set, auto_authorize_from_license(True) does NOT grant.
        # Cleared by auto_authorize_from_license(False) (server-side loss
        # acts as an implicit reset, so the user isn't permanently locked
        # out if the licence lapses and returns). The only way to clear
        # without a licence round-trip is to manually edit auth.json.
        self._user_revoked: bool = False
        self._default_timeout_minutes = default_timeout_minutes
        self._lock = threading.Lock()
        # Stamp of auth.json as of the last read or write; drives the
        # cross-process re-sync in _sync_if_changed.
        self._state_stamp: tuple | None = None
        self._restore()
        self._auto_authorize()

    def _restore(self) -> None:
        """Mirror auth.json into memory: adopt a still-valid grant, drop a
        grant the file no longer shows. Called at construction and again by
        _sync_if_changed whenever the file changes under us (a sibling
        process revoked, re-granted, or extended).

        Both clocks are re-applied here rather than trusted: a stored grant
        whose cap has passed, or that has sat unused past the idle window, is
        simply not restored - so a file that outlives its validity grants
        nothing, even if it is stale by weeks.

        Caller must hold self._lock (or be the constructor, pre-sharing).
        """
        # Stamp BEFORE reading: if a writer lands between stat and read we
        # keep an older stamp and simply re-read the same content next call.
        self._state_stamp = _file_stamp()
        # Full mirror: reset first so a file that lost its grant (revoke in
        # another process) clears ours instead of being ignored.
        self._authorized_until = None
        self._last_used = 0.0
        state = _read_state()
        until = state.get("authorized_until")
        last_used = state.get("last_used")
        if not isinstance(last_used, (int, float)):
            self._auto_granted = bool(state.get("auto_granted", False))
            self._user_revoked = bool(state.get("user_revoked", False))
            return
        # Persisted flag defaults to False on older state files; if the
        # grant is missing or stale we still return below, so the flag never
        # matters on a missing grant. Carried through here so a process
        # restart preserves the auto-vs-operator distinction.
        self._auto_granted = bool(state.get("auto_granted", False))
        self._user_revoked = bool(state.get("user_revoked", False))
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
        data = {
            "authorized_until": self._authorized_until,
            "last_used": self._last_used,
            "auto_granted": self._auto_granted,
            "user_revoked": self._user_revoked,
        }
        _write_state(data)
        # Adopt our own write's stamp so the next is_authorized doesn't
        # pointlessly re-read what we just wrote. If the write failed
        # (read-only home), the stamp is unchanged and the in-memory grant
        # keeps working for this process, same as before.
        self._state_stamp = _file_stamp()

    def _sync_if_changed(self) -> None:
        """Re-mirror auth.json when its stamp moved. Caller must hold
        self._lock. This is the cross-process propagation path: revoke() in
        any process is observed here by every other process on its next
        is_authorized()/require_authorized() call."""
        if _file_stamp() != self._state_stamp:
            self._restore()

    # -- queries -----------------------------------------------------------

    def is_authorized(self) -> bool:
        """True while a grant is active. Never writes the file; the only
        mutation is re-mirroring auth.json into memory when a sibling
        process changed it (_sync_if_changed), which is the opposite of the
        divergence described below.

        Earlier revisions lazily cleared expired grants in this method. That
        caused a real divergence: a stale in-memory state (the bridge
        started 7 hours ago, last_used was set at startup) reads as idle
        here, the method clears the grant, but the FILE still shows the
        original grant - and because the bridge never re-reads the file,
        the in-memory cleared state wins until something explicitly
        re-grants. End result: the user sees "locked" while the file
        shows a valid 24h grant. Pure read sidesteps this entirely:
        idle-lock is enforced by returning False, the grant is left for
        the next license assertion cycle to re-grant. Cleanup of the
        cleared state happens via revoke() (explicit) or via the next
        license change (license loss + auto-revoke).
        """
        with self._lock:
            self._sync_if_changed()
            return self._is_live_locked()

    def _is_live_locked(self) -> bool:
        """Is the grant on record still doing anything? Caller holds _lock.

        Extracted so that this and auto_authorize_from_license cannot disagree
        about it, which is the whole reason it exists. They used to each decide
        separately: this one refused a dead grant without clearing it, on the
        stated grounds that the next licence assertion would re-grant, while
        auto_authorize_from_license declined to re-grant whenever a grant
        record existed at all. A dead record IS a record, so the assertion
        arrived every minute and changed nothing, and /status printed the
        contradiction out loud: authorized False, beside "authorized for
        ~384m". One function owning the question closes that for good.
        """
        until = self._authorized_until
        now = time.time()
        if until == _INDEFINITE:
            # A licence auto-grant (_auto_granted) has no hard cap but DOES
            # idle-lock: require_authorized stamps _last_used on every tool
            # call, so active driving keeps the session alive and only true
            # inactivity past IDLE_LOCK_S locks it (an abandoned session
            # cannot keep driving). An explicit power-user opt-out
            # (LUCIDPILOT_AUTO_AUTHORIZE=indefinite, or authorize
            # 'indefinite'; _auto_granted False) keeps the original
            # no-clocks meaning.
            if self._auto_granted:
                return now - self._last_used <= IDLE_LOCK_S
            return True
        if isinstance(until, (int, float)) and until > now:
            # Inside the hard cap. Idle still locks it, and the grant is left
            # on record rather than cleared, for the next assertion to revive.
            return now - self._last_used <= IDLE_LOCK_S
        # Until is None, or the hard cap has passed. Locked either way.
        return False

    def require_authorized(self) -> None:
        if not self.is_authorized():
            raise ChromeAuthError(
                "Chrome control locked. Ask the user to activate their "
                "LucidPilot licence in the extension popup (or, if it is "
                "already active, deactivate and re-activate it - that fresh "
                f"assertion re-grants); {command_hint('doctor')} explains why "
                "it is locked. The agent cannot unlock it itself."
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
        # Auto-extend the hard cap while the user is actively driving. Threshold
        # of 4h left means we re-stamp at most every 20h of continuous use
        # (default window 24h), and never on back-to-back calls - cheap, no
        # surprise to a user who paused for a day and came back to find their
        # grant intact. Bypassed entirely for "indefinite" grants: they have
        # no cap to extend. Project rule (memory: lucidpilot-never-extend):
        # the user explicitly opted out of manual Extend; this is the
        # mechanical replacement.
        self._extend_if_active(threshold_s=4 * 3600)

    def extend_on_use(self) -> bool:
        """Extend an active grant to now + default window. Called from the /lp
        slash command so typing `/lp` (even before any my_browser_* call)
        re-winds an idle-locked grant back to a full window. Returns True if
        a grant was extended, False if there was nothing to extend (locked).
        A grant whose hard cap already passed is NOT revived here - explicit
        authorize() is required for that, same as before."""
        with self._lock:
            self._sync_if_changed()
            until = self._authorized_until
            if until is None or until == _INDEFINITE:
                return False
            self._authorized_until = time.time() + self._default_timeout_minutes * 60
            self._last_used = time.time()
            self._persist()
            return True

    def _extend_if_active(self, threshold_s: int) -> None:
        """Internal: silently push the hard cap forward when close to expiry.
        No-op for indefinite grants (they have no cap) and no-op for idle-
        locked grants (is_authorized above already filtered those). Cheap:
        in-memory check + occasional disk write (same throttle as last_used
        above - only when remaining actually drops below threshold)."""
        with self._lock:
            until = self._authorized_until
            if until is None or until == _INDEFINITE:
                return
            remaining = float(until) - time.time()
            if remaining > threshold_s:
                return
            self._authorized_until = time.time() + self._default_timeout_minutes * 60
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
            self._sync_if_changed()
            until = self._authorized_until
            auto = self._auto_granted
            idle_s = time.time() - self._last_used
        if until == _INDEFINITE:
            if not auto:
                return "authorized indefinitely"
            # Licence auto-grant: no hard cap, idle-locks after IDLE_LOCK_S.
            if idle_s <= IDLE_LOCK_S:
                return f"authorized (idle-locks after {IDLE_LOCK_S // 60} min unused)"
            return "idle-locked (re-activate the licence to resume)"
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
                "Unknown authorize duration. Use minutes (30m, 1440, 24h default) "
                "or 'indefinite' (alias: 'yolo')."
            )
        with self._lock:
            self._authorized_until = until
            self._last_used = time.time()
            # Explicit authorize() is an operator action - takes ownership of
            # the grant, license-lapse no longer revokes it. Stays true
            # until revoke() or until the grant expires and re-grant comes
            # through the auto path.
            self._auto_granted = False
            self._persist()
        if until == _INDEFINITE:
            return f"Browser control authorized {label}."
        return (
            f"Browser control authorized for {label} "
            f"(auto-locks after {IDLE_LOCK_S // 60} minutes of inactivity). "
            "Survives agent restarts."
        )

    def auto_authorize_from_license(self, licensed: bool) -> None:
        """Called by the bridge whenever licence state is observed.

        1.2.0 design: licence activation IS the consent moment. There is no
        separate /lp authorize - users paid for and typed a licence key,
        which is already a stronger signal than typing /lp authorize once.

        State machine (called every time the extension pushes a new assertion):

        licensed=True,  unlocked                -> grant indefinite, _auto_granted=true
        licensed=True,  already granted (manual)-> leave alone (operator owns it)
        licensed=True,  already granted (auto)  -> leave alone (still licensed)
        licensed=False, unlocked                -> no-op (never was authorised)
        licensed=False, auto-granted now        -> REVOKE (security: chargeback,
                                                       refund, ban all kill it)
        licensed=False, manually granted        -> leave alone (operator choice
                                                       for a reason; license
                                                       lapse doesn't override
                                                       an explicit grant)

        The /lp revoke path (self.revoke()) clears the auto flag and the
        grant together. A subsequent licence re-assertion would re-grant
        (see test_auto_authorize_from_license_after_revoke_re_grants) -
        that's intentional: the next /lp assertion IS a fresh consent moment.
        """
        with self._lock:
            # Sync first: a sibling process may have just revoked. Without
            # this, our stale in-memory _user_revoked=False would re-grant
            # and _persist would overwrite the revoke on disk.
            self._sync_if_changed()
            if licensed:
                # KILLSWITCH: user explicitly revoked. Auto-grant is paused
                # until the license server reports valid:false (round-trip)
                # OR the user re-enables manually by editing auth.json.
                if self._user_revoked:
                    return
                # A LIVE grant is left alone: it is the operator's, and a
                # background assertion has no business touching it.
                #
                # A DEAD one is not left alone, and the question is decided by
                # _is_live_locked() rather than by "is there a record", which
                # is what deadlocked this before. A record whose hard cap has
                # passed, or that has idle-locked, is still a record, so the
                # old `is not None` test refused to re-grant precisely when
                # re-granting was the only thing that could help. The extension
                # asserted every minute and nothing happened, for ever.
                #
                # The first fix here only revived idle-locked AUTO grants,
                # which was the wrong axis and left a real machine stuck: its
                # grant was manual and had passed its hard cap three hours
                # earlier, so it fell straight through the exception and
                # stayed locked. Whether a dead grant was set by hand or by a
                # licence does not change that it is dead, and nothing of the
                # operator's intent survives in it to protect.
                #
                # Re-granting is not an override: their grant already ended on
                # its own terms, the licence is still valid, and by this
                # design's own words licence activation IS the consent moment.
                # It is also exactly what deactivate-and-reactivate does today,
                # which is the ritual users had to learn instead.
                if self._authorized_until is not None and self._is_live_locked():
                    return
                self._authorized_until = _INDEFINITE
                self._last_used = time.time()
                self._auto_granted = True
                self._persist()
                return
            # licensed=False path: license server revoked (refund / ban).
            # Clear the killswitch flag too - the user can re-enable by
            # re-subscribing. The /lp revoke flag stays until license loss.
            if not self._auto_granted and not self._user_revoked:
                return  # nothing to clear; both flags off
            self._authorized_until = None
            self._last_used = 0.0
            self._auto_granted = False
            self._user_revoked = False
            self._persist()

    def user_revoked(self) -> bool:
        """Did the user explicitly lock control, as opposed to never unlocking it?

        The distinction matters because remote assist is free and local control
        is not. On a machine that never had a licence there is simply no grant,
        so is_authorized() is False for ever - and if that were the only question
        asked, a free requester could never be helped at all. "The user pressed
        revoke" is a different fact from "this machine was never licensed", and
        only the first should stop a helper who is already in a verified session.

        Same pure-read discipline as is_authorized: syncs a sibling process's
        change into memory, never writes.
        """
        with self._lock:
            self._sync_if_changed()
            return self._user_revoked

    def revoke(self) -> str:
        with self._lock:
            self._authorized_until = None
            self._last_used = 0.0
            self._auto_granted = False
            self._user_revoked = True
            self._persist()
        return (
            "Chrome control locked for every session. To re-enable, "
            "deactivate and re-activate the licence in the LucidPilot "
            "extension popup (a fresh licence assertion is the consent "
            "moment that re-grants)."
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
