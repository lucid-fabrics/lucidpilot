"""Loopback HTTP bridge between Hermes and the LucidPilot Chrome extension.

Vendored from hermes-chrome-plugin's ``bridge.py`` (MIT). Keep this file as
close to the upstream original as possible so future re-vendoring is a small
diff; the only intentional deviation is the env var names and default port
below, so LucidPilot's bridge never collides with hermes-chrome-plugin's own
bridge (which stays on port 16319, unmodified) when both run on one machine.

This is a Python port of the Node/TypeScript bridge in
``pi-chrome/extensions/chrome-profile-bridge/index.ts`` (the ``ChromeProfileBridge``
class). The wire protocol is unchanged, so the bundled Chrome extension
(``chrome-extension/``) works against it with **zero modifications**.

Design note (deviates from a pure-asyncio sketch on purpose): the server runs in a
daemon thread using ``ThreadingHTTPServer`` and tool handlers call :meth:`send`
synchronously, blocking on a ``concurrent.futures.Future``. This sidesteps any
question about how the Hermes host runs async tools (fresh loop per call vs.
persistent loop): the bridge owns its own thread and never depends on the
caller's event loop. Tools are therefore registered as sync handlers.

Endpoints:
  GET  /status     local process or pinned extension -> bridge/auth/license status JSON
  GET  /testdrive  local process or pinned extension -> static HTML for the popup's demo
  POST /command    local process  -> enqueue + wait (used by client-mode sessions)
  GET  /next       extension only -> long-poll (<=25s) for the next command
  POST /result     extension only -> deliver a command result
  POST /authorize  extension popup only (Origin required + pinned) -> grant or
                   revoke Chrome control; the human's button click in the
                   popup is the consent auth.py's contract requires
  POST /assert-license  extension only (Origin required + pinned) -> the
                   worker's {valid, tier, lastCheckAt} licence report

Security (mirrors the TS bridge + SECURITY.md):
  * binds 127.0.0.1 only (loopback): no remote port, no telemetry.
  * /next and /result require a browser Origin that is exactly one of the
    *pinned* ``chrome-extension://<id>`` origins (see ``_allowed_extension_ids``
    below), not just any ``chrome-extension://*`` - a plain prefix check would
    let a completely different, unrelated extension installed in the same
    Chrome profile hit these endpoints too, since every extension gets that
    scheme.
  * /status is read-only and side-effect-free, but now carries auth/license
    state (see ``ChromeProfileBridge.status`` below) alongside the always-open
    connection counters, so it gets the same origin pinning as /next and
    /result against foreign browser origins - a random webpage's script
    shouldn't get to read whether Chrome control is currently unlocked any
    more than it should get to queue/deliver commands. A local process (no
    Origin header at all, e.g. curl or ``/lp doctor``) is still allowed,
    matching /next and /result's own local-process allowance.
  * /testdrive is also read-only, static, and carries no per-user data (same
    fixture HTML for everyone) - the origin gate on it is defense-in-depth
    consistency with the rest of this file's posture, not a real requirement,
    same reasoning as /status. It exists because the popup's test-drive demo
    (chrome-extension/src/testdrive.ts) needs a real http(s) URL to click
    through: control.js's own getTabByParams refuses to automate
    chrome-extension:// tabs at all (see its "protected URL" check), so the
    demo can't just open one of the extension's own bundled pages. This
    server is already running whenever the demo is even eligible to run (its
    own auth/license gate reads through this same process), so serving one
    static page from it reuses an already-running server instead of adding a
    new one.
  * /command is accepted only from local non-browser processes.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs
from urllib import request as urllib_request, error as urllib_error
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FuturesTimeout

# Separate env vars and default port from hermes-chrome-plugin's bridge
# (HERMES_CHROME_BRIDGE_HOST/PORT, default 16319) on purpose: LucidPilot and
# the original connector must run side by side on one machine without
# colliding, so a shared env var name would be ambiguous about which bridge
# it targets.
# Which agent this Python process is driving on behalf of. Surfaces in the
# overlay's toast/log label and its accent color (content.ts's AGENT_ACCENTS),
# and names the Chrome tab group. Set by whichever host loaded the package:
# mcp_server.py sets "claude", Hermes's register() leaves the default. Module
# state rather than a parameter threaded through every call because exactly one
# host owns a given Python process - there is no per-call variation to model.
AGENT = "hermes"


def set_agent(name: str) -> None:
    global AGENT
    if name:
        AGENT = name


# Unlike AGENT ("claude"/"hermes" - shared by every process of that kind),
# this is unique PER PROCESS: two simultaneous Claude Code sessions are two
# mcp_server.py subprocesses, each importing this module fresh, each getting
# its own id here. glue.js uses it to remember which tab THIS session was
# last working on (chrome.storage.session, keyed by this value) - without
# it, an untargeted my_browser_* call falls back to Chrome's globally active
# tab, which has no notion of which session put it there, so two sessions
# each minding their own business can still collide on one tab.
SESSION_ID = uuid.uuid4().hex[:12]


DEFAULT_HOST = os.environ.get("LUCIDPILOT_BRIDGE_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("LUCIDPILOT_BRIDGE_PORT", "16329"))
DEFAULT_TIMEOUT_MS = 30_000
_NEXT_LONG_POLL_S = 25.0

_EXTENSION_DIR = os.path.join(os.path.dirname(__file__), "chrome-extension")

# Served verbatim by GET /testdrive (see the module docstring's Security
# section for why this needs to be a real http(s) page rather than a bundled
# chrome-extension:// one). Read from disk on every request rather than
# cached at import time: it's a handful of KB, local disk, and this way an
# edit to the fixture doesn't need a bridge restart to take effect - the same
# tradeoff read_extension_version() already made for manifest.json.
_TESTDRIVE_FIXTURE_PATH = os.path.join(_EXTENSION_DIR, "testdrive-fixture.html")


def extension_load_path() -> Optional[str]:
    """Folder for Chrome's "Load unpacked", or None when the extension isn't built.

    The loadable extension is chrome-extension/dist (produced by `npm run
    build`); the sibling source dir carries manifest.json but only TS sources,
    so pointing Chrome at it yields a broken extension. dist/ is gitignored,
    meaning git-based plugin installs won't have it - callers turn None into a
    "download the release zip or build it" message instead of a dead path.
    """
    dist = os.path.join(_EXTENSION_DIR, "dist")
    if os.path.isfile(os.path.join(dist, "manifest.json")):
        return dist
    return None

# Extension-ID pinning. chrome-extension/manifest.json carries a "key" field
# (an RSA public key, DER/SubjectPublicKeyInfo, base64) whose only purpose is
# making "Load unpacked" assign a STABLE id instead of a random one that
# changes per machine/per-reload. This id is Chrome's own derivation:
# sha256(that DER blob)[:16 bytes], each byte's two nibbles mapped 0-15 ->
# 'a'-'p'. The RSA private key that produced it was never committed anywhere -
# id computation only ever needs the public half, so there is nothing
# sensitive to protect here, just a fixed identity to check against.
#
# Without pinning, "/next"/"/result" only checked that the Origin header
# *looked* like a browser extension (``chrome-extension://`` prefix, see
# _is_browser_origin_allowed below) - true for literally any installed
# extension, not just this one. A malicious or merely buggy sibling extension
# in the same Chrome profile could otherwise long-poll /next and answer with
# forged results, or race the real extension on /result.
_DEV_EXTENSION_ID = "bjgfoabbfphcjlklnonbladkdoljcgel"

# Assigned by Google at the first Chrome Web Store upload (2026-08-09,
# publisher 4b06261c-d974-46de-9d34-1e67475de566). Store installs present
# this origin instead of the dev id above.
_STORE_EXTENSION_ID = "bfebfknclgjglelmlocldhnjkpngelfl"


def _allowed_extension_ids() -> frozenset[str]:
    """The pinned ids above, plus any extra ids from LUCIDPILOT_EXTENSION_IDS.

    Env var (comma-separated) lets ops add another id without a code change
    or a redeploy of this file.
    """
    extra = os.environ.get("LUCIDPILOT_EXTENSION_IDS", "")
    return frozenset(
        {_DEV_EXTENSION_ID, _STORE_EXTENSION_ID, *(x.strip() for x in extra.split(",") if x.strip())}
    )


_ALLOWED_EXTENSION_ORIGINS = frozenset(f"chrome-extension://{i}" for i in _allowed_extension_ids())


def read_extension_version() -> str:
    """The version reported to the extension via ``x-hermes-chrome-version``.

    Must equal the bundled extension's manifest version: the extension reloads
    itself only when the bridge advertises a *newer* version, so reporting the
    bundled version exactly avoids spurious self-reloads.

    dist/ FIRST, then the source manifest. The released zips ship only the
    built extension (chrome-extension/dist/), so reading the source manifest
    alone found nothing there and reported 0.0.0-dev - which then failed the
    version comparison against every real extension and told users to reload a
    perfectly current one. A git checkout has both and they are stamped
    identically, which is exactly why this never showed up in development.
    """
    for candidate in (
        os.path.join(_EXTENSION_DIR, "dist", "manifest.json"),
        os.path.join(_EXTENSION_DIR, "manifest.json"),
    ):
        try:
            with open(candidate, encoding="utf-8") as fh:
                version = str(json.load(fh).get("version") or "")
            if version:
                return version
        except Exception:
            continue
    return "0.0.0-dev"


HERMES_CHROME_VERSION = read_extension_version()

# What read_extension_version() returns when there is no bundled extension to
# read - the Hermes plugin zip ships the Python side only (the extension is a
# separate download), so this is the NORMAL case there, not a broken install.
# Callers must not compare it against the extension's real version: doing so
# nagged every Hermes user to "reload the extension" forever, on a perfectly
# current install.
UNKNOWN_EXTENSION_VERSION = "0.0.0-dev"


def extension_version_is_known() -> bool:
    return HERMES_CHROME_VERSION != UNKNOWN_EXTENSION_VERSION


# How long an extension licence assertion stays fresh. The extension re-asserts
# on every /next poll (<=25s apart while its worker is awake), but MV3 suspends
# service workers and Chrome throttles alarms, so real gaps of a few minutes
# happen on healthy installs. 10 minutes rides those out while still locking
# the Python side within minutes of the extension actually going away. Kept
# deliberately separate from the 5-minute `connected` window: that one answers
# "is the extension polling", this one answers "has it recently vouched for a
# licence", and coupling them would make a connectivity blip a licence event.
_LICENSE_ASSERT_TTL_S = 10 * 60

# The licensing server's ENTITLEMENT_SIGNING public key (raw 32 bytes,
# base64) - the pin that makes /assert-license more than the extension's
# word. The server signs a session token (entitlement blob,
# b64url(payload).b64url(sig)) into every successful /api/licenses/verify
# response; the extension forwards it verbatim and _verify_license_token
# below checks the signature here, offline. LUCIDPILOT_LICENSE_PUBKEY
# overrides for the dev licensing service and for tests; production installs
# never set it. Rotating the prod key means shipping a plugin update - by
# design (a runtime-fetched key would let anyone re-pin it).
_LICENSE_PUBKEY_B64_PROD = "J4Kftnhs+ThoqqhjekV/eWo4AY+SDzWmnc1YuPGh/To="

# Loaded lazily BY FILE PATH (not `import ed25519_verify`) so it works in
# every way this module gets loaded: as part of the plugin package, and by
# tests' importlib-by-path loader where no package parent or sys.path entry
# exists (see the auth field's comment below).
_ED25519_MODULE = None


def _ed25519():
    global _ED25519_MODULE
    if _ED25519_MODULE is None:
        import importlib.util

        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ed25519_verify.py")
        spec = importlib.util.spec_from_file_location("_lucidpilot_ed25519_verify", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        _ED25519_MODULE = module
    return _ED25519_MODULE

# The bridge instance (if any) in THIS process that owns the port - set by
# _bind_server_or_client, read by licensing.is_pro_licensed's fast path.
_SERVER_INSTANCE: Optional["ChromeProfileBridge"] = None


class BridgeError(RuntimeError):
    """Command failed, timed out, or the extension reported an error."""


@dataclass
class BridgeCommand:
    id: str
    action: str
    params: dict


@dataclass
class _Pending:
    command: BridgeCommand
    future: Future
    delivered_at: Optional[float] = None


@dataclass
class ChromeProfileBridge:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT

    # When False the my_browser_* tools focus Chrome so the user can watch; toggled
    # by ``/lp background``. Default True = silent/background.
    background_default: bool = True

    # Wired in by __init__.py's register() right after both objects are
    # constructed, so GET /status can report auth state alongside license
    # state. Typed loosely (duck-typed: anything with is_authorized()/
    # summary()) rather than importing auth.ChromeAuth, on purpose: tests load
    # this file standalone via importlib-by-path with no package parent (see
    # tests/python/test_bridge_extension_pinning.py's loader note), so a
    # top-level ``from .auth import ...`` would break every test in this file,
    # not just the ones touching auth. None (the default, e.g. when nobody
    # wires it up) fails closed - status() reports locked/unauthorized, never
    # the reverse.
    auth: Optional[Any] = None

    _httpd: Optional[ThreadingHTTPServer] = field(default=None, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, repr=False)
    _mode: Optional[str] = None  # "server" | "client" | None
    _last_seen_at: Optional[float] = None
    _client_name: Optional[str] = None

    _queue: list = field(default_factory=list, repr=False)
    _pending: dict = field(default_factory=dict, repr=False)
    _cond: threading.Condition = field(default_factory=threading.Condition, repr=False)
    _start_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # Licence state as asserted BY the extension's POST /assert-license (the
    # popup is the only place a key is ever entered; the Python side never
    # verifies or stores one). None until the first assertion arrives.
    _license_assertion: Optional[dict] = field(default=None, repr=False)
    _license_asserted_at: Optional[float] = None
    # Callbacks fired (outside any lock) when the folded licensed verdict
    # flips on an incoming assertion - mcp_server uses this to emit
    # notifications/tools/list_changed without waiting for the next tools/call.
    # NO CLOCK-DRIVEN CHANGE fires these (nothing ticks in here) - neither
    # the assertion TTL running out nor the session token passing its
    # expiresAt. Both are observed on the next is_licensed() read, which
    # every caller does before acting, so the gate is never wrong; only the
    # advertised tool LIST can lag until the next tools/call. In practice
    # neither drifts silently for long: the extension re-asserts about once a
    # minute, and any assertion that changes the verdict does fire them.
    _license_change_callbacks: list = field(default_factory=list, repr=False)
    _assert_parse_warned: bool = field(default=False, repr=False)

    # Signed-token verdict for the CURRENT assertion: state is one of
    # "missing" | "invalid" | "ok"; claims holds the verified payload's tier
    # and expiresAt when state is "ok" ("expired" is derived at read time -
    # nothing ticks in here). _token_memo caches the last (token, state,
    # claims) so the 1/min re-assert of an unchanged token skips the ~20ms
    # pure-Python verify.
    _license_token_state: str = field(default="missing", repr=False)
    _license_token_claims: Optional[dict] = field(default=None, repr=False)
    _token_memo: Optional[tuple] = field(default=None, repr=False)

    # -- lifecycle ---------------------------------------------------------

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def connected(self) -> bool:
        # MV3 service workers pause between polls; treat a recent poll as connected.
        return self._last_seen_at is not None and (time.time() - self._last_seen_at) < 5 * 60

    def ensure_started(self) -> None:
        with self._start_lock:
            if self._httpd is not None or self._mode == "client":
                return
            self._bind_server_or_client()

    def _bind_server_or_client(self) -> None:
        try:
            httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        except OSError as exc:
            # EADDRINUSE (errno 48 macOS/BSD, 98 Linux, 10048 Windows): another
            # LucidPilot session already owns this port - the intended
            # multi-session coexistence case, so just become its client, no
            # error. Anything else (permission denied, bad address, etc.) is
            # NOT that expected case: a bare OSError there is something like
            # "[Errno 13] Permission denied", which names neither the port nor
            # what to do about it. Wrap it instead of letting it bubble up raw.
            if getattr(exc, "errno", None) in (48, 98, 10048):
                self._mode = "client"
                return
            raise OSError(
                f"LucidPilot bridge failed to bind {self.host}:{self.port}: {exc}. "
                f"Check whether another process (not a LucidPilot session - that case "
                f"is handled automatically) already holds port {self.port}, or set "
                "LUCIDPILOT_BRIDGE_PORT to a free port and retry."
            ) from exc
        httpd.daemon_threads = True
        httpd.bridge = self  # type: ignore[attr-defined]
        self._httpd = httpd
        self._mode = "server"
        # In-process fast path for licensing.is_pro_licensed(): the instance
        # that owns the port holds the extension's licence assertion, and a
        # same-process caller should read it directly instead of an HTTP
        # round trip to itself. Last server wins (there is at most one - the
        # port can only be bound once per machine).
        global _SERVER_INSTANCE
        _SERVER_INSTANCE = self
        self._thread = threading.Thread(
            target=httpd.serve_forever, name="hermes-chrome-bridge", daemon=True
        )
        self._thread.start()

    def _try_promote_to_server(self) -> bool:
        if self._mode != "client":
            return self._mode == "server"
        self._mode = None
        self._bind_server_or_client()
        return self._mode == "server"

    def stop(self) -> None:
        with self._start_lock:
            if self._mode == "client":
                self._mode = None
                return
            with self._cond:
                for pending in list(self._pending.values()):
                    if not pending.future.done():
                        pending.future.set_exception(BridgeError("Chrome profile bridge stopped"))
                self._pending.clear()
                self._queue.clear()
                self._cond.notify_all()
            if self._httpd is not None:
                self._httpd.shutdown()
                self._httpd.server_close()
            self._httpd = None
            self._thread = None
            self._mode = None
            global _SERVER_INSTANCE
            if _SERVER_INSTANCE is self:
                _SERVER_INSTANCE = None

    # -- licence assertions (extension -> Python) --------------------------

    def is_licensed(self) -> bool:
        """The extension recently vouched for a valid licence AND proved it
        with a server-signed, unexpired session token. Fail closed: no
        assertion, a stale one, valid:false, or a missing/invalid/expired
        token all mean "not licensed". The token requirement is what keeps
        this from being the extension's word alone - a client that merely
        POSTs valid:true no longer unlocks anything."""
        if self._license_asserted_at is None or not self._license_assertion:
            return False
        if (time.time() - self._license_asserted_at) > _LICENSE_ASSERT_TTL_S:
            return False
        if self._license_assertion.get("valid") is not True:
            return False
        return self._license_token_read_state() == "ok"

    def _license_token_read_state(self) -> str:
        """Ingest-time state with expiry folded in at read time (nothing
        ticks between assertions, so "expired" can only be derived here)."""
        if self._license_token_state != "ok":
            return self._license_token_state
        expires_at = (self._license_token_claims or {}).get("expiresAt")
        if not isinstance(expires_at, (int, float)) or expires_at <= time.time():
            return "expired"
        return "ok"

    @staticmethod
    def _b64url_decode(part: str) -> bytes:
        pad = "=" * (-len(part) % 4)
        return base64.urlsafe_b64decode(part + pad)

    def _verify_license_token(self, token) -> tuple:
        """(state, claims) for a session token: "missing" (absent/not a
        string), "invalid" (bad structure, bad signature, or a payload that
        is not an ACTIVE lucidpilot entitlement), or "ok" with the verified
        payload. Expiry is deliberately NOT checked here - see
        _license_token_read_state. Never raises."""
        if not isinstance(token, str) or not token:
            return ("missing", None)
        if self._token_memo is not None and self._token_memo[0] == token:
            return (self._token_memo[1], self._token_memo[2])
        state, claims = "invalid", None
        try:
            payload_b64, sig_b64 = token.split(".", 1)
            payload_bytes = self._b64url_decode(payload_b64)
            signature = self._b64url_decode(sig_b64)
            pubkey_b64 = os.environ.get("LUCIDPILOT_LICENSE_PUBKEY") or _LICENSE_PUBKEY_B64_PROD
            public_key = base64.b64decode(pubkey_b64)
            if _ed25519().verify(public_key, payload_bytes, signature):
                payload = json.loads(payload_bytes)
                if (
                    isinstance(payload, dict)
                    and payload.get("v") == 1
                    and payload.get("productId") == "lucidpilot"
                    and payload.get("state") == "ACTIVE"
                ):
                    state, claims = "ok", payload
        except Exception:
            pass  # any parse/decode failure is just "invalid"
        self._token_memo = (token, state, claims)
        return (state, claims)

    def note_license_assertion(self, raw: str) -> None:
        """Store the body of an origin-pinned POST /assert-license.
        Malformed input is ignored (logged once) - a broken report must
        never take the channel down."""
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("assertion is not an object")
        except (ValueError, TypeError):
            if not self._assert_parse_warned:
                self._assert_parse_warned = True
                print("[lucidpilot] ignoring malformed licence assertion from extension", file=sys.stderr)
            return
        was = self.is_licensed()
        self._license_assertion = {
            "valid": parsed.get("valid") is True,
            "tier": parsed.get("tier") if isinstance(parsed.get("tier"), str) else None,
            "lastCheckAt": parsed.get("lastCheckAt"),
        }
        # Signature check at ingest (memoized), expiry folded in at read.
        self._license_token_state, self._license_token_claims = self._verify_license_token(
            parsed.get("token")
        )
        self._license_asserted_at = time.time()
        now = self.is_licensed()
        if was != now:
            for cb in list(self._license_change_callbacks):
                try:
                    cb()
                except Exception:
                    pass  # a listener bug must not break the poll loop

    def on_license_change(self, callback) -> None:
        """Register a zero-arg callable fired when an incoming assertion flips
        the licensed verdict. Called from the /next handler thread."""
        self._license_change_callbacks.append(callback)

    def license_fields(self) -> dict:
        """The licence part of GET /status: what the extension asserted, with
        the TTL already folded into `licensed`. `licenseAssertedAt` (epoch s,
        null before the first assertion) lets callers name the actual cause of
        a denial - key missing vs extension not reporting."""
        claims = self._license_token_claims or {}
        return {
            "licensed": self.is_licensed(),
            # The SIGNED tier outranks the asserted one - the assertion's tier
            # is the extension's word, the claim's tier is the server's.
            "tier": claims.get("tier") or (self._license_assertion or {}).get("tier"),
            "licenseAssertedAt": self._license_asserted_at,
            "licenseTokenState": self._license_token_read_state(),
            # The extension's own (unproven) verdict, so licensing.py can tell
            # "no key entered" (valid:false, generic message) apart from
            # "claims a licence it cannot prove" (valid:true + token not ok -
            # a stale or tampered extension, the update-extension message).
            "licenseAssertedValid": (self._license_assertion or {}).get("valid") is True,
        }

    # -- legacy key migration ---------------------------------------------

    def start_legacy_key_migration(self) -> None:
        """One-shot, backgrounded: if licensing.py still holds a pre-popup-era
        key, hand it to the extension (license.adopt) and delete the local
        copy on success. Backgrounded because the hand-over blocks until the
        extension polls (or times out); a session must not stall its startup
        on that. Server mode only - a client session's owner does this."""
        threading.Thread(
            target=lambda: self.migrate_legacy_key(),
            name="lucidpilot-license-migration",
            daemon=True,
        ).start()

    def migrate_legacy_key(self, timeout_ms: int = 60_000) -> Optional[str]:
        """The actual hand-over; returns a log line (also printed to stderr)
        or None when there was nothing to migrate. Deletes the local key ONLY
        after the extension confirms activation - a failed hand-over keeps it
        and retries on the next session start."""
        if self._mode != "server":
            return None
        try:
            from . import licensing
            key = licensing.legacy_license_key()
        except Exception:
            return None
        if not key:
            return None
        if self.is_licensed():
            # The extension already has a licence; the local copy is dead weight.
            licensing.forget_legacy_license_key()
            return self._log_migration("legacy licence key deleted: the extension is already licensed")
        try:
            result = self._send_local("license.adopt", {"key": key}, timeout_ms)
        except BridgeError as exc:
            return self._log_migration(f"legacy licence key hand-over failed ({exc}); keeping it, will retry next session")
        if isinstance(result, dict) and result.get("ok"):
            licensing.forget_legacy_license_key()
            return self._log_migration("legacy licence key handed to the extension and deleted locally")
        reason = result.get("error") if isinstance(result, dict) else result
        return self._log_migration(f"extension declined the legacy licence key ({reason}); keeping it, will retry next session")

    @staticmethod
    def _log_migration(message: str) -> str:
        print(f"[lucidpilot] {message}", file=sys.stderr)
        return message

    # -- status ------------------------------------------------------------

    def status(self) -> dict:
        return {
            "url": self.url,
            "mode": self._mode or "starting",
            # Named "extensionConnected" (not just "connected") because this
            # endpoint now also reports whether the *bridge itself* is
            # reachable (trivially true if you got any response at all) -
            # those are two different failure modes the popup's health panel
            # tells apart: LucidPilot not running vs. LucidPilot running but
            # the Chrome extension hasn't polled it recently.
            "extensionConnected": self.connected,
            "lastSeenAt": self._last_seen_at,
            "clientName": self._client_name,
            "queuedCommands": len(self._queue),
            "pendingCommands": len(self._pending),
            # Bundled/expected extension version (same value sent via the
            # x-hermes-chrome-version header on /next) - lets any caller,
            # including the popup, compare it against the extension's own
            # chrome.runtime.getManifest().version without a round trip.
            "version": HERMES_CHROME_VERSION,
            "authorized": self.auth.is_authorized() if self.auth else False,
            "authSummary": self.auth.summary() if self.auth else "locked",
            # Raw grant deadline (epoch s | "indefinite" | null) so the popup
            # can render a real countdown instead of parsing authSummary.
            "authorizedUntil": self.auth.authorized_until() if self.auth else None,
            **self.license_fields(),
        }

    # -- send (Hermes -> Chrome) ------------------------------------------

    def send(
        self,
        action: str,
        params: Optional[dict] = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> Any:
        self.ensure_started()
        if self._mode == "client":
            return self._send_via_owner(action, params or {}, timeout_ms)
        return self._send_local(action, params or {}, timeout_ms)

    def _send_local(self, action: str, params: dict, timeout_ms: int) -> Any:
        command = BridgeCommand(id=uuid.uuid4().hex, action=action, params=params)
        future: Future = Future()
        with self._cond:
            self._pending[command.id] = _Pending(command=command, future=future)
            self._queue.append(command)
            self._cond.notify()
        try:
            return future.result(timeout=timeout_ms / 1000)
        except FuturesTimeout:
            with self._cond:
                entry = self._pending.pop(command.id, None)
                self._queue = [c for c in self._queue if c.id != command.id]
            raise BridgeError(self._timeout_message(entry, timeout_ms))

    def _timeout_message(self, entry: Optional[_Pending], timeout_ms: int) -> str:
        poll_age = None if self._last_seen_at is None else (time.time() - self._last_seen_at) * 1000
        if entry is not None and entry.delivered_at:
            return (
                f"Timed out after {timeout_ms}ms: the Chrome extension received the command but "
                "never returned a result. The action may be long-running, or the result post "
                "failed. Run the /lp doctor command; if it persists, reload the LucidPilot Chrome "
                "extension at chrome://extensions."
            )
        if poll_age is None or poll_age > 60_000:
            seen = "never" if poll_age is None else f"{round(poll_age / 1000)}s ago"
            return (
                f"Timed out after {timeout_ms}ms: the Chrome extension is not polling (last seen "
                f"{seen}). Run /lp onboard, then load the bundled chrome-extension folder in "
                "your normal Chrome profile and keep that browser window open."
            )
        return (
            f"Timed out after {timeout_ms}ms: the Chrome extension is polling (last seen "
            f"{round(poll_age / 1000)}s ago) but did not pick up this command in time. Retry; if "
            "it persists, reload the LucidPilot Chrome extension at chrome://extensions."
        )

    def _send_via_owner(self, action: str, params: dict, timeout_ms: int) -> Any:
        body = json.dumps({"action": action, "params": params, "timeoutMs": timeout_ms}).encode()
        req = urllib_request.Request(
            f"{self.url}/command",
            data=body,
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=(timeout_ms + 2_000) / 1000) as resp:
                payload = json.loads(resp.read().decode() or "{}")
        except urllib_error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode() or "{}")
            except Exception:
                payload = {}
            if exc.code == 404:
                raise BridgeError(
                    "A running session owns the browser bridge but is on an older LucidPilot "
                    "without multi-session support. Restart that session, then retry."
                )
            raise BridgeError(payload.get("error") or f"Chrome bridge owner HTTP {exc.code}")
        except (urllib_error.URLError, ConnectionError, OSError):
            # Owner is gone, try to take over the port and run locally.
            if self._try_promote_to_server():
                return self._send_local(action, params, timeout_ms)
            raise BridgeError(
                f"The session that owned the Chrome bridge (port {self.port}) is unreachable, "
                f"and this session could not take over that port either - something else may now "
                f"be bound to it. Check for a stale or unrelated process on port {self.port}, or "
                "set LUCIDPILOT_BRIDGE_PORT to run on a different port. Restart this session, or "
                "run /lp doctor."
            )
        if not payload.get("ok"):
            raise BridgeError(payload.get("error") or "Chrome bridge owner error")
        return payload.get("result")

    # -- queue internals (called by the request handler) -------------------

    def _take_next_command(self) -> Optional[BridgeCommand]:
        """Long-poll: return the next queued command or None after the poll window."""
        deadline = time.monotonic() + _NEXT_LONG_POLL_S
        with self._cond:
            while not self._queue:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)
            command = self._queue.pop(0)
            entry = self._pending.get(command.id)
            if entry is not None:
                entry.delivered_at = time.time()
            return command

    def _deliver_result(self, result: dict) -> bool:
        with self._cond:
            pending = self._pending.pop(result.get("id"), None)
        if pending is None:
            return False
        if pending.future.done():
            return True
        if result.get("ok"):
            pending.future.set_result(result.get("result"))
        else:
            pending.future.set_exception(
                BridgeError(result.get("error") or "Chrome extension command failed")
            )
        return True

    def _mark_seen(self, client_name: Optional[str] = None) -> None:
        self._last_seen_at = time.time()
        if client_name is not None:
            self._client_name = client_name


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

def _cors_headers_for(headers) -> dict:
    origin = headers.get("origin") or ""
    if not origin.startswith("chrome-extension://"):
        return {}
    return {
        "access-control-allow-origin": origin,
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "content-type",
        "access-control-expose-headers": "x-hermes-chrome-version",
        "vary": "origin",
    }


def _is_browser_origin_allowed(headers) -> bool:
    origin = headers.get("origin") or ""
    if origin:
        # Exact match against the pinned allowlist, not a bare
        # "chrome-extension://" prefix check - see _allowed_extension_ids.
        return origin in _ALLOWED_EXTENSION_ORIGINS
    sec = headers.get("sec-fetch-site") or ""
    return sec in ("", "none", "same-origin")


def _is_local_process_request(headers) -> bool:
    return not headers.get("origin") and not headers.get("sec-fetch-site")


def _require_command_licensed(bridge: "ChromeProfileBridge", action: str) -> Optional[str]:
    """None if ``action`` may proceed over POST /command, else the error
    message to send back instead.

    THE GATE this file was missing: chrome_tools.py's my_browser_* handlers all funnel
    through its own ``_send()``, which requires ``auth.require_authorized()``
    AND ``licensing.require_pro_licensed()`` before ever calling
    ``bridge.send()`` - but ``_handle_command`` below is a second, totally
    separate way to reach ``_send_local`` (any local process, e.g. `curl -X
    POST 127.0.0.1:16329/command`) that never passed through chrome_tools.py
    at all, so it never hit that check either. This closes that hole at the
    one place every /command request must pass through, without touching
    chrome_tools.py's gate (kept as-is - see its own module docstring; that
    one hides my_browser_* tools from the agent's context, this one is runtime
    enforcement for a completely different caller).

    No action is exempt. "overlay.fire" (the overlay's wire primitive) used to
    be, back when the indicator was a free tier - LucidPilot has no free tier
    now, so the overlay is licensed like everything else and this function
    gates every action uniformly.

    The verdict is the extension's assertion PLUS the server-signed session
    token it carries (see note_license_assertion): the popup is the only place
    a key is entered, and the extension re-asserts on every poll. Fail closed,
    and NAME the cause - "not licensed" sends a user chasing their key when
    the actual problem is a silent extension, or one whose token no longer
    verifies. The three branches below mirror licensing.require_pro_licensed;
    keep them in step.
    """
    if bridge.is_licensed():
        return None
    fields = bridge.license_fields()
    asserted_at = fields["licenseAssertedAt"]
    stale = asserted_at is None or (time.time() - asserted_at) > _LICENSE_ASSERT_TTL_S
    if stale:
        return (
            "LucidPilot requires an active license, and the Chrome extension has "
            "not reported a licence recently. Check that the LucidPilot extension "
            "is installed and running (chrome://extensions), then run /lp doctor."
        )
    if fields["licenseAssertedValid"] and fields["licenseTokenState"] in ("missing", "invalid", "expired"):
        # Reporting a licence it cannot prove: an extension too old to send a
        # session token, one whose token expired offline, or a tampered one.
        # Must NOT say "enter your key" - this user very likely HAS one, and
        # licensing.require_pro_licensed says the same thing on its own path.
        return (
            "LucidPilot requires an active license, and the Chrome extension "
            "reported one it could not prove. Update the extension to this "
            "release, then open chrome://extensions and click the refresh icon "
            "on it. If it is already current, reconnect to the internet so the "
            "licence can re-verify, then retry."
        )
    try:
        from .licensing import PURCHASE_URL as purchase_url
    except Exception:
        purchase_url = "https://pilot.lucidfabrics.com"
    return (
        "LucidPilot requires an active license. Enter your licence key in the "
        "LucidPilot Chrome extension popup (the only place keys are activated). "
        f"Subscribe at {purchase_url} if you don't have one."
    )


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Silence default stderr logging.
    def log_message(self, *args) -> None:  # noqa: D401
        pass

    @property
    def _bridge(self) -> ChromeProfileBridge:
        return self.server.bridge  # type: ignore[attr-defined]

    def _send_json(self, status: int, body: Any, extra_headers: Optional[dict] = None) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, status: int, body: str, extra_headers: Optional[dict] = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> str:
        length = int(self.headers.get("content-length") or 0)
        return self.rfile.read(length).decode("utf-8") if length else ""

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not _is_browser_origin_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"})
            return
        self._send_json(200, {"ok": True}, _cors_headers_for(self.headers))

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/status":
            self._handle_status()
            return
        if path == "/testdrive":
            self._handle_testdrive()
            return
        if path == "/next":
            self._handle_next()
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/command":
            self._handle_command()
            return
        if path == "/result":
            self._handle_result()
            return
        if path == "/authorize":
            self._handle_authorize()
            return
        if path == "/assert-license":
            self._handle_assert_license()
            return
        self._send_json(404, {"error": "not found"})

    # -- endpoints ---------------------------------------------------------

    def _handle_status(self) -> None:
        if not _is_browser_origin_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"})
            return
        self._send_json(200, self._bridge.status(), _cors_headers_for(self.headers))

    def _handle_testdrive(self) -> None:
        if not _is_browser_origin_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"})
            return
        try:
            with open(_TESTDRIVE_FIXTURE_PATH, encoding="utf-8") as fh:
                html = fh.read()
        except OSError:
            self._send_json(404, {"ok": False, "error": "testdrive fixture missing"})
            return
        self._send_html(200, html, _cors_headers_for(self.headers))

    def _handle_command(self) -> None:
        if not _is_local_process_request(self.headers):
            self._send_json(403, {"ok": False, "error": "Chrome commands are accepted only from local processes"})
            return
        try:
            body = json.loads(self._read_body() or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "Invalid JSON"})
            return
        action = body.get("action")
        if not action:
            self._send_json(400, {"ok": False, "error": "Missing command action"})
            return
        license_error = _require_command_licensed(self._bridge, action)
        if license_error is not None:
            self._send_json(402, {"ok": False, "error": license_error})
            return
        try:
            result = self._bridge._send_local(
                action, body.get("params") or {}, body.get("timeoutMs") or DEFAULT_TIMEOUT_MS
            )
            self._send_json(200, {"ok": True, "result": result})
        except BridgeError as exc:
            self._send_json(504, {"ok": False, "error": str(exc)})

    def _handle_next(self) -> None:
        if not _is_browser_origin_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"})
            return
        qs = parse_qs(urlparse(self.path).query)
        self._bridge._mark_seen((qs.get("name") or [None])[0])
        command = self._bridge._take_next_command()
        version = HERMES_CHROME_VERSION
        headers = {**_cors_headers_for(self.headers), "x-hermes-chrome-version": version}
        if command is not None:
            payload = {
                "type": "command",
                "command": {"id": command.id, "action": command.action, "params": command.params},
                "expectedExtensionVersion": version,
            }
        else:
            payload = {"type": "none", "expectedExtensionVersion": version}
        self._send_json(200, payload, headers)

    def _handle_assert_license(self) -> None:
        # The extension's licence report (glue.js POSTs {valid, tier,
        # lastCheckAt}, never the key). Extension-only, same strictness as
        # /authorize: Origin must be PRESENT and pinned. A POST is the whole
        # design here, not a convenience - Chrome omits the Origin header on
        # GET fetches from an extension worker to a host-permitted origin, so
        # a piggyback header on the GET /next poll arrived origin-less and an
        # origin-pinned bridge could never accept it (the first cut of this
        # feature shipped exactly that hole; sniffed and confirmed on the real
        # extension). Non-GET requests always carry Origin, so the pin holds.
        origin = self.headers.get("origin") or ""
        if origin not in _ALLOWED_EXTENSION_ORIGINS:
            self._send_json(403, {"ok": False, "error": "licence assertions are accepted only from the pinned extension"})
            return
        self._bridge.note_license_assertion(self._read_body())
        self._send_json(200, {"ok": True}, _cors_headers_for(self.headers))

    def _handle_authorize(self) -> None:
        # Extension-only, stricter than _is_browser_origin_allowed on its own:
        # the Origin header must be PRESENT and a pinned chrome-extension://
        # id. A local process has no Origin (it should use /lp instead), and a
        # web page cannot spoof Origin - so the only caller that passes is the
        # popup, where a human clicked a button. That click is the explicit
        # human consent auth.py's contract requires; this endpoint is the
        # "web-ui: an explicit UI button/confirm" its docstring promised.
        origin = self.headers.get("origin") or ""
        if origin not in _ALLOWED_EXTENSION_ORIGINS:
            self._send_json(403, {"ok": False, "error": "authorize is accepted only from the pinned extension popup"})
            return
        auth = self._bridge.auth
        if auth is None:
            self._send_json(503, {"ok": False, "error": "Chrome control is not enabled in this session (no my_browser_* tools registered)."})
            return
        try:
            body = json.loads(self._read_body() or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "Invalid JSON"})
            return
        cors = _cors_headers_for(self.headers)
        if body.get("revoke"):
            message = auth.revoke()
        else:
            minutes = body.get("minutes")
            if not isinstance(minutes, (int, float, str)) and minutes is not None:
                self._send_json(400, {"ok": False, "error": "minutes must be a number, a duration string, or omitted"}, cors)
                return
            message = auth.authorize(minutes)
            if message.startswith("Unknown authorize duration"):
                self._send_json(400, {"ok": False, "error": message}, cors)
                return
        self._send_json(200, {
            "ok": True,
            "message": message,
            "authorized": auth.is_authorized(),
            "authSummary": auth.summary(),
            "authorizedUntil": auth.authorized_until(),
        }, cors)

    def _handle_result(self) -> None:
        if not _is_browser_origin_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"})
            return
        self._bridge._mark_seen()
        try:
            result = json.loads(self._read_body() or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "Invalid JSON"})
            return
        delivered = self._bridge._deliver_result(result)
        cors = _cors_headers_for(self.headers)
        if not delivered:
            self._send_json(404, {"ok": False, "error": "unknown command id"}, cors)
            return
        self._send_json(200, {"ok": True}, cors)
