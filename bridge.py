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
  GET  /next?kind=helper  macOS helper only (token required) -> long-poll for
                   the next app.* command
  POST /assert-helper-status  macOS helper only (token required) -> the
                   helper's {helperVersion, tccAccessibility, ...} report
  GET  /license-token  local processes only (no Origin) -> the raw session
                   token, so a client-mode sibling can mint a relay ticket

Security (mirrors the TS bridge + SECURITY.md):
  * binds 127.0.0.1 only (loopback): no remote port, no telemetry.
  * /next and /result require a browser Origin that is exactly one of the
    *pinned* ``chrome-extension://<id>`` origins (see ``_allowed_extension_ids``
    below), not just any ``chrome-extension://*`` - a plain prefix check would
    let a completely different, unrelated extension installed in the same
    Chrome profile hit these endpoints too, since every extension gets that
    scheme. Neither endpoint grants a local process the origin-less pass
    /status does: /result demands the pinned Origin outright, and /next, which
    cannot (Chrome strips Origin from a worker GET), demands at minimum a
    Sec-Fetch-Site header only a browser can set. Both refuse the
    header-less request _is_local_process_request defines, because a local
    process that reached /next would be taking a queued command away from the
    extension and answering it. See ``_is_extension_poll_allowed``.
  * /status is read-only and side-effect-free, but now carries auth/license
    state (see ``ChromeProfileBridge.status`` below) alongside the always-open
    connection counters, so it gets the same origin pinning as /next and
    /result against foreign browser origins - a random webpage's script
    shouldn't get to read whether Chrome control is currently unlocked any
    more than it should get to queue/deliver commands. A local process (no
    Origin header at all, e.g. curl or ``/lp doctor``) is still allowed here,
    and is the one endpoint of the three that still allows it: /status only
    reads state, so a local process gains nothing it could not already learn
    by reading ~/.hermes/lucidpilot/auth.json itself, whereas /next and
    /result hand out and settle queued commands.
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
  * the macOS helper (a native process, so it has no Origin header at all)
    authenticates with a shared-secret token file instead: the server-mode
    bridge writes ~/.hermes/lucidpilot/helper-token (0600) and the helper
    presents its contents in the x-lucidpilot-helper-token header. This
    proves "running as this user", not "is the signed helper binary" - the
    same trust level every local process already has on /command.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
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

# How stale the extension's last poll may be before a NEW command fails
# immediately instead of waiting out its whole timeout. The extension polls
# every _NEXT_LONG_POLL_S, so 60s is two missed windows: silent that long
# means gone (Chrome closed, extension disabled), not busy. Same threshold
# _timeout_message uses to pick the "not polling" wording, on purpose - the
# fail-fast and the timeout tell the same story.
_POLL_STALE_MS = 60_000
# ...and how long the FIRST ever command waits for the FIRST ever poll, when
# the bridge has just started and the extension may still be waking up.
_FIRST_POLL_GRACE_S = 5.0

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

# The Chrome Web Store is the only extension distribution channel (no zip,
# no unpacked-from-a-plugin-install) - commands.py/_onboard and
# chrome_tools.py/my_browser_launch both point here when no built
# chrome-extension/dist exists locally to load unpacked instead.
CHROME_WEB_STORE_URL = f"https://chromewebstore.google.com/detail/{_STORE_EXTENSION_ID}"


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


# What read_extension_version() returns when there is no bundled extension to
# read - the Hermes plugin zip ships the Python side only (the extension is a
# separate download), so this is the NORMAL case there, not a broken install.
# Callers must not compare it against the extension's real version: doing so
# nagged every Hermes user to "reload the extension" forever, on a perfectly
# current install.
UNKNOWN_EXTENSION_VERSION = "0.0.0-dev"


def extension_version_is_known() -> bool:
    return _current_extension_version() != UNKNOWN_EXTENSION_VERSION


# Per-call version lookup. Read on every use instead of caching at module
# import: a stale bridge started before a plugin update would otherwise keep
# reporting the old version forever, and every other Claude session that opens
# inherits the stale number from the on-disk auth/extension state. File I/O is
# sub-millisecond (one tiny JSON; in-process cache would buy nothing for one
# read per /status or /next call).
def _current_extension_version() -> str:
    return read_extension_version()


# ---------------------------------------------------------------------------
# macOS helper client. The helper is a second poller of GET /next, kept apart
# from the Chrome extension by (a) action namespace - app.* is the helper's,
# everything else is the extension's - and (b) a shared-secret token, since a
# native process has no Origin header for the pinning above to check.
# ---------------------------------------------------------------------------

_VERSION_FILE = os.path.join(os.path.dirname(__file__), "VERSION")


def _plugin_version() -> str:
    """The Python plugin's own version (root VERSION file), advertised to the
    helper via the x-lucidpilot-version header on /next. Same sentinel
    semantics as UNKNOWN_EXTENSION_VERSION: released plugin zips ship VERSION,
    so "0.0.0-dev" means "can't know", and callers must not compare it
    against the helper's real version (see extension_version_is_known)."""
    try:
        with open(_VERSION_FILE, encoding="utf-8") as fh:
            version = fh.read().strip()
        return version or UNKNOWN_EXTENSION_VERSION
    except OSError:
        return UNKNOWN_EXTENSION_VERSION


# Same directory (and same import-time env read) as _UPDATE_CHECK_CACHE_PATH
# above - the test suite's LUCIDPILOT_LICENSE_DIR redirect must cover this
# file too, or tests would read/write the developer's real helper token.
_HELPER_TOKEN_PATH = os.path.join(
    os.environ.get("LUCIDPILOT_LICENSE_DIR", "~/.hermes/lucidpilot"), "helper-token"
)


def helper_token() -> str:
    """Read the helper's shared secret, creating it on first use.

    NEVER rotates an existing token: the bridge port can hand over between
    sessions (_try_promote_to_server), and a rotation on every bind would 403
    a helper that is already running mid-poll. Read fresh on every check (no
    caching) so a token file rewritten by another process is honored on the
    next request - the file is the single source of truth. 0600 in a 0700
    dir, same atomic mkstemp+os.replace shape as _write_update_cache."""
    path = os.path.expanduser(_HELPER_TOKEN_PATH)
    try:
        with open(path, encoding="utf-8") as fh:
            token = fh.read().strip()
        if token:
            return token
    except OSError:
        pass
    token = secrets.token_urlsafe(32)
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".helper-token-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(token)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        # Could not persist (read-only state dir): the in-memory token still
        # lets this process answer consistently within one run; the helper
        # simply can't connect, which /lp doctor reports as such.
        pass
    return token


def _is_helper_request(headers) -> bool:
    """True when the request presents the current helper token. Constant-time
    compare; an absent header is an immediate False (the extension and every
    browser request land here headerless)."""
    presented = headers.get("x-lucidpilot-helper-token") or ""
    if not presented:
        return False
    try:
        return hmac.compare_digest(presented, helper_token())
    except Exception:
        return False


def _command_kind(action: str) -> str:
    """Which poller may receive this action: "helper" for app.*, "extension"
    for everything else. Prefix-based on purpose - a new app.<verb> needs no
    edit here, and an unknown prefix falls to the extension, which is what
    every pre-helper action already is."""
    return "helper" if isinstance(action, str) and action.startswith("app.") else "extension"


# ---------------------------------------------------------------------------
# Plugin update check. Queries GitHub's public Releases API for the latest
# published release; cache-first with a 24h TTL so the start path stays fast
# and offline-tolerant, never blocks on the network, and never spams the
# user when the API is rate-limited or unreachable. Designed to be safe to
# call from any code path: it catches every exception and degrades to "no
# notice" rather than ever raising back to the caller.
# ---------------------------------------------------------------------------

_UPDATE_CHECK_URL = "https://api.github.com/repos/lucid-fabrics/lucidpilot/releases/latest"
_UPDATE_CHECK_TTL_S = 24 * 3600
_UPDATE_CHECK_TIMEOUT_S = 5
# Same directory (and same env override) as auth.py/licensing.py, so ALL
# per-machine state lives in one inspectable dir - and so the test suite's
# LUCIDPILOT_LICENSE_DIR redirect covers this cache too, instead of test-
# spawned bridges reading/writing the developer's real ~/.hermes cache.
_UPDATE_CHECK_CACHE_PATH = os.path.join(
    os.environ.get("LUCIDPILOT_LICENSE_DIR", "~/.hermes/lucidpilot"), "version-check.json"
)


def _parse_version(s: str) -> tuple:
    """Parse a semver-ish string into a comparable tuple.

    Handles leading 'v' and optional '-' pre-release suffix (which sorts
    BEFORE the same base version: 1.2.0-rc1 < 1.2.0). Anything that doesn't
    parse as major.minor.patch falls back to (0,) so it never compares as
    "newer" than a real release.
    """
    s = (s or "").strip().lstrip("v")
    base, _, pre = s.partition("-")
    try:
        nums = tuple(int(p) for p in base.split("."))
    except (ValueError, AttributeError):
        return (0,)
    # Pre-release marker: anything with a '-' suffix sorts BEFORE the same
    # base. We don't compare pre-release identifiers to each other (1.2.0-rc1
    # vs 1.2.0-rc2 is undefined here - both older than 1.2.0, and the
    # stable-channel filter upstream in _fetch_latest_release means
    # prereleases never even reach this compare).
    if pre:
        return nums + (0,)
    return nums + (1,)


def _compare_versions(a: str, b: str) -> int:
    """-1 if a<b, 0 if equal, 1 if a>b. Semver-style: 1.10.0 > 1.9.0."""
    va, vb = _parse_version(a), _parse_version(b)
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def _read_update_cache() -> dict:
    """Read the cache file. Returns {} on missing file, JSON error, or wrong shape."""
    path = os.path.expanduser(_UPDATE_CHECK_CACHE_PATH)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_update_cache(data: dict) -> None:
    """Atomic write, same shape as auth._write_state: mkstemp (a FIXED .tmp
    name let two concurrent processes clobber each other's half-written
    JSON), makedirs 0o700 (this can be the first writer to create the
    secret-bearing state dir on a fresh install - a default-umask 755 dir
    would leave auth.json's directory world-listable), os.replace so a crash
    mid-write never corrupts the cache. Best-effort: never raises."""
    path = os.path.expanduser(_UPDATE_CHECK_CACHE_PATH)
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".version-check-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass


def _fetch_latest_release() -> dict | None:
    """Hit GitHub Releases API once. Returns the parsed release dict or None.

    - 5s timeout (worst case bound for the start path)
    - 404 / no tag / prerelease -> None (nothing to compare against)
    - Any network / parse error -> None
    - Privacy: hits api.github.com with no body, no auth; GitHub sees the
      user's IP. Acceptable for an open-source plugin's check endpoint; if
      that ever changes, the URL is one constant above.
    """
    try:
        req = urllib_request.Request(
            _UPDATE_CHECK_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "lucidpilot-update-check",
            },
        )
        with urllib_request.urlopen(req, timeout=_UPDATE_CHECK_TIMEOUT_S) as resp:
            if resp.status != 200:
                return None
            payload = json.loads(resp.read())
    except (urllib_error.URLError, urllib_error.HTTPError, OSError, ValueError):
        return None

    tag = payload.get("tag_name")
    if not tag or not isinstance(tag, str):
        return None  # no releases published yet, or GitHub returned something weird
    if payload.get("prerelease", False):
        return None  # stable channel only; betas never trigger "behind"

    body = payload.get("body") or ""
    first_line = body.splitlines()[0].strip() if body else ""

    return {
        "version": tag.lstrip("v"),
        "url": payload.get("html_url") or "",
        "notes": first_line[:120],
        "fetched_at": time.time(),
    }


def check_plugin_update(*, force: bool = False) -> dict | None:
    """Cache-first update check.

    Returns the latest-release dict if a NEWER version exists, None otherwise.
    Used by:
    - `_maybe_print_update_notice` at CLI startup (fire-and-forget stderr)
    - `/lp doctor` (verbose mode, prints version status)
    - `/lp upgrade` (decides whether to print install instructions)

    Suppression (`suppress_until` in the cache) takes precedence over cache
    age and over the live network result, so a user who has dismissed an
    update for a week does not see it on every start.

    `force=True` skips the cache TTL and re-hits the network. Used by
    /lp upgrade so the user can opt out of the 24h cache on demand.
    """
    try:
        # Hard off-switch for the CHECK path: no cache read, no cache write,
        # no network from here. (suppress_update_notice still writes its
        # dismissal to the cache - deliberate, it is user intent, not a
        # check.) Set by the test suite (conftest.py) so test-spawned bridges
        # can never hit api.github.com; also an escape hatch for air-gapped
        # installs.
        if os.environ.get("LUCIDPILOT_NO_UPDATE_CHECK"):
            return None
        now = time.time()
        cache = _read_update_cache()

        suppress_until = float(cache.get("suppress_until") or 0)
        if suppress_until > now:
            return None

        last_checked = float(cache.get("last_checked") or 0)
        cached_result = cache.get("last_result") if isinstance(cache.get("last_result"), dict) else None

        if not force and last_checked and (now - last_checked) < _UPDATE_CHECK_TTL_S:
            result = cached_result
        else:
            result = _fetch_latest_release()
            cache["last_checked"] = now
            cache["last_result"] = result
            _write_update_cache(cache)

        if not result:
            return None

        current = _current_extension_version()
        if _compare_versions(current, result["version"]) >= 0:
            return None  # current >= latest, nothing to notify

        return result
    except Exception:
        # Never raise from the update check: a corrupt cache or a transient
        # error must not break the bridge's start path.
        return None


def suppress_update_notice(weeks: int = 1) -> None:
    """Mark the update notice as dismissed for `weeks` weeks. /lp doctor
    will still show the version status; this only suppresses the CLI-startup
    one-liner. User-side escape hatch when they KNOW they're behind and
    don't want the noise every start."""
    try:
        cache = _read_update_cache()
        cache["suppress_until"] = time.time() + weeks * 7 * 24 * 3600
        _write_update_cache(cache)
    except Exception:
        pass


def _maybe_print_update_notice() -> None:
    """Fire-and-forget startup hook. Logs one stderr line if a newer release
    exists. Never blocks, never raises, never more than one line."""
    try:
        result = check_plugin_update()
        if not result:
            return
        current = _current_extension_version()
        notes = result.get("notes") or ""
        suffix = f": {notes}" if notes else ""
        print(
            f"[lucidpilot] v{current} → v{result['version']} available{suffix}. /lp upgrade",
            file=sys.stderr,
            flush=True,
        )
    except Exception:
        pass


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
# overrides for the dev licensing service and for tests, but only when
# LUCIDPILOT_DEV is also set (see _verify_license_token); a bare export on a
# production install is ignored, so it can't self-pin a self-signed token.
# Rotating the prod key means shipping a plugin update - by design (a
# runtime-fetched key would let anyone re-pin it).
#
# ROTATED 2026-08-25: the licensing worker's ENTITLEMENT_SIGNING keypair was
# rotated to kid bb-2026-08 on 2026-08-24 (fresh pair provisioned for the
# BitBonsai cloud-auth launch; private half lives only in Cloudflare's secret
# store). The old pin kept verifying every client's CACHED token until that
# token's own expiry, so the breakage surfaced machine by machine, days after
# the rotation, at midnight boundaries - if a licence "goes invalid" with a
# fresh assertion, check WHICH kid signed the asserted token before touching
# anything else. Old key, for reading tokens minted before the rotation:
# J4Kftnhs+ThoqqhjekV/eWo4AY+SDzWmnc1YuPGh/To=
_LICENSE_PUBKEY_B64_PROD = "Q0VdgQOafLKiq8LpgwIVBklQFn1K8vZ1A42PCeN1wkU="

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


class CommandRefused(BridgeError):
    """A command stopped at one of execute_gated's two gates.

    Carries the HTTP status POST /command answers with, so the wording and the
    status code stay together instead of the handler re-deriving one from the
    other. A BridgeError subclass because every caller of bridge.send() and of
    execute_gated already handles BridgeError, and a refusal is a command that
    did not run - which is what that type means.
    """

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


# The revoke killswitch's wording, in one place because two callers now say it:
# POST /command and remote assist's command loop. A remote helper reads it too,
# so it names the requester's own popup rather than assuming the reader is
# sitting in front of the machine.
_CONTROL_LOCKED_MESSAGE = (
    "Chrome control is locked (user revoke, idle lock, or "
    "expired grant). A fresh licence assertion re-grants: if "
    "this persists, deactivate and re-activate the licence in "
    "the LucidPilot extension popup, then run /lp doctor."
)


# Set while THIS process is the helper in a remote assist session: every command
# it sends goes over the relay to the requester's machine instead of to a bridge
# on this one. Module state rather than a field on ChromeProfileBridge for the
# same reason AGENT is module state - a process is in one assist session or in
# none, and there is no per-instance variation to model. remote.py builds the
# callable (remote.helper_sender); bridge.send is the only reader.
_REMOTE_SENDER: "Optional[Callable[[str, dict, int], Any]]" = None


def set_remote_sender(sender: "Optional[Callable[[str, dict, int], Any]]") -> None:
    """Route this process's commands over a remote assist session, or stop.

    ``sender(action, params, timeout_ms)`` returns the command's result or
    raises. Pass None to hand the process back to its local bridge, which is
    what ending a session does. Only ``send(..., remotable=True)`` consults it,
    so this process's own overlay and its own /lp doctor keep running here while
    the agent's tool calls run on the requester's machine.
    """
    global _REMOTE_SENDER
    _REMOTE_SENDER = sender


# Set while THIS process is the REQUESTER in a remote assist session: calling it
# ends that session on this machine. Module state for the same reason as
# _REMOTE_SENDER above. commands.py installs it when a share goes live and
# clears it when the share ends; POST /remote-stop is the only other caller, and
# it exists so the two Stop controls the user can actually see - the one in the
# in-page indicator and the one in the menu bar - reach the serving loop. Both
# of those live in another process (Chrome, and the Mac helper app), and the
# loopback bridge is the only thing all three share.
_REMOTE_STOP: "Optional[Callable[[], None]]" = None


def set_remote_stop(stop: "Optional[Callable[[], None]]") -> None:
    """Register (or clear) the way to end this machine's live share.

    Idempotent by contract: /remote-stop can be pressed twice, and the in-page
    control and the menu-bar row can both be pressed for the same session.
    """
    global _REMOTE_STOP
    _REMOTE_STOP = stop


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

    # The macOS helper's own liveness slots. Kept SEPARATE from the extension's
    # _last_seen_at/_client_name above on purpose: `connected` /
    # `extensionConnected` keep meaning the extension everywhere they are read
    # today (popup.ts, doctor, redirect gating), and each command family
    # fail-fasts on its own poller's staleness, not the other's.
    _helper_seen_at: Optional[float] = None
    _helper_name: Optional[str] = None
    # Last POST /assert-helper-status body (validated) + assertedAt. Always
    # REPLACED whole, never mutated in place - readers take unlocked
    # snapshots, same convention _poll_age_ms documents for _last_seen_at.
    _helper_status: Optional[dict] = field(default=None, repr=False)

    # Who this machine is currently shared with in a remote assist session, or
    # None. Handed to the macOS helper on every GET /next?kind=helper so its
    # menu bar can say so and offer a Stop row - see set_remote_share.
    _remote_share: Optional[str] = None

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
    # Guards the four assertion fields below plus _token_memo: writes arrive
    # on ThreadingHTTPServer request threads while tool-handler threads read,
    # and an unguarded update could pair a new assertion with the previous
    # token state for one read.
    _license_state_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # Signed-token verdict for the CURRENT assertion: state is one of
    # "missing" | "invalid" | "ok"; claims holds the verified payload's tier
    # and expiresAt when state is "ok" ("expired" is derived at read time -
    # nothing ticks in here). _token_memo caches the last (token, state,
    # claims) so the 1/min re-assert of an unchanged token skips the ~20ms
    # pure-Python verify.
    _license_token_state: str = field(default="missing", repr=False)
    _license_token_claims: Optional[dict] = field(default=None, repr=False)
    # The raw signed blob itself, kept ONLY while its state is "ok": it is the
    # credential licensing.relay_ticket() presents to the licensing worker, so
    # the licence key never has to exist on the Python side. Cleared whenever
    # verification fails, so a stale or tampered token cannot be re-presented.
    _license_token_raw: Optional[str] = field(default=None, repr=False)
    _token_memo: Optional[tuple] = field(default=None, repr=False)

    # -- lifecycle ---------------------------------------------------------

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def connected(self) -> bool:
        # MV3 service workers pause between polls; treat a recent poll as connected.
        return self._last_seen_at is not None and (time.time() - self._last_seen_at) < 5 * 60

    @property
    def helper_connected(self) -> bool:
        # Same staleness window as the extension's `connected` - the helper is
        # a native process that polls more reliably, but one shared constant
        # beats a second tuning knob until a false "connected" ever bites.
        return self._helper_seen_at is not None and (time.time() - self._helper_seen_at) < 5 * 60

    def ensure_started(self) -> None:
        with self._start_lock:
            if self._httpd is not None or self._mode == "client":
                return
            self._bind_server_or_client()
            # Fire-and-forget update notice on first start of this bridge.
            # Synchronous here is safe: the check itself is cache-first, so
            # only the first-ever start (cold cache, offline) does a network
            # call, and that is bounded by _UPDATE_CHECK_TIMEOUT_S (5s).
            # Worst case: bridge start is delayed by 5s on the very first
            # ever run on a machine with no network. After that, the 24h
            # cache makes this a no-op.
            _maybe_print_update_notice()

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
        # Make sure the helper's token file exists the moment /next could be
        # served, so a helper starting right after this bridge finds it.
        # Best-effort: helper_token() itself degrades to in-memory on OSError.
        try:
            helper_token()
        except Exception:
            pass
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
        with self._license_state_lock:
            return self._is_licensed_locked()

    def _is_licensed_locked(self) -> bool:
        """Caller must hold _license_state_lock.

        There is deliberately NO "has the extension spoken lately" check here
        any more, and removing it is the fix for a bug that locked working
        machines several times a day.

        It used to refuse when the last assertion was older than
        _LICENSE_ASSERT_TTL_S, meaning to catch an extension that had stopped
        reporting. The problem is that "stopped reporting" and "Chrome
        suspended the service worker" are the same signal. MV3 workers are
        suspended aggressively, alarms do not fire while the Mac is asleep,
        and a laptop that slept for eleven minutes woke up to a revoked
        grant and a message telling its owner to go and re-activate a licence
        that had never stopped being valid. The only reliable way out was
        another command that happened to wake the worker, which is why this
        looked like "/lp doctor fixes it".

        What actually proves the licence is the server-signed session token:
        Ed25519, machine-bound, with its own expiresAt, checked below by
        _license_token_read_state(). That is the authority and it is the one
        the licensing design intends ("period-end-bound"). A wall clock over
        the top of it added no security that the token does not already
        provide, and subtracted a working browser every time a machine slept.

        What this costs, stated plainly: an extension that is uninstalled or
        disabled leaves this machine licensed until the token itself expires,
        rather than for ten more minutes. That window is the offline grace the
        token was issued with on purpose, and app.* control is the only thing
        that could still run in it, since page.* needs the very extension that
        just went away.
        """
        if self._license_asserted_at is None or not self._license_assertion:
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
            # Dev/test seam, not a supported user knob: the env pubkey is
            # honored only when LUCIDPILOT_DEV is also set. A bare
            # LUCIDPILOT_LICENSE_PUBKEY export on a production install is
            # ignored, so it can't self-pin a self-signed ACTIVE token.
            env_pubkey = os.environ.get("LUCIDPILOT_LICENSE_PUBKEY") if os.environ.get("LUCIDPILOT_DEV") else None
            pubkey_b64 = env_pubkey or _LICENSE_PUBKEY_B64_PROD
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
        with self._license_state_lock:
            self._license_assertion = {
                "valid": parsed.get("valid") is True,
                "tier": parsed.get("tier") if isinstance(parsed.get("tier"), str) else None,
                "lastCheckAt": parsed.get("lastCheckAt"),
            }
            # Signature check at ingest (memoized), expiry folded in at read.
            token_state, token_claims = self._verify_license_token(parsed.get("token"))
            # Machine binding: the server signs the verifying machine's id into
            # the token, and the extension asserts its own stored machineId
            # alongside. A token minted for another machine (shared/stolen
            # storage blob missing its matching machineId) is rejected here.
            # An assertion WITHOUT a machineId (pre-binding extension) fails
            # closed into "invalid", which surfaces the existing
            # "update the extension" message rather than a licence refusal.
            # Honest limit: an attacker who copies the ENTIRE storage blob
            # copies the matching machineId too - the real ceiling on token
            # sharing is the server-side seat limit at verify plus the token's
            # own expiry, not this check. This closes the cheap replays only.
            if token_state == "ok":
                asserted_machine = parsed.get("machineId")
                token_machine = (token_claims or {}).get("machineId")
                if not isinstance(asserted_machine, str) or asserted_machine != token_machine:
                    token_state, token_claims = "invalid", None
            self._license_token_state, self._license_token_claims = token_state, token_claims
            # Raw retention follows the FINAL verdict - after the machine
            # binding check above, not before it - so a token minted for
            # another machine is never handed onward as a credential.
            self._license_token_raw = parsed.get("token") if token_state == "ok" else None
            self._license_asserted_at = time.time()
        # 1.2.0: licence activation IS the consent moment for browser control.
        # No more /lp authorize - the moment the extension asserts a valid
        # licence, grant an indefinite auth so my_browser_* tools work
        # without any extra typing. Reversible via /lp revoke.
        if self.auth is not None:
            self.auth.auto_authorize_from_license(self.is_licensed())
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
        with self._license_state_lock:
            claims = self._license_token_claims or {}
            return {
                "licensed": self._is_licensed_locked(),
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

    def license_token(self) -> Optional[str]:
        """The raw server-signed session token, or None when there is nothing
        a licensing endpoint should be shown. Expiry is folded in via
        _license_token_read_state, so a token that verified at ingest but has
        since lapsed comes back None rather than being presented and refused."""
        with self._license_state_lock:
            if self._license_token_read_state() != "ok":
                return None
            return self._license_token_raw

    # -- helper status (macOS helper -> Python) ----------------------------

    def note_helper_status(self, raw: str) -> None:
        """Store the body of a token-gated POST /assert-helper-status.
        Parsed input from a trust boundary: unknown keys dropped, types
        coerced, grantedApps capped. Malformed input is ignored - a broken
        report must never take the channel down."""
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("helper status is not an object")
        except (ValueError, TypeError):
            return
        granted = parsed.get("grantedApps")
        if isinstance(granted, list):
            granted = [g for g in granted if isinstance(g, str)][:200]
        else:
            granted = []
        version = parsed.get("helperVersion")
        self._helper_status = {
            "helperVersion": version if isinstance(version, str) else None,
            "tccAccessibility": parsed.get("tccAccessibility") is True,
            "tccScreenRecording": parsed.get("tccScreenRecording") is True,
            "secureInputActive": parsed.get("secureInputActive") is True,
            "grantedApps": granted,
            "assertedAt": time.time(),
        }

    def helper_fields(self) -> dict:
        """The helper part of GET /status. Pure in-memory read - this is on
        the check_fn path (evaluated once per tool per tools/list), so it
        must never touch disk or the network, exactly like license_fields."""
        return {
            "helperConnected": self.helper_connected,
            "helperLastSeenAt": self._helper_seen_at,
            "helper": self._helper_status,
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
            "version": _current_extension_version(),
            # False when `version` above is UNKNOWN_EXTENSION_VERSION
            # ("0.0.0-dev") - the normal case for a Hermes-plugin-zip install,
            # which ships the Python side only, no bundled extension to read a
            # real number from. A caller that compares `version` against its
            # own real version WITHOUT checking this first nags a perfectly
            # current install to "restart your agent" forever - see
            # extension_version_is_known's own docstring. Exposed explicitly
            # so every caller (this endpoint has more than one - see
            # popup.ts, commands.py) checks the same flag instead of each
            # re-deriving it from the sentinel string.
            "versionKnown": extension_version_is_known(),
            "authorized": self.auth.is_authorized() if self.auth else False,
            "authSummary": self.auth.summary() if self.auth else "locked",
            # Raw grant deadline (epoch s | "indefinite" | null) so the popup
            # can render a real countdown instead of parsing authSummary.
            "authorizedUntil": self.auth.authorized_until() if self.auth else None,
            **self.license_fields(),
            **self.helper_fields(),
            # What the helper should be running; same sentinel caveat as
            # `version`/`versionKnown` above, but for the Python plugin's own
            # VERSION file rather than the bundled extension manifest.
            "expectedHelperVersion": _plugin_version(),
        }

    # -- send (Hermes -> Chrome) ------------------------------------------

    def send(
        self,
        action: str,
        params: Optional[dict] = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        *,
        remotable: bool = False,
    ) -> Any:
        """The one place that decides where a command goes.

        Three destinations, longest wire last: a bridge in this process, a
        sibling session that owns the port, or - while this process is the
        helper in a remote assist session - the requester's machine on the far
        side of the relay. The remote branch is the same idea _send_via_owner
        has always implemented ("my agent's commands execute on someone else's
        bridge"), with a longer wire and a mailbox its owner cannot open, which
        is why it belongs here rather than in a second send path that would
        drift out of step with this one.

        ``remotable`` says this command came from an agent tool call, which is
        the only kind an assist session is about. It is opt-in, and it defaults
        to False on purpose: the other callers of send() are this process's own
        internals - indicator_tools painting the helper's own overlay,
        commands.py's /lp doctor probing the helper's own Chrome and helper -
        and shipping those to the requester would cost the helper their own
        indicator and their own diagnostics, refused at the far end as a scope
        violation with no hint that a local tool was simply misrouted. Forgetting
        the flag on a new call site therefore keeps the behaviour send() has
        always had rather than quietly widening what crosses the relay.
        """
        sender = _REMOTE_SENDER if remotable else None
        if sender is not None:
            try:
                return sender(action, params or {}, timeout_ms)
            except BridgeError:
                raise
            except Exception as exc:
                # Everything upstream of send() (chrome_tools._guard,
                # app_tools) handles BridgeError and nothing else, so a failure
                # out on the relay has to arrive as one rather than escaping as
                # remote.py's RemoteError into a tool call nobody is catching.
                raise BridgeError(f"Remote assist: {exc}") from None
        self.ensure_started()
        if self._mode == "client":
            return self._send_via_owner(action, params or {}, timeout_ms)
        return self._send_local(action, params or {}, timeout_ms)

    def execute_gated(
        self,
        action: str,
        params: dict,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        *,
        remote: bool = False,
    ) -> Any:
        """Run one command through the two gates every command must pass.

        THE chokepoint, and it has to stay a single one. Two callers arrive
        here: POST /command (any local process, and any client-mode session)
        and remote.py's command loop (a helper on the far side of the relay).
        Gating them in two places would mean two licence checks and two revoke
        checks that agree today and drift on the Tuesday somebody edits one of
        them, which for the revoke killswitch means a helper who keeps driving
        the browser after the requester locked it.

        Raises CommandRefused when a gate says no, BridgeError when the command
        itself fails. It dispatches at the bottom of this method rather than
        through self.send(): send() is the outbound path, and a command that
        arrived here came IN, so a process that was both helper and requester
        would otherwise post an inbound command straight back out over the
        relay.

        ``remote=True`` differs from a local call in exactly one way, and it is
        the overlay.fire exemption below.
        """
        # Remote assist is free on the requester's side, and this is where that
        # is decided. The reasoning, because it is a licensing decision sitting
        # in a security gate:
        #
        # The paid thing is driving somebody else's machine, and that lives on
        # the HELPER's side - their agent's my_browser_* calls go through
        # chrome_tools._send, which requires their licence before anything
        # leaves. Charging the requester too was charging a stranger admission to
        # be helped: they install this because someone they trust told them to,
        # and the first thing they met was a paywall for a product they had not
        # chosen.
        #
        # What makes it safe to skip is the precondition, not generosity.
        # `remote` is a Python argument, never a wire field: POST /command
        # cannot set it (it does not pass the kwarg at all), so the only caller
        # that can is remote.py's loop. And `_remote_share` is set by
        # _share_confirm AFTER hmac.compare_digest on the six digits, so both
        # together mean "a pairing this machine's own user verified out loud is
        # live right now". That is a stronger consent signal than a licence key.
        verified_share = remote and self._remote_share is not None
        if not verified_share:
            license_error = _require_command_licensed(self, action)
            if license_error is not None:
                raise CommandRefused(license_error, 402)
        # Revoke killswitch, server-side. chrome_tools._send gates on auth in
        # the CLIENT process, but this is also reachable by client-mode
        # sessions and bare local callers that never ran that gate. Honoring
        # auth here means /lp revoke in any session stops every session's
        # commands at the one chokepoint they all share, and it does that
        # cross-process with no new code: auth.py's (mtime_ns, inode, size)
        # stamp is re-read on every is_authorized(). Only enforced when auth is
        # wired (it always is in real sessions); a bare test bridge without
        # auth keeps its licence-only behavior.
        #
        # overlay.fire is exempt for LOCAL callers on purpose: indicator_tools'
        # gate is licence-only because painting an overlay is not driving the
        # browser (see its module docstring) - a client-mode session's
        # indicator must keep working while Chrome control is locked, same as
        # in server mode. A REMOTE caller gets no such exemption. The overlay
        # is the requester's own screen, and someone who just revoked control
        # must not still be painted on by the helper they revoked.
        auth = self.auth
        exempt = action == "overlay.fire" and not remote
        if verified_share:
            # A free requester has no grant to be authorised BY - is_authorized()
            # is False for ever on an unlicensed machine - so asking that question
            # here would refuse every command in a session the user just approved
            # out loud. What still has to be honoured is the killswitch, and that
            # is a DIFFERENT fact: "I pressed revoke" rather than "I never bought
            # this". Only the first stops a helper mid-session.
            if auth is not None and auth.user_revoked():
                raise CommandRefused(_CONTROL_LOCKED_MESSAGE, 403)
        elif not exempt and auth is not None and not auth.is_authorized():
            raise CommandRefused(_CONTROL_LOCKED_MESSAGE, 403)
        # Dispatch, deliberately without send()'s lazy ensure_started(), which
        # would REBIND a bridge that was stopped. POST /command cannot reach
        # that case (its handler only exists while a server is up) but
        # remote.py's loop can, and a command still in flight when the requester
        # ends their session and stops the bridge must not re-open a listening
        # socket on 127.0.0.1 behind their back.
        if self._mode == "client":
            return self._send_via_owner(action, params, timeout_ms)
        if self._httpd is None:
            raise BridgeError("the LucidPilot bridge is not running")
        return self._send_local(action, params, timeout_ms)

    # -- remote assist ------------------------------------------------------

    def set_remote_share(self, label: "Optional[str]") -> None:
        """Name whoever this machine is shared with right now, or None.

        This is the one fact about a share the macOS helper cannot work out for
        itself. It only ever sees app.* commands, so a menu-bar row derived from
        dispatched commands is (a) missing entirely for a browser-scope share,
        which never sends it one, and (b) gone again as soon as the control
        session's idle timeout fires, which is a few seconds of quiet rather
        than the end of anything. The share's real lifetime is known here and
        only here, so the helper reads it off GET /next?kind=helper.

        A waiting poller is woken so the row appears when the share starts,
        rather than up to _NEXT_LONG_POLL_S later - which for a person opening
        that menu because a stranger is clicking around their Mac is the whole
        difference between a control and a decoration.

        ponytail: this is the bridge SERVER's state, so it is right for the
        session that owns the port and invisible from a session proxying through
        _send_via_owner. Same ceiling as _REMOTE_STOP, and the same upgrade:
        forward both over /command rather than keeping them beside it.
        """
        with self._cond:
            if self._remote_share == label:
                return
            self._remote_share = label
            self._cond.notify_all()

    def remote_share(self) -> "Optional[str]":
        return self._remote_share

    def _send_local(self, action: str, params: dict, timeout_ms: int) -> Any:
        # Dead poller, dead air: with the responsible client gone a click used
        # to sit here for its whole 200s timeout only to end with the very
        # message we can already give. Staleness is judged PER KIND - an
        # app.* command cares whether the macOS helper polls, not whether the
        # extension does, and vice versa.
        kind = _command_kind(action)
        poll_age = self._poll_age_ms(kind)
        if poll_age is not None and poll_age > _POLL_STALE_MS:
            raise BridgeError(self._not_polling_message("Not sent", kind))
        command = BridgeCommand(id=uuid.uuid4().hex, action=action, params=params)
        future: Future = Future()
        with self._cond:
            self._pending[command.id] = _Pending(command=command, future=future)
            self._queue.append(command)
            # notify_all, not notify: with two pollers parked in
            # _take_next_command a single notify can wake the WRONG one (it
            # rescans, finds nothing of its kind, sleeps again) while the
            # right one sleeps out its full long-poll window.
            self._cond.notify_all()
        timeout_s = timeout_ms / 1000
        if poll_age is None:
            # Never polled: the bridge may have started a second ago with the
            # client's first poll already in flight, so a short grace here
            # instead of the full timeout. The command is queued FIRST, and the
            # grace is spent waiting on the future rather than sleeping, so a
            # first poll landing at 0.2s picks it up at 0.2s and a fast result
            # returns immediately - the 5s is a ceiling, never a delay.
            grace = min(_FIRST_POLL_GRACE_S, timeout_s)
            try:
                return future.result(timeout=grace)
            except FuturesTimeout:
                if self._poll_age_ms(kind) is None:
                    self._drop_pending(command.id)
                    raise BridgeError(self._not_polling_message("Not sent", kind)) from None
            timeout_s -= grace
        try:
            return future.result(timeout=timeout_s)
        except FuturesTimeout:
            raise BridgeError(self._timeout_message(self._drop_pending(command.id), timeout_ms, kind))

    def _drop_pending(self, command_id: str) -> Optional[_Pending]:
        """Un-queue a command that will never be answered; returns its entry
        (delivered_at and all) so the caller can word the failure."""
        with self._cond:
            entry = self._pending.pop(command_id, None)
            self._queue = [c for c in self._queue if c.id != command_id]
        return entry

    def _poll_age_ms(self, kind: str = "extension") -> Optional[float]:
        """Age of the given poller's last poll in ms, None if it never polled.
        The seen-at slots are written unlocked on request threads (_mark_seen)
        and read unlocked everywhere else (`connected`, status()); a plain
        attribute read is atomic and no caller needs more than a snapshot, so
        this reads them the same way."""
        last = self._helper_seen_at if kind == "helper" else self._last_seen_at
        return None if last is None else (time.time() - last) * 1000

    def _not_polling_message(self, lead: str, kind: str = "extension") -> str:
        """The one place the poller-is-gone wording lives: both the fail-fast
        in _send_local and _timeout_message's not-polling branch say this,
        differing only in how the failure is introduced. The helper branch
        must name the HELPER as the fix - telling a user whose extension is
        fine to reinstall the extension reads as nonsense."""
        poll_age = self._poll_age_ms(kind)
        seen = "never" if poll_age is None else f"{round(poll_age / 1000)}s ago"
        if kind == "helper":
            return (
                f"{lead}: LucidPilot for Mac is not running (last seen {seen}). Ask the user to "
                "install and launch the LucidPilot for Mac helper app, then run /lp doctor."
            )
        return (
            f"{lead}: the Chrome extension is not polling (last seen {seen}). Ask the user to "
            "run /lp onboard to install the companion extension and to keep that browser "
            "window open."
        )

    def _timeout_message(self, entry: Optional[_Pending], timeout_ms: int, kind: str = "extension") -> str:
        client = "LucidPilot for Mac" if kind == "helper" else "the Chrome extension"
        remedy = (
            "quit and relaunch the LucidPilot for Mac helper app"
            if kind == "helper"
            else "reload the LucidPilot Chrome extension at chrome://extensions"
        )
        if entry is not None and entry.delivered_at:
            return (
                f"Timed out after {timeout_ms}ms: {client} received the command but "
                "never returned a result. The action may be long-running, or the result post "
                f"failed. Ask the user to run /lp doctor; if it persists, they should {remedy}."
            )
        poll_age = self._poll_age_ms(kind)
        if poll_age is None or poll_age > _POLL_STALE_MS:
            return self._not_polling_message(f"Timed out after {timeout_ms}ms", kind)
        return (
            f"Timed out after {timeout_ms}ms: {client} is polling (last seen "
            f"{round(poll_age / 1000)}s ago) but did not pick up this command in time. Retry; if "
            f"it persists, {remedy}."
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

    def _take_next_command(self, kind: str = "extension") -> Optional[BridgeCommand]:
        """Long-poll: return the next queued command OF THIS POLLER'S KIND, or
        None after the poll window. One shared queue with a kind-aware scan
        rather than a queue per kind: the queue is 0-2 deep in practice, and a
        second list would double the state stop()/_drop_pending/status() keep
        in step. ponytail: linear rescan per wake; partition into per-kind
        deques if a batching client ever makes the queue deep."""
        deadline = time.monotonic() + _NEXT_LONG_POLL_S
        with self._cond:
            share = self._remote_share
            while True:
                for i, command in enumerate(self._queue):
                    if _command_kind(command.action) == kind:
                        del self._queue[i]
                        entry = self._pending.get(command.id)
                        if entry is not None:
                            entry.delivered_at = time.time()
                        return command
                # A share starting or ending is the one non-command event the
                # helper's poll carries (see set_remote_share), and its menu bar
                # is a live control rather than a status line, so it ends the
                # poll window early instead of waiting it out.
                if kind == "helper" and self._remote_share != share:
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def _deliver_result(self, result: dict, kind: str = "extension") -> bool:
        with self._cond:
            command_id = result.get("id")
            pending = self._pending.get(command_id)
            # A poller of one kind must not complete the other kind's command:
            # the sender's kind is proven (token vs pinned Origin), the
            # pending command's kind is derived from its action, and a
            # mismatch is answered like an unknown id.
            if pending is not None and _command_kind(pending.command.action) != kind:
                return False
            pending = self._pending.pop(command_id, None)
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

    def _mark_seen(self, client_name: Optional[str] = None, kind: str = "extension") -> None:
        if kind == "helper":
            self._helper_seen_at = time.time()
            if client_name is not None:
                self._helper_name = client_name
            return
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


def _is_host_allowed(headers, port: int, bound_host: str = "") -> bool:
    """The standard loopback-service defense against DNS rebinding.

    A page on evil.com whose DNS is re-pointed at 127.0.0.1 reaches this
    server with requests the browser labels same-origin (Sec-Fetch-Site:
    same-origin, no Origin header), which _is_browser_origin_allowed alone
    cannot tell apart from a real local request - but its Host header still
    says evil.com. Every legitimate caller sends a loopback Host: the
    extension fetches http://127.0.0.1:PORT, local processes use
    http.client/curl against 127.0.0.1 or localhost. Reject everything else
    before any endpoint logic runs. Missing Host (pre-HTTP/1.1) fails
    closed - every real client here sends one. ``bound_host`` keeps a
    non-default LUCIDPILOT_BRIDGE_HOST bind from 403ing its own clients
    (which send Host: <bound_host>:<port>)."""
    host = (headers.get("host") or "").strip().lower()
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}", "127.0.0.1", "localhost"}
    if bound_host:
        allowed.add(f"{bound_host.strip().lower()}:{port}")
    return host in allowed


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


def _is_extension_poll_allowed(headers) -> bool:
    """GET /next's extension path: pinned Origin when present, and browser-issued.

    _is_browser_origin_allowed alone says yes to a request carrying NEITHER an
    Origin NOR a Sec-Fetch-Site, which is precisely what
    _is_local_process_request calls a local process. That let any process on
    the machine long-poll /next, take a queued command off the queue and answer
    it, which is theft of an in-flight command, not merely a read.

    The extension cannot be asked for an Origin here and that is not a choice:
    Chrome omits Origin on a GET from an extension worker to a host-permitted
    URL (sniffed on the real built extension, same finding that killed the
    piggyback-header licence assertion - see _handle_assert_license). The same
    sniff shows it DOES send ``Sec-Fetch-Site: none``, and Sec-Fetch-* are
    forbidden header names, so a page's JS can never set them and only the
    browser itself does. Requiring one of the two present is therefore the
    strongest gate this endpoint can hold without an extension change.

    Its honest limit, the same one /authorize documents: a local NON-browser
    process can forge Sec-Fetch-Site with curl. This proves "not a local
    process that merely asked", not "the real extension". Closing it properly
    needs a secret the extension holds, and the extension has no way to obtain
    one over loopback that a same-uid process could not obtain too. Do not
    build anything on this gate that assumes otherwise: a same-uid process on
    this machine can already read auth.json and helper-token (both 0600, both
    owned by that same uid) and attach to Chrome over CDP by itself, so it is
    outside the threat model here exactly as it is on /command.

    # ponytail: the no-Origin branch also accepts Sec-Fetch-Site: same-origin,
    # which is what a script on a page THIS server serves would send - today
    # only /testdrive, static fixture HTML with no user input and so no way to
    # get hostile script onto it. Narrowing to exactly "none" would close that
    # and costs one comparison, but it stakes the whole poll loop on a single
    # sniff of what Chrome sends, and a wrong guess 403s every poll and kills
    # the product. Narrow it when there is a second HTML surface on this
    # origin, or once a CI job asserts the real extension's header shape.
    """
    if not _is_browser_origin_allowed(headers):
        return False
    return bool(headers.get("origin") or headers.get("sec-fetch-site"))


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
    # The TOKEN's verdict is asked first, because the token is what decides
    # (see _is_licensed_locked). Staleness only picks the wording now, and it
    # must not get first refusal: a machine whose licence genuinely expired
    # while it was asleep is stale AND expired, and telling that person their
    # extension "has not reported recently" sends them to reinstall a working
    # extension instead of renewing. Name the real cause.
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
    stale = asserted_at is None or (time.time() - asserted_at) > _LICENSE_ASSERT_TTL_S
    if stale:
        if action.startswith("app."):
            # A helper-only user may have never installed the extension - but
            # the extension IS the licence-activation channel (the only place
            # a key is entered), even for Mac app control. Name that, or this
            # error reads as nonsense to someone who never wanted a browser
            # extension.
            return (
                "LucidPilot requires an active license, and none has been asserted "
                "recently. The Chrome extension is what activates and reports your "
                "licence, even for Mac app control: install it, activate your key "
                "in its popup, then run /lp doctor."
            )
        return (
            "LucidPilot requires an active license, and the Chrome extension has "
            "not reported a licence recently. Check that the LucidPilot extension "
            "is installed and running (chrome://extensions), then run /lp doctor."
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

    def _host_allowed(self) -> bool:
        """One Host check ahead of every endpoint - see _is_host_allowed."""
        addr = self.server.server_address
        if _is_host_allowed(self.headers, addr[1], bound_host=str(addr[0])):
            return True
        self._send_json(403, {"ok": False, "error": "host not allowed"})
        return False

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not self._host_allowed():
            return
        cors = _cors_headers_for(self.headers)
        if not _is_browser_origin_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"}, cors)
            return
        self._send_json(200, {"ok": True}, cors)

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_allowed():
            return
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
        if path == "/license-token":
            self._handle_license_token()
            return
        self._send_json(404, {"error": "not found"}, _cors_headers_for(self.headers))

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_allowed():
            return
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
        if path == "/assert-helper-status":
            self._handle_assert_helper_status()
            return
        if path == "/remote-stop":
            self._handle_remote_stop()
            return
        self._send_json(404, {"error": "not found"}, _cors_headers_for(self.headers))

    # -- endpoints ---------------------------------------------------------

    def _handle_status(self) -> None:
        # cors computed unconditionally, before the check: a browser that
        # fails CORS on a response has no way to read the body OR the status
        # code, so a 403 sent without these headers doesn't read as "denied",
        # it reads as "server unreachable" - the exact failure mode this bug
        # produced (see popup.ts's collectDiagnostics catching it as
        # bridgeError instead of the real "origin not allowed" reason).
        cors = _cors_headers_for(self.headers)
        if not _is_browser_origin_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"}, cors)
            return
        self._send_json(200, self._bridge.status(), cors)

    def _handle_license_token(self) -> None:
        """The raw session token, for a CLIENT-mode sibling session about to
        mint a relay ticket (licensing.relay_ticket). Local processes only -
        the same gate as /command, and the same honest ceiling: a same-uid
        process this refuses could POST /command and drive the browser
        outright, so this hides the token from web pages, not from malware."""
        if not _is_local_process_request(self.headers):
            self._send_json(403, {"ok": False, "error": "the licence token is served only to local processes"})
            return
        token = self._bridge.license_token()
        if not token:
            self._send_json(404, {"ok": False, "error": "no verified licence token held"})
            return
        self._send_json(200, {"ok": True, "token": token})

    def _handle_testdrive(self) -> None:
        cors = _cors_headers_for(self.headers)
        if not _is_browser_origin_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"}, cors)
            return
        try:
            with open(_TESTDRIVE_FIXTURE_PATH, encoding="utf-8") as fh:
                html = fh.read()
        except OSError:
            self._send_json(404, {"ok": False, "error": "testdrive fixture missing"}, cors)
            return
        self._send_html(200, html, cors)

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
        # Both gates live in execute_gated, which remote assist's command loop
        # also calls, so a helper's command is refused by the same licence
        # check and the same revoke killswitch a local one is. CommandRefused
        # first: it is a BridgeError subclass, and a gate refusal is a 402 or a
        # 403, never the 504 a real command failure gets.
        try:
            result = self._bridge.execute_gated(
                action, body.get("params") or {}, body.get("timeoutMs") or DEFAULT_TIMEOUT_MS
            )
            self._send_json(200, {"ok": True, "result": result})
        except CommandRefused as exc:
            self._send_json(exc.status, {"ok": False, "error": str(exc)})
        except BridgeError as exc:
            self._send_json(504, {"ok": False, "error": str(exc)})

    def _handle_next(self) -> None:
        qs = parse_qs(urlparse(self.path).query)
        if (qs.get("kind") or [""])[0] == "helper":
            # The macOS helper's poll. Token-gated (a native process has no
            # Origin for the pin below to check); no CORS headers - this is
            # never a browser. The extension's own path stays byte-identical
            # below: its poll loop treats any non-200 as fatal-with-backoff.
            if not _is_helper_request(self.headers):
                self._send_json(403, {"ok": False, "error": "helper token missing or wrong"})
                return
            self._bridge._mark_seen((qs.get("name") or [None])[0], kind="helper")
            command = self._bridge._take_next_command("helper")
            headers = {"x-lucidpilot-version": _plugin_version()}
            if command is not None:
                payload = {
                    "type": "command",
                    "command": {"id": command.id, "action": command.action, "params": command.params},
                }
            else:
                payload = {"type": "none"}
            # On BOTH shapes, and on every poll rather than only when it
            # changes: this poll is the helper's whole picture of the share, and
            # a field it can miss is a menu-bar row that can be wrong.
            payload["remote"] = self._bridge.remote_share()
            self._send_json(200, payload, headers)
            return
        if not _is_extension_poll_allowed(self.headers):
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"}, _cors_headers_for(self.headers))
            return
        self._bridge._mark_seen((qs.get("name") or [None])[0])
        command = self._bridge._take_next_command()
        version = _current_extension_version()
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
            self._send_json(403, {"ok": False, "error": "licence assertions are accepted only from the pinned extension"}, _cors_headers_for(self.headers))
            return
        self._bridge.note_license_assertion(self._read_body())
        self._send_json(200, {"ok": True}, _cors_headers_for(self.headers))

    def _handle_remote_stop(self) -> None:
        # The Stop control in the in-page indicator and the one in the menu bar
        # both land here, and they are the only two callers this accepts.
        #
        # An earlier cut of this gated on nothing, reasoning that an endpoint
        # which only ever REMOVES capability cannot be misused. That was wrong
        # about who can call it. A POST from a page carrying a plain
        # content-type is a CORS-simple request: no preflight is sent, the
        # browser delivers it, and an ungated handler runs - so any page the
        # requester visits, including one the helper walked them onto, could end
        # the share silently and do it again on every load so a share never got
        # going. Denial only, but denial of the feature by anyone on the web.
        #
        # So: the pinned extension Origin (glue.js's remoteStop is a POST and
        # POSTs always carry one), or a header-less local request, which is the
        # Mac helper's URLSession. A page can never be either - it cannot remove
        # its own Origin. Same honest limit every other gate here documents: a
        # same-uid process can forge the header-less shape with curl, and for an
        # endpoint whose whole effect is "stop sharing" that is not worth
        # another lock.
        #
        # `stopped` is what it did, not what it was told: false means no share
        # was live here. The extension reads that field rather than the status
        # code, because "this bridge is too old to know what /remote-stop means"
        # (404) and "there was nothing to stop" are opposite answers to the
        # question of whether the Stop button worked.
        cors = _cors_headers_for(self.headers)
        origin = self.headers.get("origin") or ""
        if origin not in _ALLOWED_EXTENSION_ORIGINS and not _is_local_process_request(self.headers):
            self._send_json(403, {"ok": False, "error": "stop requests are accepted only from LucidPilot itself"}, cors)
            return
        stop = _REMOTE_STOP
        if stop is None:
            self._send_json(200, {"ok": True, "stopped": False}, cors)
            return
        stop()
        self._send_json(200, {"ok": True, "stopped": True}, cors)

    def _handle_authorize(self) -> None:
        # Extension-only, stricter than _is_browser_origin_allowed on its own:
        # the Origin header must be PRESENT and a pinned chrome-extension://
        # id. A local process has no Origin (it should use /lp instead), and a
        # web page cannot spoof Origin. NOTE the limits of that: a local
        # NON-browser process can trivially forge this header with curl, so
        # the pin proves "not a web page", not "a human clicked" - see the
        # security audit. In 1.2.0 the popup no longer calls this endpoint at
        # all (its auth UI was removed; licence activation is the consent
        # moment). Kept for compatibility and for the e2e harness; the pin
        # still keeps every web origin out.
        cors = _cors_headers_for(self.headers)
        origin = self.headers.get("origin") or ""
        if origin not in _ALLOWED_EXTENSION_ORIGINS:
            self._send_json(403, {"ok": False, "error": "authorize is accepted only from the pinned extension popup"}, cors)
            return
        auth = self._bridge.auth
        if auth is None:
            self._send_json(503, {"ok": False, "error": "Chrome control is not enabled in this session (no my_browser_* tools registered)."}, cors)
            return
        try:
            body = json.loads(self._read_body() or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "Invalid JSON"}, cors)
            return
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
        # The helper token, when present and correct, identifies the sender's
        # kind; _deliver_result then refuses to complete the other kind's
        # commands. The extension never sends this header, so its path below
        # is untouched.
        if _is_helper_request(self.headers):
            self._bridge._mark_seen(kind="helper")
            try:
                result = json.loads(self._read_body() or "{}")
            except json.JSONDecodeError:
                self._send_json(400, {"ok": False, "error": "Invalid JSON"})
                return
            if not self._bridge._deliver_result(result, kind="helper"):
                self._send_json(404, {"ok": False, "error": "unknown command id"})
                return
            self._send_json(200, {"ok": True})
            return
        # Extension-only, and stricter than /next's gate above: the Origin must
        # be PRESENT and pinned, the same bar /authorize and /assert-license
        # hold. /next has to settle for Sec-Fetch-Site because Chrome strips
        # Origin from a worker GET; this is a POST, and Chrome appends Origin
        # to every non-GET request, so the full pin is affordable here
        # (sniffed on the real built extension, both requests, same session).
        # Without it an origin-less local process could answer a command it
        # never received, or race the real extension to answer one it did.
        cors = _cors_headers_for(self.headers)
        if (self.headers.get("origin") or "") not in _ALLOWED_EXTENSION_ORIGINS:
            self._send_json(403, {"ok": False, "error": "browser origin not allowed"}, cors)
            return
        self._bridge._mark_seen()
        try:
            result = json.loads(self._read_body() or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "Invalid JSON"}, cors)
            return
        delivered = self._bridge._deliver_result(result)
        if not delivered:
            self._send_json(404, {"ok": False, "error": "unknown command id"}, cors)
            return
        self._send_json(200, {"ok": True}, cors)

    def _handle_assert_helper_status(self) -> None:
        # The macOS helper's state report (version, TCC grants, allowlist).
        # Token-gated, mirroring /assert-license's extension pinning: the
        # bridge holds the verdicts, the pollers assert them.
        if not _is_helper_request(self.headers):
            self._send_json(403, {"ok": False, "error": "helper status is accepted only from the LucidPilot Mac helper"})
            return
        self._bridge._mark_seen(kind="helper")
        self._bridge.note_helper_status(self._read_body())
        self._send_json(200, {"ok": True, "expectedHelperVersion": _plugin_version()})
