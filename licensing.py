"""Licence state for LucidPilot Pro's my_browser_*/indicator_* tools.

The Chrome extension popup is the ONLY place a licence key is ever entered or
verified (chrome-extension/src/license.ts talks to api.lucidfabrics.com and
stores the verdict). This module no longer stores, verifies, or even sees a
key: the extension reports {valid, tier, lastCheckAt, token} to the bridge
(glue.js -> POST /assert-license, paced off the /next poll it already makes),
bridge.py caches that assertion behind a short TTL, and this module just
reads the folded verdict.

That inversion is sound because my_browser_* cannot function without the extension
anyway - it drives Chrome through it - so the extension is always present
whenever the Python side needs a licence. The assertion is NOT taken on the
extension's word alone: `token` is a server-signed session token (Ed25519,
expiring at the paid period end + grace, floor 8 days) minted by the
licensing service on every successful verify, and
bridge.py checks its signature itself against a pinned public key (see
bridge._verify_license_token and the vendored ed25519_verify module). Origin
pinning keeps foreign processes off the channel; the token keeps a tampered
extension from vouching for itself.

Two read paths, one truth:
  - server mode: this process owns port 16329, so bridge._SERVER_INSTANCE
    holds the assertion in memory - read it directly, no I/O.
  - client mode: another LucidPilot session owns the port; ask its GET /status
    (which reports the same folded verdict), memoized for a couple of seconds
    because mcp_server evaluates every tool's check_fn around every call.

Fail closed: no bridge, no recent assertion, or valid:false all mean "not
licensed", and the messages here name the actual cause - a user whose
extension went silent must not be told to go buy a key they already have.

Legacy state (~/.hermes/lucidpilot/license.json, override dir
LUCIDPILOT_LICENSE_DIR) is kept read-only for one purpose: the one-shot
migration in bridge.migrate_legacy_key() that hands a pre-popup-era key to
the extension and then deletes it here. The Ed25519 verification, the
`cryptography` dependency, and the online verify/recheck logic that used to
live in this file went with the key storage - the extension does all of that
now.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

# Storefront link surfaced in every "you don't have this yet" message
# (require_pro_licensed below, chrome_tools.py's gate, commands.py's /lp
# doctor) - one constant so the URL only lives in one place.
PURCHASE_URL = "https://pilot.lucidfabrics.com"

_STATE_DIR = os.path.expanduser(os.environ.get("LUCIDPILOT_LICENSE_DIR", "~/.hermes/lucidpilot"))
_STATE_FILE = os.path.join(_STATE_DIR, "license.json")

# Client-mode /status probe: short timeout (an unreachable bridge must not
# stall a tools/list), short memo (mcp_server runs every check_fn twice per
# tool call, ~46 reads - one HTTP hit per couple of seconds is plenty fresh
# against a 10-minute assertion TTL).
_STATUS_TIMEOUT_S = 1.0
_STATUS_MEMO_TTL_S = 2.0

_memo_lock = threading.Lock()
_memo: Optional[dict] = None
_memo_at: float = 0.0


class LicenseRequiredError(RuntimeError):
    """Raised by require_pro_licensed() when Pro isn't currently licensed.

    Mirrors auth.ChromeAuthError's contract exactly (see its docstring): a
    plain RuntimeError subclass that chrome_tools.py's _guard() wrapper turns
    into a ``[lucidpilot] ...`` string instead of letting it escape a tool handler.
    """


def _command_hint(subcommand: str = "") -> str:
    """Host-correct /lp command name. Duplicated from auth.command_hint rather
    than imported: auth -> bridge -> licensing already, so importing auth here
    would close an import cycle for three lines of string building."""
    try:
        from .bridge import AGENT
    except ImportError:
        AGENT = "hermes"
    base = "/lucidpilot:lp" if AGENT == "claude" else "/lp"
    return f"{base} {subcommand}".strip()


# -- reading the extension's assertion ----------------------------------------

def _server_bridge():
    """The in-process bridge that owns the port, or None (client mode /
    standalone module load)."""
    try:
        from . import bridge
        b = bridge._SERVER_INSTANCE
        if b is not None and b._mode == "server":
            return b
    except Exception:
        pass
    return None


def _bridge_url() -> str:
    # Same env vars bridge.py reads, duplicated as strings rather than
    # imported: tests load this module standalone by path, where relative
    # imports fail, and the fallback must keep working there.
    host = os.environ.get("LUCIDPILOT_BRIDGE_HOST", "127.0.0.1")
    port = os.environ.get("LUCIDPILOT_BRIDGE_PORT", "16329")
    return f"http://{host}:{port}"


def _fetch_owner_status() -> Optional[dict]:
    try:
        with urllib_request.urlopen(f"{_bridge_url()}/status", timeout=_STATUS_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode() or "{}")
        return data if isinstance(data, dict) else None
    except (urllib_error.URLError, ConnectionError, OSError, ValueError):
        return None


def invalidate_status_cache() -> None:
    """Drop the client-mode memo. mcp_server's licence-change callback calls
    this before diffing tool visibility, so a fresh assertion is visible
    immediately instead of after the memo expires."""
    global _memo, _memo_at
    with _memo_lock:
        _memo = None
        _memo_at = 0.0


def _status_snapshot() -> Optional[dict]:
    """Client-mode /status snapshot through the 2s memo (None when the owner
    is unreachable; the None is memoized too, same as always, so a dead owner
    doesn't get probed 46 times per tools listing)."""
    global _memo, _memo_at
    with _memo_lock:
        if _memo is not None and (time.time() - _memo_at) < _STATUS_MEMO_TTL_S:
            return _memo
        status = _fetch_owner_status()
        _memo = status
        _memo_at = time.time()
        return status


def license_state() -> dict:
    """Structured licence snapshot {licensed, tier, licenseAssertedAt,
    licenseTokenState, licenseAssertedValid} - the same fields bridge.py's
    GET /status reports, whichever process owns the port. One function so
    commands.py's /lp status//lp doctor and the tool gates can't drift from
    each other."""
    b = _server_bridge()
    if b is not None:
        return b.license_fields()
    status = _status_snapshot()
    if not status:
        return {
            "licensed": False,
            "tier": None,
            "licenseAssertedAt": None,
            "licenseTokenState": None,
            "licenseAssertedValid": False,
        }
    return {
        "licensed": status.get("licensed") is True,
        "tier": status.get("tier"),
        "licenseAssertedAt": status.get("licenseAssertedAt"),
        # None when the owning process predates signed tokens; the generic
        # unlicensed messaging applies then, not the update-extension one.
        "licenseTokenState": status.get("licenseTokenState"),
        "licenseAssertedValid": status.get("licenseAssertedValid") is True,
    }


def helper_state() -> dict:
    """{helperConnected, helperLastSeenAt, helper} - the owning bridge's
    macOS-helper fields, however this process reaches it: server mode is a
    pure in-memory read (bridge.helper_fields), client mode rides the same
    memoized /status the licence reads use, so my_app_*'s check_fn adds zero
    HTTP on the hot path. Slightly odd home for non-licence state, accepted
    on purpose: this module owns the owning-bridge state read, licence and
    otherwise - a second memo of the same endpoint would be worse."""
    b = _server_bridge()
    if b is not None:
        return b.helper_fields()
    status = _status_snapshot()
    if not status:
        return {"helperConnected": False, "helperLastSeenAt": None, "helper": None}
    helper = status.get("helper")
    return {
        "helperConnected": status.get("helperConnected") is True,
        "helperLastSeenAt": status.get("helperLastSeenAt"),
        "helper": helper if isinstance(helper, dict) else None,
    }


def is_pro_licensed() -> bool:
    """Cheap check, safe as a tool ``check_fn`` evaluated on every tool
    listing (same contract as auth.ChromeAuth.is_authorized). Server mode is
    a pure in-memory read; client mode is one memoized loopback HTTP call.
    True only when the extension recently asserted a valid licence."""
    return license_state()["licensed"] is True


def require_pro_licensed() -> None:
    """Runtime layer (defense in depth): call this inside every my_browser_* handler
    right alongside auth.require_authorized() - check_fn keeps the tool out
    of the agent's context while unlicensed; this raises in case a handler
    somehow runs anyway. The message names the cause: a silent extension is
    not a missing key."""
    state = license_state()
    if state["licensed"] is True:
        return
    if state["licenseAssertedAt"] is None:
        raise LicenseRequiredError(
            "LucidPilot requires an active license, and the Chrome extension has "
            "not reported a licence recently. Check that the LucidPilot extension "
            f"is installed and running, then run {_command_hint('doctor')}."
        )
    if state.get("licenseAssertedValid") and state.get("licenseTokenState") in ("missing", "invalid", "expired"):
        # The extension says "licensed" but could not prove it with a
        # server-signed session token: an outdated extension (predates
        # tokens), a token past its expiry (offline beyond the paid period), or a
        # tampered one. All three have the same fix path for a real customer.
        raise LicenseRequiredError(
            "LucidPilot requires an active license, and the Chrome extension "
            "reported one it could not prove. Ask the user to update the "
            "extension to this release (chrome://extensions, refresh icon), or "
            "if it is already current, to reconnect to the internet so the "
            "licence can re-verify. Then retry."
        )
    raise LicenseRequiredError(
        "LucidPilot requires an active license. Ask the user to enter their "
        "licence key in the LucidPilot Chrome extension popup, or to subscribe "
        f"at {PURCHASE_URL} if they don't have one."
    )


def license_status_summary() -> str:
    """One-line human-readable status, mirrors auth.ChromeAuth.summary()."""
    state = license_state()
    if state["licensed"] is True:
        tier = state["tier"] or "Pro"
        # Only claim the verification THIS process actually performed. In
        # client mode the token was checked by whichever session owns the
        # port, and an owner older than signed tokens reports no state at all
        # - saying "verified" there would be describing work nobody did.
        if state.get("licenseTokenState") == "ok":
            return f"licensed ({tier}), server-signed token verified"
        return f"licensed ({tier}), per the session that owns the bridge"
    if state["licenseAssertedAt"] is None:
        return "unknown (extension has not reported a licence recently)"
    if state.get("licenseAssertedValid") and state.get("licenseTokenState") in ("missing", "invalid", "expired"):
        return f"unproven licence (token {state['licenseTokenState']} - update the extension / reconnect)"
    return "no licence activated (enter your key in the extension popup)"


# -- legacy key migration (read-only remnant of the old key store) ------------

def legacy_license_key() -> Optional[str]:
    """The key activate_license() used to store here, or None. Only
    bridge.migrate_legacy_key() should care - new installs never write one."""
    try:
        with open(_STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        key = data.get("license_key") if isinstance(data, dict) else None
        return key if isinstance(key, str) and key else None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def forget_legacy_license_key() -> None:
    """Delete the legacy state file outright. Nothing else lives in it worth
    keeping: the machine id only mattered as a licence seat, and the extension
    mints its own."""
    try:
        os.unlink(_STATE_FILE)
    except FileNotFoundError:
        pass
    except OSError:
        pass  # unreadable/undeletable file: migration will just retry next start


_LICENSE_API = os.environ.get("LUCIDPILOT_LICENSE_API", "https://api.lucidfabrics.com").rstrip("/")
_TICKET_TIMEOUT_S = 10.0


def _session_token() -> Optional[str]:
    """The raw server-signed session token this machine holds, or None.

    Server mode reads it off the in-process bridge. Client mode asks the
    owner's GET /license-token - the sibling that talks to the extension is
    the only process that has one.
    """
    b = _server_bridge()
    if b is not None:
        try:
            return b.license_token()
        except Exception:
            return None
    try:
        req = urllib_request.Request(f"{_bridge_url()}/license-token", method="GET")
        with urllib_request.urlopen(req, timeout=_STATUS_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode() or "{}")
        token = data.get("token") if isinstance(data, dict) else None
        return token if isinstance(token, str) and token else None
    except (urllib_error.URLError, ConnectionError, OSError, ValueError):
        return None


def _request_ticket(payload: bytes) -> str:
    """One POST to the licensing worker, or LicenseRequiredError with the cause."""
    req = urllib_request.Request(
        f"{_LICENSE_API}/api/licenses/relay-ticket",
        data=payload,
        # The UA matters: the default Python one trips Cloudflare's Browser
        # Integrity Check at the edge (403 error 1010) before the worker runs.
        headers={"content-type": "application/json", "user-agent": "LucidPilot-remote"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=_TICKET_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode() or "{}")
    except urllib_error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode() or "{}")
        except Exception:  # noqa: BLE001
            detail = {}
        message = detail.get("error") if isinstance(detail, dict) else None
        raise LicenseRequiredError(
            "The licensing service refused to issue a relay ticket"
            + (f": {message}" if message else f" (HTTP {exc.code})")
            + ". If your licence looks fine in the popup, try again in a minute."
        ) from None
    except (urllib_error.URLError, ConnectionError, OSError, ValueError) as exc:
        raise LicenseRequiredError(
            f"Couldn't reach the licensing service to start a share ({exc}). "
            "Check the connection and try again."
        ) from None
    ticket = data.get("ticket") if isinstance(data, dict) else None
    if not isinstance(ticket, str) or not ticket:
        raise LicenseRequiredError(
            "The licensing service answered without a ticket. Try again in a "
            "minute; if it keeps happening the service is misdeployed."
        )
    return ticket


def relay_ticket(*, joining: bool = False) -> str:
    """The ticket the relay demands, of the right tier for what is being done.

    Two tiers, and which one this machine can get is the whole free/paid line:
    an anonymous ticket may OPEN a channel and may not join one, so being helped
    costs nothing and helping is what needs a licence.

    ``joining`` says which end is asking, and it changes what a bad licence
    means. Opening: nothing about being helped requires a licence, so a missing,
    expired or unreadable token falls through to an anonymous ticket rather than
    stopping somebody being helped over a billing problem they may not know they
    have. Joining: a licence is the actual requirement, so the same failure is
    reported rather than silently downgraded into a ticket that will be refused
    at the relay with a message about tiers that means nothing to anybody.
    """
    token = _session_token()
    if not token:
        if joining:
            raise LicenseRequiredError(
                "Helping someone needs a verified licence, and this machine isn't "
                "holding one right now. Open the extension popup and check the "
                f"licence there, or run {_command_hint('doctor')}."
            )
        return _request_ticket(b"{}")

    try:
        return _request_ticket(json.dumps({"token": token}).encode())
    except LicenseRequiredError:
        if joining:
            raise
        # Being helped never required a licence, so a token this machine cannot
        # cash in must not be the thing that stops it.
        return _request_ticket(b"{}")


if __name__ == "__main__":
    # ponytail: runnable self-check for the non-trivial logic left in this
    # file - the fold from bridge fields to verdict/summary and the legacy-key
    # readers. No network, no real state file.
    import tempfile
    import unittest.mock as mock

    with mock.patch(f"{__name__}._server_bridge", return_value=None), \
         mock.patch(f"{__name__}._fetch_owner_status", return_value=None):
        invalidate_status_cache()
        assert is_pro_licensed() is False, "no bridge must fail closed"
        assert "not reported" in license_status_summary()

    fresh = {"licensed": True, "tier": "PRO", "licenseAssertedAt": time.time()}
    with mock.patch(f"{__name__}._server_bridge", return_value=None), \
         mock.patch(f"{__name__}._fetch_owner_status", return_value=fresh):
        invalidate_status_cache()
        assert is_pro_licensed() is True
        assert "PRO" in license_status_summary()

    with tempfile.TemporaryDirectory() as tmp:
        state_file = os.path.join(tmp, "license.json")
        with mock.patch(f"{__name__}._STATE_FILE", state_file):
            assert legacy_license_key() is None
            with open(state_file, "w", encoding="utf-8") as fh:
                json.dump({"license_key": "LUCIDPILOT-PR-x.y"}, fh)
            assert legacy_license_key() == "LUCIDPILOT-PR-x.y"
            forget_legacy_license_key()
            assert legacy_license_key() is None
            forget_legacy_license_key()  # idempotent

    print("licensing.py self-check passed")
