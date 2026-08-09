"""QA Layer 5 security drills for LucidPilot's bridge (bridge.py) and the
built Chrome extension (chrome-extension/dist/).

Three drills not already covered by test_bridge_extension_pinning.py:

  1. A second, genuinely separate fake extension origin (distinct string from
     that file's FOREIGN_EXTENSION_ID) hitting /next and /result - checked at
     the HTTP layer (403) AND at the internal queue/pending state (nothing
     popped, nothing delivered, nothing corrupted for the real extension).
  2. A browser-page-context fetch to /command (Origin + Sec-Fetch-Site
     headers present, as a malicious webpage's own JS would send - never
     hand-settable by page JS, only by the browser itself) - confirms
     _is_local_process_request rejects it before the command is ever parsed
     or queued.
  3. A structural grep-gate over the actual built dist/ output: no logAction()
     call site in content.js, and no branch of glue.js's buildMessage(), ever
     threads a `.text`/`.value`-shaped typed-content read into the audit-log
     message.

Loader note: same importlib-by-path pattern as test_bridge_extension_pinning.py
(see that file's own header comment for why) - duplicated here rather than
imported cross-file since these test files aren't meant to depend on each
other's fixtures.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import subprocess
import sys
import threading
import time
import types
import unittest.mock as mock
from concurrent.futures import Future
from pathlib import Path

import pytest

import ed25519_sign

REPO_ROOT = Path(__file__).resolve().parents[2]

# Distinct from test_bridge_extension_pinning.py's FOREIGN_EXTENSION_ID
# ("qz"*16) - a genuinely separate fake origin, not a plausible variant of the
# pinned one. Same "outside a-p" trick (Chrome ids only ever use a-p), just a
# different pair of letters, so it can never collide with either the real
# pinned id or the other test file's foreign id.
SECOND_FOREIGN_EXTENSION_ID = "rt" * 16


def load_bridge_module():
    for name in list(sys.modules):
        if name == "bridge_under_test_drills":
            sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("bridge_under_test_drills", REPO_ROOT / "bridge.py")
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["bridge_under_test_drills"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bridge_module():
    return load_bridge_module()


@pytest.fixture
def running_bridge(bridge_module):
    """Unlike test_bridge_extension_pinning.py's fixture of the same name,
    this yields the bridge object itself (not just its port) - drill 1 needs
    to inspect _queue/_pending directly, not just HTTP responses."""
    bridge = bridge_module.ChromeProfileBridge(host="127.0.0.1", port=0)
    bridge.ensure_started()
    assert bridge._mode == "server"
    port = bridge._httpd.server_address[1]
    yield bridge, port
    bridge.stop()


def _request(port: int, method: str, path: str, headers: dict, body: bytes | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        payload = json.loads(resp.read().decode() or "{}")
        return resp.status, payload
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Drill 1: a second, separate fake extension - HTTP rejection AND queue
# integrity (not just the status code).
# ---------------------------------------------------------------------------

def test_second_foreign_extension_cannot_steal_or_corrupt_queued_command(bridge_module, running_bridge):
    bridge, port = running_bridge
    foreign_origin = f"chrome-extension://{SECOND_FOREIGN_EXTENSION_ID}"

    # Seed one real pending command directly (white-box: mirrors exactly what
    # _send_local does), so there is a live command in the queue for the
    # attacker to try to steal/answer.
    command = bridge_module.BridgeCommand(id="legit-cmd-1", action="page.click", params={"x": 1, "y": 2})
    future: Future = Future()
    entry = bridge_module._Pending(command=command, future=future)
    with bridge._cond:
        bridge._pending[command.id] = entry
        bridge._queue.append(command)

    assert list(bridge._queue) == [command]
    assert bridge._pending[command.id] is entry
    assert entry.delivered_at is None
    assert not future.done()

    # Attempt 1: foreign extension polls /next trying to steal the command.
    status, body = _request(port, "GET", "/next", {"origin": foreign_origin})
    assert status == 403
    assert body["ok"] is False

    # Queue must be completely untouched by the rejected attempt - not just
    # "still non-empty", but the exact same command, never popped/delivered.
    assert list(bridge._queue) == [command]
    assert bridge._pending[command.id] is entry
    assert entry.delivered_at is None
    assert not future.done()

    # Attempt 2: foreign extension posts a forged result for that command id.
    forged = json.dumps({"id": command.id, "ok": True, "result": {"forged": True}}).encode()
    status, body = _request(
        port, "POST", "/result",
        {"origin": foreign_origin, "content-type": "application/json"},
        body=forged,
    )
    assert status == 403
    assert body["ok"] is False

    # The forged result must never have reached _deliver_result: same pending
    # entry, same future, still unresolved.
    assert bridge._pending[command.id] is entry
    assert not future.done()
    assert list(bridge._queue) == [command]

    # Positive control: the REAL pinned extension can still retrieve the
    # untouched command afterwards - proves the queue survived the attack
    # uncorrupted, not merely that the attacker's requests 403'd.
    real_origin = f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"
    status, body = _request(port, "GET", "/next", {"origin": real_origin})
    assert status == 200
    assert body["type"] == "command"
    assert body["command"]["id"] == command.id
    assert list(bridge._queue) == []  # legitimately popped, exactly once
    assert entry.delivered_at is not None

    future.set_result({"ok": True})  # avoid an unresolved-future warning on teardown


# ---------------------------------------------------------------------------
# Drill 2: /command must reject a browser-page-context fetch (Origin and/or
# Sec-Fetch-Site present - headers page JS cannot spoof, only the browser
# itself sets Sec-Fetch-Site), per _is_local_process_request's documented
# "local processes only" design.
# ---------------------------------------------------------------------------

def test_command_endpoint_rejects_malicious_webpage_fetch(running_bridge):
    bridge, port = running_bridge
    body = json.dumps({"action": "page.click", "params": {"x": 1, "y": 2}}).encode()
    status, payload = _request(
        port, "POST", "/command",
        {
            "origin": "https://evil.example",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "content-type": "application/json",
        },
        body=body,
    )
    assert status == 403
    assert payload == {"ok": False, "error": "Chrome commands are accepted only from local processes"}
    # The forged command must never have been parsed or enqueued.
    assert bridge._queue == []
    assert bridge._pending == {}


def test_command_endpoint_rejects_same_origin_page_fetch_with_only_sec_fetch_site(running_bridge):
    """Sec-Fetch-Site alone (no Origin) is what a same-origin page fetch looks
    like - still browser-injected, still not a local process. Covers the
    `and` in _is_local_process_request, not just the Origin half of it."""
    bridge, port = running_bridge
    body = json.dumps({"action": "page.click", "params": {}}).encode()
    status, payload = _request(
        port, "POST", "/command",
        {"sec-fetch-site": "same-origin", "content-type": "application/json"},
        body=body,
    )
    assert status == 403
    assert payload["ok"] is False
    assert bridge._queue == []


def test_command_endpoint_allows_true_local_process_request(bridge_module, running_bridge, monkeypatch):
    """Control: a real local process (no Origin, no Sec-Fetch-Site at all -
    e.g. curl, or /lp's own in-process caller) must get PAST the origin gate.

    Isolates the ORIGIN gate specifically: the licence gate is stubbed open so
    a 402 can't mask an origin-gate pass. (This used to lean on overlay.fire
    being licence-exempt; nothing is exempt now.) A tiny timeoutMs then proves
    it reached real command handling - 504 = nobody answered - rather than
    being rejected at either gate (403 or 402)."""
    _bridge, port = running_bridge
    monkeypatch.setattr(bridge_module, "_require_command_licensed", lambda *_a: None)
    body = json.dumps({
        "action": "overlay.fire",
        "params": {"targetId": 1, "event": "__claude-indicator-show", "detail": {}},
        "timeoutMs": 50,
    }).encode()
    status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
    assert status == 504
    assert payload["ok"] is False


# ---------------------------------------------------------------------------
# Drill 4: THE CONFIRMED BYPASS this file exists to close. chrome_tools.py's
# my_browser_* handlers all funnel through its own _send(), which requires
# auth.require_authorized() AND licensing.require_pro_licensed() before ever
# calling bridge.send() - but POST /command is a second, totally separate way
# to reach _send_local (any local process, e.g. `curl -X POST
# 127.0.0.1:16329/command -d '{"action":"page.click",...}'`, the exact
# pattern this project's own docs show) that never passed through
# chrome_tools.py at all. _require_command_licensed closes that hole; these
# two tests check it at the HTTP layer (402, not 200/504) AND at internal
# queue state (never enqueued at all - not merely rejected after queuing),
# same shape as Drill 1/2 above. NO action is exempt: "overlay.fire" used to
# be, back when the indicator was a free tier, but LucidPilot has no free tier
# now and the overlay is licensed like everything else.
# ---------------------------------------------------------------------------

def test_command_endpoint_gates_non_overlay_actions_when_unlicensed(running_bridge):
    bridge, port = running_bridge
    body = json.dumps({"action": "page.click", "params": {"x": 1, "y": 2}, "timeoutMs": 50}).encode()
    status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
    assert status == 402
    assert payload["ok"] is False
    assert payload["error"]  # non-empty, actionable message - never a bare failure
    # Denied before ever reaching the queue, not queued-then-rejected.
    assert bridge._queue == []
    assert bridge._pending == {}


def test_command_endpoint_gates_overlay_fire_too(running_bridge):
    """The former exemption, now closed: the overlay is paid like everything
    else, so an unlicensed caller cannot even paint a cursor."""
    bridge, port = running_bridge
    body = json.dumps({
        "action": "overlay.fire",
        "params": {"targetId": 1, "event": "__claude-cursor-click", "detail": {"x": 1, "y": 2}},
        "timeoutMs": 50,
    }).encode()
    status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
    assert status == 402
    assert payload["ok"] is False
    assert payload["error"]
    # Denied before the queue, same as any other action.
    assert bridge._queue == []
    assert bridge._pending == {}


def test_licensed_overlay_fire_reaches_dispatch(bridge_module, running_bridge, monkeypatch):
    """Positive control for the test above: with the licence gate open, the
    same request gets all the way to real dispatch (504 = nobody answered),
    proving the 402 was the licence gate and not a broken overlay path."""
    bridge, port = running_bridge
    monkeypatch.setattr(bridge_module, "_require_command_licensed", lambda *_a: None)
    body = json.dumps({
        "action": "overlay.fire",
        "params": {"targetId": 1, "event": "__claude-cursor-click", "detail": {"x": 1, "y": 2}},
        "timeoutMs": 50,
    }).encode()
    status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
    assert status == 504
    assert payload["ok"] is False
    assert bridge._queue == []
    assert bridge._pending == {}


# ---------------------------------------------------------------------------
# Drill 5: the gate's verdict now lives in bridge state itself (the
# extension's assertion), so unlike the pre-inversion suite the flat load
# above already exercises the REAL gate. The package loader is kept for two
# reasons: it proves licensing.is_pro_licensed() (the check_fn every tool
# registers) reads the same bridge state through its _server_bridge fast
# path, and it pins the licensed round trip end to end - assertion in over
# the extension's own polling endpoint, command queued, result delivered.
# ---------------------------------------------------------------------------

def load_bridge_module_as_package():
    pkg_name = "security_drills_pkg_under_test"
    for name in list(sys.modules):
        if name == pkg_name or name.startswith(pkg_name + "."):
            sys.modules.pop(name, None)
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = [str(REPO_ROOT)]
    sys.modules[pkg_name] = pkg
    spec = importlib.util.spec_from_file_location(f"{pkg_name}.bridge", REPO_ROOT / "bridge.py")
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"{pkg_name}.bridge"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    # licensing's _server_bridge fast path does `from . import bridge`, which
    # resolves to the same package member loaded above - import licensing
    # explicitly here so tests can call is_pro_licensed() on the real module.
    licensing_module = importlib.import_module(f"{pkg_name}.licensing")
    return module, licensing_module


@pytest.fixture
def bridge_and_licensing(tmp_path, monkeypatch):
    # Isolates real on-disk license state (~/.hermes/lucidpilot/license.json)
    # behind a throwaway tmp_path for every test using this fixture, so
    # "unlicensed" is genuinely, deterministically true here regardless of
    # whatever license state happens to exist on the machine running this
    # suite - matching this file's own "genuinely separate" testing style
    # (see SECOND_FOREIGN_EXTENSION_ID's header comment above).
    monkeypatch.setenv("LUCIDPILOT_LICENSE_DIR", str(tmp_path / "lucidpilot"))
    return load_bridge_module_as_package()


@pytest.fixture
def running_bridge_pkg(bridge_and_licensing):
    module, licensing_module = bridge_and_licensing
    bridge = module.ChromeProfileBridge(host="127.0.0.1", port=0)
    bridge.ensure_started()
    assert bridge._mode == "server"
    port = bridge._httpd.server_address[1]
    yield bridge, port, module, licensing_module
    bridge.stop()


def test_command_endpoint_real_license_gate_denies_unlicensed_control_action(running_bridge_pkg):
    bridge, port, _module, licensing_module = running_bridge_pkg
    # Sanity: the check_fn path (licensing reading this very bridge through
    # _server_bridge) agrees the session is unlicensed - one verdict, two
    # readers.
    assert licensing_module.is_pro_licensed() is False

    body = json.dumps({"action": "page.click", "params": {"x": 1, "y": 2}, "timeoutMs": 50}).encode()
    status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
    assert status == 402
    assert payload["ok"] is False
    # No assertion has ever arrived here, so the denial must name the actual
    # cause - a silent extension - not send the user hunting for a key.
    assert "not reported a licence recently" in payload["error"]

    # Not merely "rejected at the HTTP layer" - never enqueued internally either
    # (same shape as Drill 1/4's queue-state checks above; unlike that drill's
    # GET /next positive control, deliberately NOT polling /next here to prove
    # emptiness - _take_next_command long-polls for _NEXT_LONG_POLL_S (25s)
    # when the queue is empty, so that would just make this test slow for no
    # extra proof beyond what _queue/_pending already show directly).
    assert bridge._queue == []
    assert bridge._pending == {}


def test_command_endpoint_licensed_control_action_reaches_queue_and_completes(running_bridge_pkg):
    """Licenses the bridge the way the real extension does (an assertion
    recorded by the /next path) and proves a real control action (page.click)
    doesn't just skip the 402 - it fully reaches the real queue (observable
    via the real extension's GET /next, the exact endpoint the actual Chrome
    extension polls) and, once "answered" the way the real extension would
    via POST /result, completes the original POST /command with a 200 and the
    real result payload. Reaching a 504 timeout alone wouldn't distinguish
    "queued but never answered" from "the gate secretly still swallowed it
    silently" - actually draining the queue and completing the round trip is
    the stronger proof."""
    bridge, port, module, licensing_module = running_bridge_pkg

    result_holder: dict = {}

    def do_post() -> None:
        body = json.dumps({
            "action": "page.click",
            "params": {"x": 9, "y": 9},
            "timeoutMs": 5000,
        }).encode()
        status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
        result_holder["status"] = status
        result_holder["payload"] = payload

    bridge.note_license_assertion(ed25519_sign.valid_assert())
    # Sanity: the check_fn path sees the same verdict the gate will use.
    assert licensing_module.is_pro_licensed() is True

    poster = threading.Thread(target=do_post, daemon=True)
    poster.start()
    try:
        real_origin = f"chrome-extension://{module._DEV_EXTENSION_ID}"
        command = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status, payload = _request(port, "GET", "/next", {"origin": real_origin})
            if payload.get("type") == "command":
                command = payload["command"]
                break
            time.sleep(0.02)
        assert command is not None, "licensed page.click never reached the real queue"
        assert command["action"] == "page.click"
        assert command["params"] == {"x": 9, "y": 9}

        # Answer it exactly like the real extension's POST /result would,
        # so the blocked POST above returns normally instead of timing out.
        result_body = json.dumps({"id": command["id"], "ok": True, "result": {"clicked": True}}).encode()
        status, payload = _request(
            port, "POST", "/result",
            {"origin": real_origin, "content-type": "application/json"},
            body=result_body,
        )
        assert status == 200
        assert payload == {"ok": True}
    finally:
        poster.join(timeout=5)
        assert not poster.is_alive(), "POST /command never returned - dispatch likely never reached the queue"

    assert result_holder["status"] == 200
    assert result_holder["payload"] == {"ok": True, "result": {"clicked": True}}


# ---------------------------------------------------------------------------
# Drill 6: the licence assertion channel itself. The extension licenses the
# bridge via POST /assert-license; these tests pin down WHO can do that
# (only the pinned extension origin - an origin-less request, which curl and
# any sibling extension's host-permitted fetch both produce, is refused) and
# for HOW LONG it holds (the TTL fails closed once the extension goes
# silent). A POST because Chrome omits the Origin header on host-permitted
# GETs from the worker - a piggyback header on GET /next arrived origin-less
# in real Chrome and could never pass this pin (shipped and sniffed).
# ---------------------------------------------------------------------------

# A provable assertion: valid:true plus a session token signed by the suite's
# test key (conftest pins its public half via LUCIDPILOT_LICENSE_PUBKEY).
_VALID_ASSERT = ed25519_sign.valid_assert()


def test_assertion_from_pinned_origin_licenses_the_bridge(bridge_module, running_bridge):
    bridge, port = running_bridge
    assert bridge.is_licensed() is False
    real_origin = f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"
    status, payload = _request(
        port, "POST", "/assert-license",
        {"origin": real_origin}, body=_VALID_ASSERT.encode(),
    )
    assert status == 200
    assert payload["ok"] is True
    assert bridge.is_licensed() is True
    assert bridge.license_fields()["tier"] == "PRO"


def test_assertion_without_origin_is_refused(running_bridge):
    """An origin-less request - curl, or a sibling extension's host-permitted
    fetch (both arrive with no Origin header) - must not license the bridge,
    the exact spoof this inversion closed."""
    bridge, port = running_bridge
    status, _payload = _request(port, "POST", "/assert-license", {}, body=_VALID_ASSERT.encode())
    assert status == 403
    assert bridge.is_licensed() is False


def test_next_poll_no_longer_carries_an_assertion(bridge_module, running_bridge, monkeypatch):
    """Regression pin on the dead transport: even a pinned-Origin GET /next
    with the old header must not license the bridge - the header path is gone,
    not merely gated."""
    monkeypatch.setattr(bridge_module, "_NEXT_LONG_POLL_S", 0.05)
    bridge, port = running_bridge
    real_origin = f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"
    status, _payload = _request(
        port, "GET", "/next",
        {"origin": real_origin, "x-lucidpilot-assert": _VALID_ASSERT},
    )
    assert status == 200
    assert bridge.is_licensed() is False


def test_assertion_expires_after_ttl_and_command_names_the_cause(bridge_module, running_bridge):
    bridge, port = running_bridge
    bridge.note_license_assertion(_VALID_ASSERT)
    assert bridge.is_licensed() is True

    # Age the assertion past the TTL (inject the clock rather than sleeping).
    bridge._license_asserted_at = time.time() - bridge_module._LICENSE_ASSERT_TTL_S - 1
    assert bridge.is_licensed() is False

    body = json.dumps({"action": "page.click", "params": {"x": 1, "y": 2}, "timeoutMs": 50}).encode()
    status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
    assert status == 402
    assert "not reported a licence recently" in payload["error"]
    assert bridge._queue == []


def test_fresh_but_invalid_assertion_points_at_the_popup(running_bridge):
    """An extension that IS reporting, just without a key, is a missing-key
    problem - the 402 must say popup/subscribe, not blame connectivity."""
    bridge, port = running_bridge
    bridge.note_license_assertion(json.dumps({"valid": False, "tier": None, "lastCheckAt": 0}))
    assert bridge.is_licensed() is False

    body = json.dumps({"action": "page.click", "params": {"x": 1, "y": 2}, "timeoutMs": 50}).encode()
    status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
    assert status == 402
    assert "popup" in payload["error"]
    assert "not reported a licence recently" not in payload["error"]


def test_malformed_assertion_is_ignored_and_does_not_unlicense(running_bridge):
    bridge, _port = running_bridge
    bridge.note_license_assertion(_VALID_ASSERT)
    assert bridge.is_licensed() is True
    bridge.note_license_assertion("{not json")
    assert bridge.is_licensed() is True  # garbage neither crashes nor clobbers


def test_assertion_flip_fires_change_callbacks_once_per_flip(running_bridge):
    bridge, _port = running_bridge
    flips: list = []
    bridge.on_license_change(lambda: flips.append(True))

    bridge.note_license_assertion(_VALID_ASSERT)      # unlicensed -> licensed
    bridge.note_license_assertion(_VALID_ASSERT)      # no flip: still licensed
    bridge.note_license_assertion(json.dumps({"valid": False}))  # licensed -> unlicensed
    assert len(flips) == 2


# ---------------------------------------------------------------------------
# Drill 6b: the signed session token - the part of /assert-license that is
# NOT the extension's word. valid:true alone (what a patched extension can
# say) must license nothing; only a token signed by the licensing server's
# entitlement key may. Each drill is one forgery attempt.
# ---------------------------------------------------------------------------


def test_valid_true_without_token_is_not_licensed(running_bridge):
    """The pre-token assertion shape - exactly what a tampered or outdated
    extension sends. The honor system this feature removed."""
    bridge, _port = running_bridge
    bridge.note_license_assertion(json.dumps({"valid": True, "tier": "PRO", "lastCheckAt": 0}))
    assert bridge.is_licensed() is False
    assert bridge.license_fields()["licenseTokenState"] == "missing"


def test_tampered_payload_is_not_licensed(running_bridge):
    """Re-signable only with the private key: flipping any payload byte after
    signing must fail. Tier upgrade attempt as the concrete case."""
    bridge, _port = running_bridge
    token = ed25519_sign.session_token()
    payload_b64, sig_b64 = token.split(".")
    import base64 as b64

    raw = b64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    tampered = raw.replace(b'"PRO"', b'"ULT"', 1)
    tampered_b64 = b64.urlsafe_b64encode(tampered).rstrip(b"=").decode()
    bridge.note_license_assertion(ed25519_sign.valid_assert(token=f"{tampered_b64}.{sig_b64}"))
    assert bridge.is_licensed() is False
    assert bridge.license_fields()["licenseTokenState"] == "invalid"


def test_token_signed_by_a_foreign_key_is_not_licensed(running_bridge):
    """A cracker minting tokens with their own keypair."""
    bridge, _port = running_bridge
    foreign_secret, _foreign_pub = ed25519_sign.generate_keypair()
    bridge.note_license_assertion(
        ed25519_sign.valid_assert(token=ed25519_sign.mint_token(foreign_secret))
    )
    assert bridge.is_licensed() is False
    assert bridge.license_fields()["licenseTokenState"] == "invalid"


def test_expired_token_is_not_licensed(running_bridge):
    bridge, _port = running_bridge
    stale = int(time.time()) - 10
    bridge.note_license_assertion(
        ed25519_sign.valid_assert(token=ed25519_sign.session_token(expiresAt=stale))
    )
    assert bridge.is_licensed() is False
    assert bridge.license_fields()["licenseTokenState"] == "expired"


def test_wrong_product_or_state_is_not_licensed(running_bridge):
    """A genuine token from another product (or a revoked entitlement) must
    not unlock LucidPilot - the payload pins productId and state, not just
    the signature."""
    bridge, _port = running_bridge
    bridge.note_license_assertion(
        ed25519_sign.valid_assert(token=ed25519_sign.session_token(productId="bitbonsai"))
    )
    assert bridge.is_licensed() is False
    bridge.note_license_assertion(
        ed25519_sign.valid_assert(token=ed25519_sign.session_token(state="REVOKED"))
    )
    assert bridge.is_licensed() is False


def test_valid_token_with_valid_false_is_not_licensed(running_bridge):
    """The extension's own verdict still counts: a stolen-but-genuine token
    cannot override an extension that says unlicensed (e.g. right after
    deactivation, before the token would expire server-side)."""
    bridge, _port = running_bridge
    bridge.note_license_assertion(ed25519_sign.valid_assert(valid=False))
    assert bridge.is_licensed() is False


def test_unproven_assertion_402_names_the_extension_not_the_key(running_bridge):
    """A paying customer whose extension is too old to send a token (or whose
    token expired offline) must NOT be told to enter a key they already have.
    The /command gate and licensing.require_pro_licensed answer the same
    condition, so they must give the same answer."""
    bridge, port = running_bridge
    bridge.note_license_assertion(json.dumps({"valid": True, "tier": "PRO", "lastCheckAt": 0}))
    assert bridge.is_licensed() is False

    body = json.dumps({"action": "page.click", "params": {"x": 1, "y": 2}, "timeoutMs": 50}).encode()
    status, payload = _request(port, "POST", "/command", {"content-type": "application/json"}, body=body)
    assert status == 402
    assert "could not prove" in payload["error"]
    assert "refresh icon" in payload["error"]
    assert "Enter your licence key" not in payload["error"]
    assert bridge._queue == []


def test_signed_tier_outranks_asserted_tier(running_bridge):
    """license_fields reports the server-signed tier, not the extension's
    claim - a patched popup cannot cosmetically upgrade itself."""
    bridge, _port = running_bridge
    bridge.note_license_assertion(ed25519_sign.valid_assert(tier="ULTIMATE"))
    assert bridge.is_licensed() is True
    assert bridge.license_fields()["tier"] == "PRO"  # from the signed claims


# ---------------------------------------------------------------------------
# Drill 3: structural grep-gate over the actual BUILT dist/ output. No literal
# secret to grep for (nothing is hardcoded) - the check is that no logAction()
# call, and no branch of glue.js's buildMessage(), ever threads a
# `.value`/`.text`-shaped typed-content read into the message that ends up in
# chrome.storage.local's audit log.
# ---------------------------------------------------------------------------

DIST_DIR = REPO_ROOT / "chrome-extension" / "dist"

# ponytail: existence-only freshness check (no mtime staleness comparison
# like tests/e2e/global-setup.ts does) - good enough for CI (which always
# runs `npm run build` before pytest, see .gitea/workflows/ci.yml) and for a
# first local run. If dist/ goes stale without being rebuilt, this check
# would read old output; rebuild via `npm run build` if that's ever a problem.
def _ensure_dist_built() -> None:
    if (DIST_DIR / "content.js").exists() and (DIST_DIR / "glue.js").exists():
        return
    subprocess.run(["npm", "run", "build"], cwd=REPO_ROOT, check=True)


# Shapes that would indicate typed input leaking into the log pipeline: a
# member access on `.value`/`.text` (DOM input value, or a control message's
# text field), or an object literal carrying one of those as a key.
LEAK_TOKENS = (".value", ".text", "text:", "value:")


def _extract_call_args(source: str, call_prefix: str) -> list[str]:
    """Return the raw argument-list text of every `call_prefix(...)`
    invocation in source, paren-balanced and quote-aware (skips characters
    inside '/"/` strings so a stray ')' in a JS string literal can't
    mismatch the depth count). Deliberately not a real JS parser - stdlib
    string scanning is enough for this repo's flat, unminified esbuild IIFE
    output; add a real parser only if that stops being true.
    """
    calls: list[str] = []
    start = 0
    while True:
        idx = source.find(call_prefix, start)
        if idx == -1:
            break
        i = idx + len(call_prefix)
        depth = 1
        quote = None
        arg_start = i
        while depth > 0 and i < len(source):
            c = source[i]
            if quote:
                if c == "\\":
                    i += 2
                    continue
                if c == quote:
                    quote = None
            elif c in ("'", '"', "`"):
                quote = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            i += 1
        calls.append(source[arg_start:i - 1])
        start = i
    return calls


def _extract_function_body(source: str, function_signature_prefix: str) -> str:
    start = source.index(function_signature_prefix)
    depth = 0
    end = None
    for i in range(start, len(source)):
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    assert end is not None, f"unbalanced braces after {function_signature_prefix!r}"
    return source[start:end]


def test_content_js_logaction_calls_never_carry_typed_text():
    _ensure_dist_built()
    content_js = (DIST_DIR / "content.js").read_text()
    calls = _extract_call_args(content_js, "logAction(")
    # Sanity: the extraction itself must actually find the known call sites
    # (11 in chrome-extension/src/content.ts as of this writing) - an empty
    # list would make every assertion below vacuously true.
    assert len(calls) >= 11, f"expected >=11 logAction() calls in content.js, found {len(calls)}"
    offenders = [c for c in calls if any(tok in c for tok in LEAK_TOKENS)]
    assert offenders == [], f"logAction() called with a typed-text-shaped argument: {offenders}"


def _strip_line_comments(text: str) -> str:
    """Drop `// ...` line comments (quote-aware, so a `//` inside a string
    literal survives). glue.js is copied into dist/ verbatim (see
    scripts/build-extension.mjs's STATIC_ASSETS) - unlike content.js, which
    esbuild compiles and strips comments from, glue.js's own source comments
    (e.g. "never params.text") are still literally present in dist/glue.js
    and would otherwise false-positive a substring check on `params.text`.
    """
    out = []
    quote = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"', "`"):
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            if j == -1:
                break
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def test_glue_js_build_message_never_reads_params_text_or_value():
    _ensure_dist_built()
    glue_js = (DIST_DIR / "glue.js").read_text()
    # buildMessage() is the sole place a page.type/page.fill command's
    # `params` gets turned into the runtime message content.ts's logAction
    # persists - see its own header comment ("never params.text").
    fn_body = _strip_line_comments(_extract_function_body(glue_js, "function buildMessage"))
    assert "params.text" not in fn_body
    assert "params.value" not in fn_body
    # Belt-and-suspenders: the type/fill branch must only ever assign
    # coordinates (x/y), never text/value, onto the outgoing message.
    assert "msg.text" not in fn_body
    assert "msg.value" not in fn_body
