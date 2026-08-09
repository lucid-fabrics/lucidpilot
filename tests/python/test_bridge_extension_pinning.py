"""Pytest coverage for extension-id pinning on bridge.py's /next and /result
endpoints (see bridge.py's _allowed_extension_ids / _is_browser_origin_allowed).

Loader note: mirrors test_plugin_registration.py's importlib-by-path loader.
bridge.py has no relative imports (stdlib only), so a plain `import bridge`
would work once its directory is on sys.path - but which directory ends up on
sys.path depends on how pytest was invoked (rootdir vs. this file's own
directory), and _allowed_extension_ids() reads LUCIDPILOT_EXTENSION_IDS at
*import* time (same pattern as DEFAULT_PORT reading LUCIDPILOT_BRIDGE_PORT),
so tests that patch that env var need a genuinely fresh module object, not
whatever happened to already be cached in sys.modules. Loading by file path
sidesteps both problems.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Not a real id - just guaranteed not to be the one pinned in manifest.json's
# "key" field / bridge.py's _DEV_EXTENSION_ID (both real ids are lowercase
# a-p only, by construction of Chrome's id algorithm - this uses 'q'/'z' so
# it can never collide with a real one by accident).
FOREIGN_EXTENSION_ID = "qz" * 16


def load_bridge_module():
    for name in list(sys.modules):
        if name == "bridge_under_test":
            sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("bridge_under_test", REPO_ROOT / "bridge.py")
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["bridge_under_test"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bridge_module():
    return load_bridge_module()


def test_pinned_dev_id_is_allowed(bridge_module):
    headers = {"origin": f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"}
    assert bridge_module._is_browser_origin_allowed(headers) is True


def test_foreign_extension_id_is_rejected(bridge_module):
    headers = {"origin": f"chrome-extension://{FOREIGN_EXTENSION_ID}"}
    assert bridge_module._is_browser_origin_allowed(headers) is False


def test_extension_id_matches_manifest_key():
    """Not just re-asserting the same hardcoded string bridge.py carries:
    recompute the id independently from chrome-extension/manifest.json's
    "key" field via Chrome's own algorithm (sha256(DER)[:16], nibbles mapped
    0-15 -> 'a'-'p') and check the two agree."""
    import base64
    import hashlib

    bridge = load_bridge_module()
    manifest = json.loads((REPO_ROOT / "chrome-extension" / "manifest.json").read_text())
    der = base64.b64decode(manifest["key"])
    digest = hashlib.sha256(der).digest()[:16]
    computed_id = "".join(chr(ord("a") + (b >> 4)) + chr(ord("a") + (b & 0xF)) for b in digest)
    assert computed_id == bridge._DEV_EXTENSION_ID


def test_extra_id_from_env_var_is_allowed():
    with mock.patch.dict(os.environ, {"LUCIDPILOT_EXTENSION_IDS": FOREIGN_EXTENSION_ID}):
        bridge = load_bridge_module()
        headers = {"origin": f"chrome-extension://{FOREIGN_EXTENSION_ID}"}
        assert bridge._is_browser_origin_allowed(headers) is True
        # The dev id itself is still allowed too - env var adds, never replaces.
        dev_headers = {"origin": f"chrome-extension://{bridge._DEV_EXTENSION_ID}"}
        assert bridge._is_browser_origin_allowed(dev_headers) is True


@pytest.fixture
def running_bridge(bridge_module):
    """A real ChromeProfileBridge bound to an OS-assigned free port (port=0),
    so this suite never fights a real bridge.py process for 16329."""
    bridge = bridge_module.ChromeProfileBridge(host="127.0.0.1", port=0)
    bridge.ensure_started()
    assert bridge._mode == "server"
    port = bridge._httpd.server_address[1]
    yield port
    bridge.stop()


def _request(port: int, method: str, path: str, origin: str | None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, headers={"origin": origin} if origin else {})
        resp = conn.getresponse()
        body = json.loads(resp.read().decode() or "{}")
        return resp.status, body
    finally:
        conn.close()


# /result never blocks (unlike /next's long-poll), so these hit the real HTTP
# handler end to end without needing to queue a command first.

def test_result_endpoint_rejects_foreign_extension_origin(running_bridge):
    status, body = _request(running_bridge, "POST", "/result", f"chrome-extension://{FOREIGN_EXTENSION_ID}")
    assert status == 403
    assert body["ok"] is False


def test_result_endpoint_accepts_pinned_extension_origin(bridge_module, running_bridge):
    origin = f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"
    status, body = _request(running_bridge, "POST", "/result", origin)
    # 404 here is _deliver_result's "unknown command id" - business logic, not
    # the origin gate. That's the point: a 403 would mean pinning broke the
    # legitimate extension's own requests.
    assert status == 404
    assert body["ok"] is False
    assert "browser origin not allowed" not in (body.get("error") or "")


# OPTIONS (preflight) never blocks either, and shares do_OPTIONS's origin
# check with GET /next - so this covers /next's enforcement without needing
# to race its 25s long-poll.

def test_next_preflight_rejects_foreign_extension_origin(running_bridge):
    status, body = _request(running_bridge, "OPTIONS", "/next", f"chrome-extension://{FOREIGN_EXTENSION_ID}")
    assert status == 403
    assert body["ok"] is False


def test_next_preflight_accepts_pinned_extension_origin(bridge_module, running_bridge):
    origin = f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"
    status, body = _request(running_bridge, "OPTIONS", "/next", origin)
    assert status == 200
    assert body["ok"] is True


# /status is read-only (GET, no queue interaction) so, like /result above, it
# hits the real HTTP handler end to end with no setup beyond a running bridge.

def test_status_endpoint_rejects_foreign_extension_origin(running_bridge):
    status, body = _request(running_bridge, "GET", "/status", f"chrome-extension://{FOREIGN_EXTENSION_ID}")
    assert status == 403
    assert body["ok"] is False


def test_status_endpoint_accepts_pinned_extension_origin(bridge_module, running_bridge):
    origin = f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"
    status, body = _request(running_bridge, "GET", "/status", origin)
    assert status == 200
    # Fields the popup's health panel and /lp doctor both rely on.
    assert "extensionConnected" in body
    assert "authorized" in body
    assert "version" in body
    assert "licensed" in body


def test_status_endpoint_allows_local_process_request(running_bridge):
    """No Origin header at all (curl, /lp doctor's own in-process calls if it
    ever went over HTTP) must keep working - pinning only targets *browser*
    origins, per _is_browser_origin_allowed's own local-process allowance."""
    status, body = _request(running_bridge, "GET", "/status", None)
    assert status == 200
    assert "version" in body


# /testdrive (popup test-drive fixture): read-only static HTML, so - like
# /status and /result above - it hits the real HTTP handler end to end with
# no queued command needed. Uses http.client directly (not the JSON-decoding
# _request helper above) since the response body is HTML, not JSON.

def _request_raw(port: int, path: str, origin: str | None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers={"origin": origin} if origin else {})
        resp = conn.getresponse()
        return resp.status, resp.getheader("content-type"), resp.read().decode()
    finally:
        conn.close()


def test_testdrive_endpoint_rejects_foreign_extension_origin(running_bridge):
    status, _content_type, body = _request_raw(running_bridge, "/testdrive", f"chrome-extension://{FOREIGN_EXTENSION_ID}")
    assert status == 403
    assert json.loads(body)["ok"] is False


def test_testdrive_endpoint_serves_fixture_html(bridge_module, running_bridge):
    origin = f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"
    status, content_type, body = _request_raw(running_bridge, "/testdrive", origin)
    assert status == 200
    assert content_type is not None and "text/html" in content_type
    # The exact id testdrive.ts's page.click step targets - if this fixture's
    # markup ever changes, this test and the real demo break for the same
    # reason, not silently drift apart.
    assert 'id="test-drive-link"' in body


def test_testdrive_endpoint_allows_local_process_request(running_bridge):
    status, _content_type, body = _request_raw(running_bridge, "/testdrive", None)
    assert status == 200
    assert "test-drive-link" in body
