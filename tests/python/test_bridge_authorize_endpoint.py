"""POST /authorize: the popup's Chrome-control grant/revoke endpoint.

The security property under test: ONLY the pinned extension popup can reach
it. A local process has no Origin header (it must keep using /lp), a web page
cannot spoof its Origin, and a foreign extension's Origin isn't pinned - all
three must be refused, while the pinned Origin grants/revokes for real.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

FOREIGN_EXTENSION_ID = "qz" * 16


def _load(name: str, filename: str):
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bridge_and_auth():
    bridge_mod = _load("bridge_authz_under_test", "bridge.py")
    auth_mod = _load("auth_authz_under_test", "auth.py")
    bridge = bridge_mod.ChromeProfileBridge(host="127.0.0.1", port=0)
    bridge.auth = auth_mod.ChromeAuth()
    bridge.ensure_started()
    assert bridge._mode == "server"
    port = bridge._httpd.server_address[1]
    yield bridge_mod, bridge, port
    bridge.stop()


def _post_authorize(port: int, headers: dict, body: dict):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", "/authorize", body=json.dumps(body).encode(), headers={"content-type": "application/json", **headers})
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read().decode() or "{}")
    finally:
        conn.close()


def _pinned_origin(bridge_mod) -> dict:
    return {"origin": f"chrome-extension://{bridge_mod._DEV_EXTENSION_ID}"}


def test_pinned_popup_can_authorize_and_status_reflects_it(bridge_and_auth):
    bridge_mod, bridge, port = bridge_and_auth
    status, payload = _post_authorize(port, _pinned_origin(bridge_mod), {"minutes": 480})
    assert status == 200
    assert payload["ok"] is True
    assert payload["authorized"] is True
    assert isinstance(payload["authorizedUntil"], float)
    assert bridge.status()["authorized"] is True
    assert bridge.status()["authorizedUntil"] == payload["authorizedUntil"]


def test_pinned_popup_can_revoke(bridge_and_auth):
    bridge_mod, bridge, port = bridge_and_auth
    _post_authorize(port, _pinned_origin(bridge_mod), {"minutes": 60})
    status, payload = _post_authorize(port, _pinned_origin(bridge_mod), {"revoke": True})
    assert status == 200
    assert payload["authorized"] is False
    assert payload["authorizedUntil"] is None
    assert bridge.auth.is_authorized() is False


def test_local_process_without_origin_is_refused(bridge_and_auth):
    _bridge_mod, bridge, port = bridge_and_auth
    status, payload = _post_authorize(port, {}, {"minutes": 60})
    assert status == 403
    assert "extension popup" in payload["error"]
    assert bridge.auth.is_authorized() is False


def test_webpage_and_foreign_extension_origins_are_refused(bridge_and_auth):
    _bridge_mod, bridge, port = bridge_and_auth
    for origin in ("https://evil.example", f"chrome-extension://{FOREIGN_EXTENSION_ID}"):
        status, _payload = _post_authorize(port, {"origin": origin, "sec-fetch-site": "cross-site"}, {"minutes": 60})
        assert status == 403, origin
    assert bridge.auth.is_authorized() is False


def test_503_when_no_auth_is_wired(bridge_and_auth):
    bridge_mod, bridge, port = bridge_and_auth
    bridge.auth = None
    status, payload = _post_authorize(port, _pinned_origin(bridge_mod), {"minutes": 60})
    assert status == 503
    assert "not enabled" in payload["error"]


def test_bad_duration_is_a_400_and_grants_nothing(bridge_and_auth):
    bridge_mod, bridge, port = bridge_and_auth
    status, payload = _post_authorize(port, _pinned_origin(bridge_mod), {"minutes": "soon"})
    assert status == 400
    assert "Unknown authorize duration" in payload["error"]
    assert bridge.auth.is_authorized() is False


def test_indefinite_grant_round_trips(bridge_and_auth):
    bridge_mod, bridge, port = bridge_and_auth
    status, payload = _post_authorize(port, _pinned_origin(bridge_mod), {"minutes": "indefinite"})
    assert status == 200
    assert payload["authorizedUntil"] == "indefinite"
    assert bridge.status()["authorizedUntil"] == "indefinite"
