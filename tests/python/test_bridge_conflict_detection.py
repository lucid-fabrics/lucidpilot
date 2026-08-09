"""Pytest coverage for bridge.py's port-conflict handling
(_bind_server_or_client). See loader note in test_bridge_extension_pinning.py -
same approach here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


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


def test_real_eaddrinuse_between_two_bridges_stays_a_silent_client(bridge_module):
    """Regression guard: tightening the OSError branch below must not break
    the intentional multi-session coexistence path - two ChromeProfileBridge
    instances genuinely fighting over one real port should still resolve to
    server + client, no exception, exactly as before this change."""
    owner = bridge_module.ChromeProfileBridge(host="127.0.0.1", port=0)
    owner.ensure_started()
    assert owner._mode == "server"
    real_port = owner._httpd.server_address[1]
    try:
        guest = bridge_module.ChromeProfileBridge(host="127.0.0.1", port=real_port)
        guest.ensure_started()
        assert guest._mode == "client"
    finally:
        owner.stop()


def test_unexpected_bind_error_is_wrapped_with_port_and_env_var(bridge_module):
    """The one gap this feature closes: any OSError that ISN'T the recognized
    EADDRINUSE errno (48/98/10048) used to bubble up as a bare, unhelpful
    "[Errno N] ..." string. It should now name the port and point at
    LUCIDPILOT_BRIDGE_PORT."""
    bridge = bridge_module.ChromeProfileBridge(host="127.0.0.1", port=54329)

    def _raise_permission_denied(*_args, **_kwargs):
        raise OSError(13, "Permission denied")

    with mock.patch.object(bridge_module, "ThreadingHTTPServer", side_effect=_raise_permission_denied):
        with pytest.raises(OSError) as exc_info:
            bridge.ensure_started()

    message = str(exc_info.value)
    assert "54329" in message
    assert "LUCIDPILOT_BRIDGE_PORT" in message
    # Original error text preserved, not swallowed.
    assert "Permission denied" in message


def test_owner_unreachable_message_names_port_and_env_var(bridge_module):
    """_send_via_owner's give-up message (mode=="client", owner unreachable,
    and this instance can't take over the port either) should also name the
    port and the env var override - the other spot a real port conflict
    surfaces to whoever is waiting on a bridge.send() call."""
    bridge = bridge_module.ChromeProfileBridge(host="127.0.0.1", port=54331)
    bridge._mode = "client"  # pretend another session owns the port

    with mock.patch.object(bridge, "_try_promote_to_server", return_value=False):
        with mock.patch("urllib.request.urlopen", side_effect=ConnectionError("boom")):
            with pytest.raises(bridge_module.BridgeError) as exc_info:
                bridge._send_via_owner("tab.list", {}, timeout_ms=1000)

    message = str(exc_info.value)
    assert "54331" in message
    assert "LUCIDPILOT_BRIDGE_PORT" in message
