"""Coverage for the two Python-side pieces of session-scoped tab isolation
(the real behavior - remembering and re-targeting a session's own tab -
lives in glue.js and is proven end-to-end by tests/e2e/regression.spec.ts's
"two sessions each stick to their own tab" test):

1. bridge.SESSION_ID is generated per module load (simulating "per process" -
   two independent execs of bridge.py's top level, same as two real
   mcp_server.py subprocesses each importing it fresh).
2. chrome_tools.py's _send() actually puts it on the wire, alongside the
   existing `agent` field, on a REAL (auth+licence gated) my_browser_*
   handler call - not just a raw POST /command, which bypasses chrome_tools.py
   entirely and so cannot prove this.

Loader: same importlib-by-path / synthetic-package approach as
test_bridge_conflict_detection.py and test_security_drills.py's
load_bridge_module_as_package - both documented there, reused verbatim here.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path

import pytest

import ed25519_sign

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_bridge_module():
    for name in list(sys.modules):
        if name == "session_isolation_bridge_under_test":
            sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(
        "session_isolation_bridge_under_test", REPO_ROOT / "bridge.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["session_isolation_bridge_under_test"] = module
    spec.loader.exec_module(module)
    return module


def test_session_id_differs_per_process():
    """Two independent execs of bridge.py's module top level (what two real
    mcp_server.py subprocesses each do) must not generate the same id - if
    they collided, two simultaneous sessions would share one tab, exactly
    the bug this feature exists to prevent."""
    first = load_bridge_module()
    second = load_bridge_module()
    assert first.SESSION_ID and second.SESSION_ID
    assert first.SESSION_ID != second.SESSION_ID


def test_session_id_stable_within_one_module_instance():
    module = load_bridge_module()
    first_read = module.SESSION_ID
    second_read = module.SESSION_ID
    assert first_read == second_read


def load_pkg_with_chrome_tools():
    """Same synthetic-package trick as test_security_drills.py's
    load_bridge_module_as_package, extended to also load chrome_tools.py -
    which does `from . import bridge as bridge_module` and needs a real
    package parent to resolve that."""
    pkg_name = "session_isolation_pkg_under_test"
    for name in list(sys.modules):
        if name == pkg_name or name.startswith(pkg_name + "."):
            sys.modules.pop(name, None)
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = [str(REPO_ROOT)]
    sys.modules[pkg_name] = pkg
    spec = importlib.util.spec_from_file_location(f"{pkg_name}.bridge", REPO_ROOT / "bridge.py")
    assert spec is not None and spec.loader is not None
    bridge_mod = importlib.util.module_from_spec(spec)
    sys.modules[f"{pkg_name}.bridge"] = bridge_mod
    spec.loader.exec_module(bridge_mod)
    auth_mod = importlib.import_module(f"{pkg_name}.auth")
    licensing_mod = importlib.import_module(f"{pkg_name}.licensing")
    chrome_tools_mod = importlib.import_module(f"{pkg_name}.chrome_tools")
    return bridge_mod, auth_mod, licensing_mod, chrome_tools_mod


class _RecordingBridge:
    """Duck-types just enough of ChromeProfileBridge for chrome_tools._send:
    a background_default _wire() reads, and a send() that records what it
    was called with instead of doing real I/O (there is no extension
    connected in this test)."""

    def __init__(self):
        self.background_default = True
        self.connected = False
        self.calls = []

    def send(self, action, params, timeout_ms=None):
        self.calls.append((action, params))
        return {}


def test_send_puts_this_processs_session_id_on_the_wire(tmp_path, monkeypatch):
    monkeypatch.setenv("LUCIDPILOT_LICENSE_DIR", str(tmp_path / "lucidpilot"))
    bridge_mod, auth_mod, licensing_mod, chrome_tools_mod = load_pkg_with_chrome_tools()

    # License + authorize directly (no real bridge/extension needed - _send's
    # two gates, auth.require_authorized() and require_pro_licensed(), just
    # need to not raise). server-mode assertion via the real signed-token
    # path, same as test_security_drills.py's licensed fixtures.
    real_bridge = bridge_mod.ChromeProfileBridge(host="127.0.0.1", port=0)
    real_bridge.ensure_started()
    try:
        real_bridge.note_license_assertion(ed25519_sign.valid_assert())
        assert licensing_mod.is_pro_licensed() is True

        auth = auth_mod.ChromeAuth()
        auth.authorize("30")
        assert auth.is_authorized() is True

        recording = _RecordingBridge()

        class FakeContext:
            def __init__(self):
                self.tools = {}

            def register_tool(self, name, toolset, schema, handler, emoji=None, check_fn=None, **kw):
                self.tools[name] = handler

            def register_hook(self, *a, **kw):
                pass

            def register_command(self, *a, **kw):
                pass

        ctx = FakeContext()
        chrome_tools_mod.register_all_tools(ctx, recording, auth)

        result = ctx.tools["my_browser_navigate"]({"url": "https://example.com"})
        assert "[lucidpilot]" not in result  # would mean a gate raised instead of reaching send()

        assert len(recording.calls) == 1
        action, params = recording.calls[0]
        assert action == "page.navigate"
        assert params["sessionId"] == bridge_mod.SESSION_ID
        assert params["agent"] == bridge_mod.AGENT
    finally:
        real_bridge.stop()
