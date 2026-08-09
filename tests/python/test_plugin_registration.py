"""Real pytest coverage for this repo's plugin registration surface: register(ctx)
must wire up exactly the 21 my_browser_* + 6 indicator_* tools (no collisions, no typos),
the pre_llm_call primer hook, and check_fn auth-gating on every my_browser_* tool.

Loader note: "lucidpilot" is a valid Python package name, so a plain
`import lucidpilot` is tried first. It still fails under a bare `pytest` run
from the repo root itself
(the package's own directory is on sys.path, not its *parent*, so `import lucidpilot`
has nothing to resolve), so this falls back to loading __init__.py by file path via
importlib, adapted from hermes-chrome-plugin's own tests/test_lifecycle.py loader.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_BROWSER_TOOLS = {
    "my_browser_launch",
    "my_browser_tab",
    "my_browser_snapshot",
    "my_browser_find",
    "my_browser_inspect",
    "my_browser_navigate",
    "my_browser_evaluate",
    "my_browser_click",
    "my_browser_type",
    "my_browser_fill",
    "my_browser_key",
    "my_browser_wait_for",
    "my_browser_list_console_messages",
    "my_browser_list_network_requests",
    "my_browser_get_network_request",
    "my_browser_screenshot",
    "my_browser_hover",
    "my_browser_drag",
    "my_browser_tap",
    "my_browser_scroll",
    "my_browser_upload_file",
}
EXPECTED_INDICATOR_TOOLS = {
    "indicator_show",
    "indicator_hide",
    "indicator_move",
    "indicator_click",
    "indicator_type",
    "indicator_scroll",
}
EXPECTED_TOOLS = EXPECTED_BROWSER_TOOLS | EXPECTED_INDICATOR_TOOLS


def _purge(package_name):
    """Drop the package AND its submodules from sys.modules.

    Popping only the parent is not enough: register() imports `.auth` lazily,
    and a stale `lucidpilot.auth` left in sys.modules makes that import
    short-circuit without re-binding `auth` onto the freshly-imported parent,
    so the second test to use the fixture sees no `plugin.auth`. Only bites
    when the checkout directory is importable as `lucidpilot` (CI), not under
    the path-loader fallback below.
    """
    for name in [
        n for n in sys.modules if n == package_name or n.startswith(package_name + ".")
    ]:
        sys.modules.pop(name, None)


def load_plugin_module():
    """Load this repo's __init__.py, package import first, path-loader fallback."""
    try:
        _purge("lucidpilot")
        return importlib.import_module("lucidpilot")
    except ModuleNotFoundError:
        pass

    package_name = "lucidpilot_under_test"
    _purge(package_name)
    spec = importlib.util.spec_from_file_location(
        package_name,
        REPO_ROOT / "__init__.py",
        submodule_search_locations=[str(REPO_ROOT)],
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeContext:
    """Minimal ctx: records register_tool/register_hook/register_command calls."""

    def __init__(self) -> None:
        self.tools: list[dict] = []
        self.hooks: list[tuple[str, object]] = []
        self.commands: list[dict] = []

    def register_tool(self, name, toolset, schema, handler, emoji=None, check_fn=None, **kw):
        self.tools.append(
            {
                "name": name,
                "toolset": toolset,
                "schema": schema,
                "handler": handler,
                "emoji": emoji,
                "check_fn": check_fn,
            }
        )

    def register_hook(self, event, fn):
        self.hooks.append((event, fn))

    def register_command(self, name, handler=None, description=None, args_hint=None, **kw):
        self.commands.append({"name": name, "handler": handler})


@pytest.fixture
def registered_ctx():
    """register(ctx) with control_tools forced to "always".

    Default mode is "auto", which skips my_browser_* registration whenever
    ~/.hermes/plugins/hermes-chrome-plugin exists on disk (see
    _other_chrome_plugin_installed in __init__.py) - true on this dev machine.
    Forcing "always" via the env var (which _control_tools_mode reads before
    ever consulting that heuristic) makes the 27-tool assertion below
    independent of what else happens to be installed locally.
    """
    plugin = load_plugin_module()
    ctx = FakeContext()
    with mock.patch.dict(os.environ, {"LUCIDPILOT_CONTROL_TOOLS": "always"}):
        plugin.register(ctx)
    return plugin, ctx


def test_registers_exactly_27_tools(registered_ctx):
    _plugin, ctx = registered_ctx
    assert len(ctx.tools) == 27


def test_tool_names_match_expected_lp_and_indicator_sets(registered_ctx):
    _plugin, ctx = registered_ctx
    names = [t["name"] for t in ctx.tools]

    # no duplicate registrations under one name
    assert len(names) == len(set(names))

    actual = set(names)
    assert actual == EXPECTED_TOOLS
    assert actual & EXPECTED_BROWSER_TOOLS == EXPECTED_BROWSER_TOOLS
    assert actual & EXPECTED_INDICATOR_TOOLS == EXPECTED_INDICATOR_TOOLS


def test_pre_llm_call_hook_registered(registered_ctx):
    _plugin, ctx = registered_ctx
    hook_names = [name for name, _fn in ctx.hooks]
    assert "pre_llm_call" in hook_names


def test_control_primer_scopes_its_claim_over_other_browser_tools(registered_ctx):
    """The primer is how my_browser_* wins the tool-selection coin flip in a session
    that also has chrome_*/mcp__chrome*/Playwright loaded - it must say so.
    It must ALSO say when not to: a blanket "always use my_browser_*" sends the model
    down the slow path on tasks a plain fetch does better, which loses more
    than the precedence wins. mcp_server.SERVER_INSTRUCTIONS carries the same
    two halves for Claude Code; keep them in step."""
    plugin, _ctx = registered_ctx
    primer = plugin._CONTROL_PRIMER
    assert "ahead of any other browser tool" in primer
    assert "signed in to" in primer
    assert "not for every URL" in primer
    assert "research question" in primer


def test_auto_mode_skips_browser_tools_when_other_plugin_dir_present():
    """The actual default: LUCIDPILOT_CONTROL_TOOLS unset (mode "auto"), on a
    machine where ~/.hermes/plugins/hermes-chrome-plugin really exists.

    registered_ctx above always forces mode="always" so its 27-tool count is
    independent of what's installed locally; nothing before this test actually
    exercised the default "auto" branch against a real hermes-chrome-plugin
    directory. Skips (rather than fakes the directory) if this machine ever
    stops having that install, since _other_chrome_plugin_installed is a
    disk-existence heuristic, not something this test should mock around.
    """
    plugin = load_plugin_module()
    if not plugin._other_chrome_plugin_installed():
        pytest.skip("hermes-chrome-plugin not installed on this machine")

    ctx = FakeContext()
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("LUCIDPILOT_CONTROL_TOOLS", None)
        assert plugin._control_tools_mode() == "auto"
        plugin.register(ctx)

    names = {t["name"] for t in ctx.tools}
    assert names == EXPECTED_INDICATOR_TOOLS, "auto mode should skip all 21 my_browser_* tools here"
    assert ctx.commands == [], "no /lp command should register when my_browser_* tools are skipped"


def test_auto_mode_claims_the_slot_when_the_other_plugin_is_disabled():
    """Standing aside is for a plugin that is actually REGISTERING tools. A
    hermes-chrome-plugin that is installed but disabled contributes no
    chrome_* tools, so deferring to it left the user with no browser control
    at all - both plugins holding the door for each other."""
    plugin = load_plugin_module()
    if not os.path.isdir(plugin._OTHER_PLUGIN_DIR):
        pytest.skip("hermes-chrome-plugin not installed on this machine")

    # hermes_cli only exists inside a Hermes install, so stand in a fake
    # module rather than importing one that isn't there under pytest.
    def fake_hermes_config(enabled):
        pkg = types.ModuleType("hermes_cli")
        cfg = types.ModuleType("hermes_cli.config")
        cfg.load_config = lambda: {"plugins": {"enabled": enabled}}
        pkg.config = cfg
        return {"hermes_cli": pkg, "hermes_cli.config": cfg}

    with mock.patch.dict(sys.modules, fake_hermes_config(["minimax"])):
        assert plugin._other_chrome_plugin_installed() is False
    with mock.patch.dict(sys.modules, fake_hermes_config(["hermes-chrome-plugin"])):
        assert plugin._other_chrome_plugin_installed() is True
    # Config unreadable: fail safe by assuming it is active (stand aside).
    broken = types.ModuleType("hermes_cli.config")
    def _boom():
        raise RuntimeError("no config here")
    broken.load_config = _boom
    pkg = types.ModuleType("hermes_cli"); pkg.config = broken
    with mock.patch.dict(sys.modules, {"hermes_cli": pkg, "hermes_cli.config": broken}):
        assert plugin._other_chrome_plugin_installed() is True


def test_every_lp_tool_is_auth_and_license_gated_via_check_fn(registered_ctx):
    """chrome_tools.py wires check_fn to require BOTH auth.is_authorized() AND
    licensing.is_pro_licensed() on every my_browser_* registration (the visibility-layer
    gate: control tools need Chrome control granted AND a valid subscription);
    indicator_* tools are licence-gated only - painting an overlay isn't driving
    the browser, so it must not need the Chrome-control grant."""
    plugin, ctx = registered_ctx
    by_name = {t["name"]: t for t in ctx.tools}

    for name in EXPECTED_BROWSER_TOOLS:
        check_fn = by_name[name]["check_fn"]
        assert check_fn is not None, f"{name} missing check_fn gate"
        assert callable(check_fn)

    # Forced, never ambient: this machine may hold a real licence and a real
    # persisted Chrome-control grant, and an assertion that only passes on an
    # unlicensed laptop is not testing the gate.
    probe_all = [by_name[name]["check_fn"] for name in EXPECTED_BROWSER_TOOLS]
    with mock.patch.object(plugin.auth.ChromeAuth, "is_authorized", return_value=False), \
         mock.patch.object(plugin.chrome_tools, "is_pro_licensed", return_value=False):
        for check_fn in probe_all:
            assert check_fn() is False

    probe = by_name["my_browser_snapshot"]["check_fn"]

    # Authorized but unlicensed: still gated off, both must hold.
    with mock.patch.object(plugin.auth.ChromeAuth, "is_authorized", return_value=True), \
         mock.patch.object(plugin.chrome_tools, "is_pro_licensed", return_value=False):
        assert probe() is False

    # Licensed but not authorized: still gated off.
    with mock.patch.object(plugin.auth.ChromeAuth, "is_authorized", return_value=False), \
         mock.patch.object(plugin.chrome_tools, "is_pro_licensed", return_value=True):
        assert probe() is False

    # Both hold: gate opens.
    with mock.patch.object(plugin.auth.ChromeAuth, "is_authorized", return_value=True), \
         mock.patch.object(plugin.chrome_tools, "is_pro_licensed", return_value=True):
        assert probe() is True

    # indicator_*: licence-gated, NOT auth-gated. Both states are forced
    # explicitly - the developer machine running this may itself hold a real
    # activated licence, so asserting on ambient state would be a coin flip.
    for name in EXPECTED_INDICATOR_TOOLS:
        check_fn = by_name[name]["check_fn"]
        assert check_fn is not None, f"{name} missing licence gate"
        assert callable(check_fn)

    indicator_probe = by_name["indicator_click"]["check_fn"]
    with mock.patch.object(plugin.indicator_tools, "is_pro_licensed", return_value=False):
        assert indicator_probe() is False, "unlicensed must hide the overlay tools"
    with mock.patch.object(plugin.auth.ChromeAuth, "is_authorized", return_value=False), \
         mock.patch.object(plugin.indicator_tools, "is_pro_licensed", return_value=True):
        assert indicator_probe() is True, "overlay must not require the Chrome-control grant"


def test_missing_cryptography_no_longer_matters():
    """INVERTED from the original drill: licensing.py stopped verifying keys
    locally (the extension does that now), so the `cryptography` dependency is
    gone and a machine without it must get the FULL tool surface - the old
    degrade-to-nothing path would mean the dependency quietly came back.

    Blocks the real import via a sys.meta_path finder, same mechanism the
    original test used to prove the degrade, now proving the independence.
    """
    import importlib.abc
    import importlib.machinery

    class _BlockCryptography(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path, target=None):
            if fullname == "cryptography" or fullname.startswith("cryptography."):
                raise ImportError(f"blocked for test: {fullname}")
            return None

    for name in list(sys.modules):
        if name == "cryptography" or name.startswith("cryptography."):
            sys.modules.pop(name)
    for name in list(sys.modules):
        if name == "licensing" or name.endswith(".licensing"):
            sys.modules.pop(name)

    blocker = _BlockCryptography()
    sys.meta_path.insert(0, blocker)
    try:
        plugin = load_plugin_module()
        ctx = FakeContext()
        with mock.patch.dict(os.environ, {"LUCIDPILOT_CONTROL_TOOLS": "always"}):
            plugin.register(ctx)  # must not raise
    finally:
        sys.meta_path.remove(blocker)

    # Full surface, no degrade: the licence stack is stdlib-only now.
    assert {t["name"] for t in ctx.tools} == EXPECTED_TOOLS
    assert [c["name"] for c in ctx.commands] == ["lp"]
