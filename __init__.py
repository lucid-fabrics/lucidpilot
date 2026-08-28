"""LucidPilot plugin for Hermes: my_browser_* browser control + indicator_* visibility overlay.

Two independent tool sets share this one plugin:
  * my_browser_* (chrome_tools.py, 21 tools) - drive the user's real, signed-in Chrome
    profile through LucidPilot's own companion extension + bridge.py (loopback
    HTTP, port 16329 by default). Locked by default, gated per-tool by
    check_fn=auth.is_authorized, unlocked automatically by licence
    activation in the extension popup (/lp revoke re-locks). This is a
    Python-side fork of hermes-chrome-plugin's own chrome_* tools, renamed to
    my_browser_* so both plugins can be installed side by side with zero tool-name or
    (after the /lp rename in commands.py) command-name collisions.
  * indicator_* (indicator_tools.py, 6 tools) - cosmetic border/cursor/toast in
    the user's real Chrome. Licence-gated (check_fn=licensing.is_pro_licensed)
    but NOT auth-gated: painting an overlay isn't driving the browser, so it
    doesn't need the Chrome-control grant my_browser_* requires. See indicator_tools.py's
    module docstring for why targetId is optional and its guard never raises.

LucidPilot has no free tier: without an active licence neither tool set
registers, and the extension itself paints nothing (see chrome-extension/
src/license.ts).

control_tools config knob ("auto" | "always" | "never", default "auto"; set
via LUCIDPILOT_CONTROL_TOOLS env var or a `lucidpilot: control_tools:` section
in ~/.hermes/config.yaml, same shape as hermes-chrome-plugin's own
`hermes_chrome_plugin: authorize:`): my_browser_* duplicates hermes-chrome-plugin's
chrome_* tools almost tool-for-tool, so running both plugins in one Hermes
session would double up the agent's browser-control tool list for no benefit.
"auto" skips registering my_browser_* (and the /lp command) when hermes-chrome-plugin
also looks installed; indicator_* still registers regardless, it's cosmetic
and has nothing to conflict with (it remains licence-gated either way).

Detecting "installed" (see _other_chrome_plugin_installed): the PluginContext
handed to register(ctx) exposes register_tool/register_hook/register_command
and a handful of provider-registration methods, nothing that lists sibling
plugins (confirmed against chrome_tools.py/commands.py's own ctx usage, and
against hermes_cli.plugins.PluginContext directly). The host's PluginManager
does have a list_plugins() with exactly what "auto" wants, but PluginContext
only reaches it through a leading-underscore ``_manager`` attribute:
undocumented, not part of the surface any plugin in this codebase (or
hermes-chrome-plugin's own source) relies on, and one hermes_cli refactor away
from silently breaking. So this falls back to the heuristic the task called
out as acceptable: does hermes-chrome-plugin's plugin directory exist on
disk. That answers "is it installed", not "is it enabled and actually loaded
this session" (a user could have it installed but denylisted via config.yaml's
plugins.disabled) - good enough for "avoid visual clutter", not leaned on for
anything security-sensitive.

Module-name note: the plugin directory isn't guaranteed to be a valid Python
package name (Claude Code installs under a version-numbered leaf dir, e.g.
`.../lucidpilot/1.0.0/`), so intra-plugin imports stay relative. They're
deferred to inside register()
rather than sitting at module level: relative imports need the file loaded as
a package member either way, but keeping them local lets this file's two pure
helpers below run standalone (`python3 __init__.py`) without chrome_tools.py/
bridge.py etc. needing to be importable as a real package.
"""

from __future__ import annotations

import os
import sys

_OTHER_PLUGIN_DIR = os.path.expanduser("~/.hermes/plugins/hermes-chrome-plugin")

_INDICATOR_PRIMER = """\
<lucidpilot-indicator>
The user's Chrome shows a border, mouse cursor, and toast whenever indicator_* tools fire, so they can see what you're doing on a visible tab.

my_browser_* tools already paint this automatically through LucidPilot's own extension, so skip indicator_* entirely while driving Chrome via my_browser_*.

Call indicator_* only when driving a visible tab through some OTHER Chrome surface that doesn't paint its own overlay, e.g. hermes-chrome-plugin's chrome_* tools (a separate companion extension) or chrome-devtools-mcp's mcp__chrome__* tools. In that case, whatever tool performs the real action:
1. Before a real click, call indicator_click(x, y) with the same coordinates first (add targetId too if you have one, from my_browser_tab/chrome_tab's action='list').
2. Before a real type/fill, call indicator_type(x, y) first.
3. Before a real scroll, call indicator_scroll(direction) first.
4. indicator_show is optional (any indicator_click/type/scroll activates it automatically); call indicator_hide when the task is done.

targetId is optional: pass a Chrome tab id if you have one (from my_browser_tab/chrome_tab's action='list', or equivalent) and it fires through LucidPilot's own bridge automatically. Omit it if you don't have a compatible one (e.g. chrome-devtools-mcp uses a separate sandboxed Chrome with its own, incompatible tab-id numbering): the tool then returns the exact JavaScript to run instead, run it via whichever Chrome evaluate tool you have, then continue.

These are purely cosmetic and independent of the real action; never let one block, delay, or fail the real action. Skip this entirely for background/hidden tabs since there's no one to see it.
</lucidpilot-indicator>"""

_CONTROL_PRIMER = """\
<lucidpilot>
Browser control is available through the my_browser_* tools via LucidPilot's own companion Chrome extension running in the user's normal, signed-in Chrome profile (real cookies/sessions; no remote-debug port, no throwaway profile).

When to reach for my_browser_* first, ahead of any other browser tool (chrome_*, mcp__chrome*, Playwright, plain HTTP fetch): anything that needs THE USER'S OWN browser - a site they are signed in to, their cookies or session, a tab they already have open, or an action they should be able to watch happen. This includes localhost/local dev URLs (e.g. "visit http://localhost:4300") - a dev server only exists on the user's machine, so previewing it is squarely their browser, not a fetch target. Those tools drive a different browser (or none), so on a logged-in site they land on a sign-in wall while my_browser_* is already through it.

Most web work is NOT a browser task, and my_browser_* is the wrong reflex for it. A research question - "how do people do X", "what's the best way to Y", anything answerable from public pages - belongs to the web search/extract tools; they read many sources in the time one browser drives to one. Fetching a single public page's text is likewise cheaper without a browser, and scraping something that must not touch the user's session belongs in a sandboxed browser. Reach for my_browser_* when the task needs THEIR browser, not for every URL.

Usage rules:
1. my_browser_snapshot before clicking/typing; prefer the stable `uid` over `selector`.
2. Pass includeSnapshot=true on my_browser_click/my_browser_type/my_browser_fill/my_browser_key to verify state in one round trip.
3. my_browser_* run in the background by default; pass background=false (or /lp background off) when the user wants to watch.
4. If a my_browser_* tool reports browser control is locked, ask the user to activate (or deactivate and re-activate) their licence in the extension popup; the agent cannot unlock it itself.
5. Run /lp doctor when in doubt about connectivity.

my_browser_* actions paint the AI Session Indicator overlay (border/cursor/toast) automatically as part of LucidPilot's own extension; no separate indicator_* call is needed for them.
</lucidpilot>"""

# Injected only when the Mac helper is actually connected - priming the model
# about tools it cannot see would just invite failed calls (same gating logic
# as _CONTROL_PRIMER's auth check). Kept in step with the my_app_* paragraph
# of mcp_server.SERVER_INSTRUCTIONS.
_APP_PRIMER = """\
<lucidpilot-mac>
The LucidPilot for Mac helper is connected: my_app_* tools drive native macOS apps (Mail, Xcode, Finder, Notes, Terminal, ...) the same visible way my_browser_* drives Chrome - frame, second cursor, toast.

Choosing between the families: anything that lives in a browser - including a web app in an app-shaped window - is my_browser_*. Native Mac apps are my_app_*. "Open the invoice page" is the browser; "attach it to a new Mail draft" is the app.

my_app_* only works on apps the user has allowlisted in the helper's menu bar UI. An app marked "NOT granted" in my_app_list, or a consent error, means the USER must allow it there - the agent cannot grant it; ask, then retry.

Usage rules:
1. Start with my_app_list, then my_app_snapshot for element uids; act by uid.
2. Prefer my_app_fill for text (no keyboard, works on background apps, immune to secure input) and my_app_menu for app commands (Save, Export, ...) - both work without focusing the app.
3. The user's mouse entering the controlled window pauses control; Esc stops it. Errors say so - report them, don't retry blindly.
</lucidpilot-mac>"""


def _control_tools_mode() -> str:
    """Read the control_tools knob: "auto" (default) | "always" | "never".

    Env var wins over config.yaml, mirroring the HERMES_CHROME_AUTHORIZE /
    hermes_chrome_plugin.authorize precedence hermes-chrome-plugin's own
    __init__.py uses for its standing-authorization grant. An unset or
    unrecognized value falls back to "auto".
    """
    mode = (os.environ.get("LUCIDPILOT_CONTROL_TOOLS") or "").strip().lower()
    if not mode:
        try:
            from hermes_cli.config import load_config

            cfg = load_config() or {}
            section = cfg.get("lucidpilot")
            if isinstance(section, dict):
                mode = str(section.get("control_tools") or "").strip().lower()
        except Exception:
            mode = ""
    return mode if mode in ("auto", "always", "never") else "auto"


def _other_chrome_plugin_installed() -> bool:
    """Best-effort: is hermes-chrome-plugin also ACTIVE on this machine.

    Disk existence plus config enablement, see the module docstring for why
    there is no live-registry check available through PluginContext. Used
    solely by control_tools="auto" to skip a redundant set of
    browser-control tools.

    Enablement matters, not just the directory: Hermes plugins are opt-in via
    `plugins.enabled`, so a disabled hermes-chrome-plugin registers no
    chrome_* tools and there is nothing to collide with. Checking disk alone
    meant that disabling it left the user with NO browser control in auto
    mode - each plugin politely standing aside for the other.
    """
    if not os.path.isdir(_OTHER_PLUGIN_DIR):
        return False
    try:
        from hermes_cli.config import load_config

        plugins = (load_config() or {}).get("plugins")
        if isinstance(plugins, dict) and isinstance(plugins.get("enabled"), list):
            return "hermes-chrome-plugin" in plugins["enabled"]
    except Exception:
        pass
    # Config unreadable or shaped differently than expected: assume it is
    # active, the same fail-safe as before (skip rather than double up).
    return True


def register(ctx) -> None:
    mode = _control_tools_mode()
    register_control = mode == "always" or (mode == "auto" and not _other_chrome_plugin_installed())

    auth = None
    bridge = None
    registered = False
    try:
        import atexit

        from . import licensing, redirect_policy
        from .app_tools import register_all_tools as _register_app_tools
        from .auth import ChromeAuth, command_hint
        from .bridge import ChromeProfileBridge
        from .chrome_tools import register_all_tools as _register_browser_tools
        from .commands import register_all_commands
        from .indicator_tools import register_all_tools as _register_indicator_tools
    except ImportError as exc:
        # Everything here is stdlib-only since licensing.py stopped verifying
        # keys locally (the `cryptography` dependency went with it), so this
        # only fires on a genuinely broken install. Degrade quietly rather
        # than letting the exception escape register(), which would make the
        # host treat the whole plugin load as failed. print() (not a raised
        # error) because this runs during plugin load, before any
        # logging/context is wired up.
        print(
            f"[lucidpilot] tools unavailable ({exc}) - "
            "reinstall LucidPilot, then restart your agent.",
            file=sys.stderr,
        )
    else:
        bridge = None
        if register_control:
            auth = ChromeAuth()
            # auth wired in at construction so GET /status can report auth state
            # (locked/authorized) alongside connection/license state - see
            # ChromeProfileBridge.auth's own comment in bridge.py for why this is
            # a plain attribute (duck-typed) rather than a ChromeAuth import.
            bridge = ChromeProfileBridge(auth=auth)

        # Cosmetic overlay: licence-gated (inside indicator_tools) but not
        # auth-gated, and not subject to the control_tools knob - it has no
        # hermes-chrome-plugin counterpart to collide with. Shares the
        # session's bridge when one exists so indicator_* rides the in-memory
        # queue instead of constructing a second bridge (EADDRINUSE -> HTTP
        # round-trip through our own server).
        _register_indicator_tools(ctx, bridge=bridge)
        registered = True

        if register_control:
            _register_browser_tools(ctx, bridge, auth)
            # my_app_* rides the same control_tools knob as my_browser_* (so
            # control_tools=never hides BOTH families): auth and bridge are
            # only constructed in this block, and there is no rival native
            # app-control family for "auto" to de-duplicate against anyway.
            _register_app_tools(ctx, bridge, auth)
            register_all_commands(ctx, bridge, auth)

            # Cleanup: stop the bridge when the owning Python process exits. Not
            # tied to on_session_end, which Hermes fires after every conversation
            # turn, so one chat session could stop another session's active bridge.
            atexit.register(bridge.stop)

            # Bind now (same reason as mcp_server: the popup polls /status the
            # moment it opens), then hand any pre-popup-era key to the
            # extension (one-shot, backgrounded, no-op when nothing to do).
            try:
                bridge.ensure_started()
            except OSError:
                pass
            bridge.start_legacy_key_migration()

    # Primer: inject usage guidance once per session (first turn). pre_llm_call
    # return {"context": ...} is appended to the user message (ephemeral;
    # preserves the system-prompt cache). Skipped entirely when nothing
    # registered (missing dependency) - priming the model about tools it cannot
    # see would just invite failed calls. The control-tools section is added
    # only once my_browser_* is both registered and actually unlocked, same as
    # hermes-chrome-plugin's own primer gating.
    def _inject_primer(is_first_turn: bool = False, **_kw):
        if not is_first_turn or not registered:
            return None
        parts = [_INDICATOR_PRIMER]
        if auth is not None and auth.is_authorized():
            parts.append(_CONTROL_PRIMER)
            try:
                if licensing.helper_state()["helperConnected"]:
                    parts.append(_APP_PRIMER)
            except Exception:
                pass  # a broken status probe must not break the turn
        return {"context": "\n\n".join(parts)}

    ctx.register_hook("pre_llm_call", _inject_primer)

    # Redirect: hermes-chrome-plugin's chrome_* tools duplicate my_browser_*
    # almost tool-for-tool (see this module's docstring), so when both are
    # actually registered together - only under control_tools="always", since
    # "auto" already avoids the double-registration below - a chrome_* call
    # is denied in favor of the my_browser_* equivalent, but only when
    # my_browser_* would actually work right now (licensed, authorized,
    # extension connected). Same gate condition as pretooluse_hook.py's
    # Claude Code side, just checked in-process instead of over HTTP.
    if bridge is not None and auth is not None:

        def _redirect_rival_tool(tool_name: str = "", **_kw):
            if tool_name not in redirect_policy.REDIRECT_TOOLS_HERMES:
                return None
            if not redirect_policy.is_enabled():
                return None
            if not (licensing.is_pro_licensed() and auth.is_authorized() and bridge.connected):
                return None
            return {
                "action": "block",
                "message": redirect_policy.block_message(tool_name, command_hint()),
            }

        ctx.register_hook("pre_tool_call", _redirect_rival_tool)


if __name__ == "__main__":
    # ponytail: runnable self-check for the only non-trivial branching logic
    # in this file (mode resolution + the disk heuristic). Doesn't exercise
    # register() itself, that needs a real Hermes ctx and package context.
    import unittest.mock as mock

    assert _control_tools_mode() in ("auto", "always", "never")
    with mock.patch.dict(os.environ, {"LUCIDPILOT_CONTROL_TOOLS": "always"}):
        assert _control_tools_mode() == "always"
    with mock.patch.dict(os.environ, {"LUCIDPILOT_CONTROL_TOOLS": "never"}):
        assert _control_tools_mode() == "never"
    with mock.patch.dict(os.environ, {"LUCIDPILOT_CONTROL_TOOLS": "bogus"}):
        assert _control_tools_mode() == "auto"  # invalid value falls back to default

    assert isinstance(_other_chrome_plugin_installed(), bool)

    print("__init__.py self-check OK:", _control_tools_mode(), _other_chrome_plugin_installed())
