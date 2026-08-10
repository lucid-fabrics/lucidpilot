"""Policy for redirecting rival "your Chrome" tool calls to LucidPilot's own
my_browser_* tools.

Shared by both hosts: pretooluse_hook.py (Claude Code, a bare subprocess) and
__init__.py (Hermes, in-process). Kept free of bridge.py/auth.py/licensing.py
imports on purpose, matching those modules' own avoidance of cross-imports
(auth -> bridge -> licensing already; adding this module to that chain for a
handful of strings and a tool-name set isn't worth it). Callers pass in
whatever they already know about licence/auth state; this module only owns
"which tools" and "is the redirect itself enabled".
"""

from __future__ import annotations

import json
import os
import tempfile

# Exact MCP tool names with a real my_browser_* counterpart. EXACT names, not
# a prefix/regex match on the whole rival server: chrome-devtools's
# take_heapsnapshot, lighthouse_audit, performance_*, emulate, resize_page,
# handle_dialog, and claude-in-chrome's gif_creator, resize_window,
# shortcuts_* have no my_browser_* equivalent - blocking those would strand
# the model with no tool that can finish the task. Anything not in this set
# always falls through to allow.
REDIRECT_TOOLS = frozenset(
    {
        # mcp__claude-in-chrome__*
        "mcp__claude-in-chrome__navigate",
        "mcp__claude-in-chrome__computer",
        "mcp__claude-in-chrome__read_page",
        "mcp__claude-in-chrome__get_page_text",
        "mcp__claude-in-chrome__find",
        "mcp__claude-in-chrome__form_input",
        "mcp__claude-in-chrome__javascript_tool",
        "mcp__claude-in-chrome__read_console_messages",
        "mcp__claude-in-chrome__read_network_requests",
        "mcp__claude-in-chrome__browser_batch",
        "mcp__claude-in-chrome__file_upload",
        "mcp__claude-in-chrome__tabs_create_mcp",
        "mcp__claude-in-chrome__tabs_close_mcp",
        "mcp__claude-in-chrome__tabs_context_mcp",
        # mcp__chrome-devtools__*
        "mcp__chrome-devtools__navigate_page",
        "mcp__chrome-devtools__click",
        "mcp__chrome-devtools__fill",
        "mcp__chrome-devtools__fill_form",
        "mcp__chrome-devtools__hover",
        "mcp__chrome-devtools__drag",
        "mcp__chrome-devtools__take_screenshot",
        "mcp__chrome-devtools__take_snapshot",
        "mcp__chrome-devtools__evaluate_script",
        "mcp__chrome-devtools__press_key",
        "mcp__chrome-devtools__upload_file",
        "mcp__chrome-devtools__wait_for",
        "mcp__chrome-devtools__new_page",
        "mcp__chrome-devtools__close_page",
        "mcp__chrome-devtools__select_page",
        "mcp__chrome-devtools__list_pages",
        "mcp__chrome-devtools__list_console_messages",
        "mcp__chrome-devtools__get_console_message",
        "mcp__chrome-devtools__list_network_requests",
        "mcp__chrome-devtools__get_network_request",
    }
)


# The Hermes-side equivalent: hermes-chrome-plugin's chrome_* tools, which
# chrome_tools.py's own docstring describes as "a Python-side fork...renamed
# to my_browser_*". Unlike REDIRECT_TOOLS above, this is full 1:1 parity (no
# exclusions) since every chrome_* tool has a my_browser_* counterpart by
# construction - confirmed against hermes-chrome-plugin's actual tools.py.
REDIRECT_TOOLS_HERMES = frozenset(
    {
        "chrome_click",
        "chrome_drag",
        "chrome_evaluate",
        "chrome_fill",
        "chrome_find",
        "chrome_get_network_request",
        "chrome_hover",
        "chrome_inspect",
        "chrome_key",
        "chrome_launch",
        "chrome_list_console_messages",
        "chrome_list_network_requests",
        "chrome_navigate",
        "chrome_screenshot",
        "chrome_scroll",
        "chrome_snapshot",
        "chrome_tab",
        "chrome_tap",
        "chrome_type",
        "chrome_upload_file",
        "chrome_wait_for",
    }
)


def block_message(tool_name: str, cmd_prefix: str) -> str:
    """The permissionDecisionReason / pre_tool_call block message.

    One wording for both hosts, since this module is the one place it lives.
    Names the situation rather than a specific my_browser_* tool: the two
    tool sets map close to 1:1 by shape (navigate, click, screenshot, ...),
    so this is a nudge toward the right family, not a lookup table the model
    has to trust blindly.
    """
    return (
        f"{tool_name} drives a different, unauthenticated browser. LucidPilot's "
        "own my_browser_* tools are already set up for this Chrome profile "
        "(the user's real, signed-in browser) - use one of those instead. "
        f"Run `{cmd_prefix} default off` if this session should use other "
        "browser tools instead."
    )


# Separate file from auth.json/license.json on purpose: a preference write
# must never be able to race or interact with a security grant.
_PREFS_DIR = os.path.expanduser(os.environ.get("LUCIDPILOT_LICENSE_DIR", "~/.hermes/lucidpilot"))
_PREFS_FILE = os.path.join(_PREFS_DIR, "prefs.json")


def _read_prefs() -> dict:
    try:
        with open(_PREFS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def is_enabled() -> bool:
    """Default True: a missing or corrupt prefs file means the redirect is
    on. Unlike auth.json's fail-closed default (that gate protects browser
    control), this one is a UX preference - the worst case of defaulting on
    is an extra hint message, not a security grant, so it fails open."""
    return _read_prefs().get("redirect", True) is not False


def set_enabled(value: bool) -> None:
    """Atomic replace, mirroring auth._write_state's shape."""
    state = _read_prefs()
    state["redirect"] = bool(value)
    try:
        os.makedirs(_PREFS_DIR, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=_PREFS_DIR, prefix=".prefs-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, _PREFS_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        # Read-only home, full disk, sandbox: the in-memory choice for this
        # process is lost on exit, same tradeoff auth._write_state makes.
        pass


if __name__ == "__main__":
    # ponytail: runnable self-check for the only branching logic in this file.
    import shutil

    _test_dir = tempfile.mkdtemp(prefix="redirect-policy-selfcheck-")
    _PREFS_DIR = _test_dir
    _PREFS_FILE = os.path.join(_PREFS_DIR, "prefs.json")
    try:
        assert is_enabled() is True  # no file yet -> default on
        set_enabled(False)
        assert is_enabled() is False
        set_enabled(True)
        assert is_enabled() is True
        with open(_PREFS_FILE, "w", encoding="utf-8") as fh:
            fh.write("not json")
        assert is_enabled() is True  # corrupt -> default on
        assert "mcp__claude-in-chrome__navigate" in REDIRECT_TOOLS
        assert "mcp__chrome-devtools__take_heapsnapshot" not in REDIRECT_TOOLS
        assert "chrome_navigate" in REDIRECT_TOOLS_HERMES
        assert len(REDIRECT_TOOLS_HERMES) == 21
        assert block_message("mcp__claude-in-chrome__navigate", "/lp")
        print("redirect_policy.py: self-check ok")
    finally:
        shutil.rmtree(_test_dir, ignore_errors=True)
