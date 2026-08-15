"""Claude Code PreToolUse hook: redirects rival "your Chrome" tool calls to
LucidPilot's own my_browser_* tools when they would actually work.

Registered in .claude-plugin/plugin.json against
mcp__(claude-in-chrome|chrome-devtools)__* tools. Fires as a fresh subprocess
per matched tool call, reads the PreToolUse event on stdin, and either says
nothing (allow, the common case) or prints a deny decision to stdout.

Every step below fails open. A hook that can wedge a session on a bug or a
slow network call is worse than the tool-choice bug it exists to fix, so
anything unexpected (malformed stdin, unreachable bridge, a crash) falls
straight through to "allow" rather than risk blocking a legitimate rival-tool
call the user actually wanted.

Deliberately does not import bridge.py/auth.py/licensing.py: this process is
a hook, not the long-running MCP server, and pulling in that whole module
graph (with its own import-cycle avoidance, see auth.py's docstring) buys
nothing here that a single GET /status doesn't already give it.
"""

from __future__ import annotations

import json
import os
import sys
from urllib import error as urllib_error
from urllib import request as urllib_request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redirect_policy  # noqa: E402

_STATUS_TIMEOUT_S = 1.0
_CMD_PREFIX = "/lucidpilot:lp"  # this hook only ever runs under Claude Code


def _bridge_status() -> dict:
    host = os.environ.get("LUCIDPILOT_BRIDGE_HOST", "127.0.0.1")
    port = os.environ.get("LUCIDPILOT_BRIDGE_PORT", "16329")
    try:
        with urllib_request.urlopen(f"http://{host}:{port}/status", timeout=_STATUS_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode() or "{}")
        return data if isinstance(data, dict) else {}
    except (urllib_error.URLError, ConnectionError, OSError, ValueError):
        return {}


def _decide(event: dict) -> dict | None:
    """None = allow (say nothing). A dict = the deny payload to print."""
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or tool_name not in redirect_policy.REDIRECT_TOOLS:
        return None
    if not redirect_policy.is_enabled():
        return None
    status = _bridge_status()
    # 1.2.0: licence activation is the consent moment for browser control
    # (auth auto-grants via auth.auto_authorize_from_license). The redirect
    # only needs to confirm the LucidPilot pipeline is live: licence valid +
    # extension connected. An explicit /lp revoke still beats this (revoke
    # clears auth AND license cache stays valid, but redirect_policy sees
    # the lock via the auth field - checked below).
    if not (status.get("licensed") is True and status.get("authorized") is True and status.get("extensionConnected") is True):
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": redirect_policy.block_message(tool_name, _CMD_PREFIX),
        }
    }


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
        if not isinstance(event, dict):
            return 0
        decision = _decide(event)
    except BaseException:
        return 0
    if decision is not None:
        print(json.dumps(decision))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
