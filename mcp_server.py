#!/usr/bin/env python3
"""MCP stdio server: LucidPilot's tools for Claude Code (and any MCP host).

Bridges the exact same Python modules the Hermes plugin loads - nothing is
forked. A tiny collector object stands in for Hermes's PluginContext (the
plugin only ever uses register_tool/register_command/register_hook), the
existing ``register_all_tools`` calls populate it, and this file speaks
newline-delimited JSON-RPC 2.0 over stdio (the MCP stdio transport - one JSON
object per line, NOT LSP Content-Length framing).

Tool surface:
  - 6  indicator_* (licence-gated; cosmetic overlay, no auth needed)
  - 21 my_browser_*        (unless LUCIDPILOT_CONTROL_TOOLS=never; per-call gated on
                    auth + Pro license exactly as in Hermes)
  - lucidpilot_command     (/lp status|doctor|onboard|background|license|help)
  - my_browser_authorize   (/lp authorize|revoke ONLY - kept as a separate tool so a
                    user who always-allows lucidpilot_command for /lp status never
                    silently allowlists self-authorization; the host's
                    per-tool permission prompt is the human gate that replaces
                    "typing /lp authorize IS the human action" in Hermes)

The Hermes-side "auto" heuristic (skip my_browser_* when ~/.hermes/plugins/
hermes-chrome-plugin exists) is deliberately NOT applied here: that dir marks
a *Hermes* plugin which can never load into this host's session, so honoring
it would hide my_browser_* from anyone who runs both hosts. Only "never" skips.

stdout is reserved for JSON-RPC; all diagnostics go to stderr. The imported
modules are stdout-clean by construction (no module-level prints; bridge.py
silences its HTTP server's log_message).
"""

from __future__ import annotations

import atexit
import importlib
import importlib.util
import json
import os
import sys
import threading
from typing import Any, Callable

_DIR = os.path.dirname(os.path.abspath(__file__))

# The repo modules use relative imports and the install dir may be hyphenated
# (not a valid identifier), so load __init__.py by path under a fixed package
# name - same loader the pytest suite uses (tests/python/test_plugin_registration.py).
_PKG = "lucidpilot_mcp_host"


def _log(msg: str) -> None:
    print(f"[lucidpilot-mcp] {msg}", file=sys.stderr, flush=True)


def _read_version() -> str:
    try:
        with open(os.path.join(_DIR, "VERSION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "0.0.0-dev"


def _load_package() -> None:
    if _PKG in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        _PKG,
        os.path.join(_DIR, "__init__.py"),
        submodule_search_locations=[_DIR],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load LucidPilot package from {_DIR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_PKG] = module
    # Executes __init__.py's module level only; register() is never called here
    # (it is Hermes's entry point and prints to stdout on a missing dependency,
    # which would corrupt the JSON-RPC stream).
    spec.loader.exec_module(module)


class ToolCollector:
    """Stands in for Hermes's PluginContext; records tools instead of serving them."""

    def __init__(self) -> None:
        self.tools: dict[str, dict] = {}
        self.lp_handler: Callable[[str], str] | None = None

    def register_tool(self, name, toolset, schema, handler, check_fn=None, description="", emoji=None, **kw) -> None:
        self.tools[name] = {
            "description": description or "",
            "schema": schema,
            "handler": handler,
            "check_fn": check_fn,
        }

    def visible_tools(self) -> dict[str, dict]:
        """Tools this host should advertise right now.

        check_fn is Hermes's visibility hint, re-evaluated per tool listing -
        so an unlicensed (or locked) session advertises nothing rather than
        offering tools whose every call would be refused. A raising check_fn
        is treated as "hide": it can only mean the gate can't be evaluated.
        """
        visible = {}
        for name, tool in self.tools.items():
            check = tool.get("check_fn")
            if check is None:
                visible[name] = tool
                continue
            try:
                if check():
                    visible[name] = tool
            except Exception:  # noqa: BLE001 - an unevaluatable gate stays shut
                continue
        return visible

    def register_command(self, name, handler=None, description=None, args_hint=None, **kw) -> None:
        if name == "lp":
            self.lp_handler = handler

    def register_hook(self, event, fn) -> None:
        # MCP has no per-call hook, so a Hermes pre_llm_call primer cannot be
        # replayed on every turn. The one-shot equivalent is `instructions` on
        # the initialize result (see SERVER_INSTRUCTIONS) - the client feeds it
        # to the model once per session. Tool descriptions and /lp carry the
        # rest.
        pass


# Sent once, on initialize, as MCP's `instructions` - the closest thing this
# protocol has to Hermes's pre_llm_call primer (__init__.py's _CONTROL_PRIMER,
# kept deliberately in step with this text). It exists because tool
# descriptions alone lose the ONE decision that matters when a session also
# has chrome-devtools-mcp or a Playwright server loaded: which browser the
# user actually meant. Deliberately scoped rather than a blanket "always use
# my_browser_*" - overclaiming would push the model into slower work on tasks a plain
# fetch handles better, and that costs more trust than it wins.
SERVER_INSTRUCTIONS = """\
LucidPilot drives the user's OWN Chrome - their normal, signed-in profile, real cookies and sessions, the windows they already have open - through a companion extension over a loopback bridge.

Reach for my_browser_* first, ahead of any other browser tool, whenever the task needs that specific browser: a site the user is signed in to, their session or cookies, a tab they already have open, or an action they should be able to watch happen (my_browser_* paints a border, cursor and toast in the real window as it works). Other browser tools drive a different browser or none at all, so on a logged-in site they land on a sign-in wall that my_browser_* is already past.

Most web work is NOT a browser task, and my_browser_* is the wrong reflex for it. A research question - "how do people do X", "what's the best way to Y", anything answerable from public pages - belongs to the web search/fetch tools; they read many sources in the time one browser drives to one. Reading a single public page is likewise cheaper without a browser, and anything that must not touch the user's session belongs in a sandboxed browser. Reach for my_browser_* when the task needs THEIR browser, not for every link.

Browser control is locked until the user runs /lp authorize - the agent cannot authorize itself. If the my_browser_* tools are missing entirely, the licence or the extension is the reason; /lp doctor says which."""


_ARGS_ONLY_SCHEMA = {
    "type": "object",
    "properties": {
        "args": {
            "type": "string",
            "description": "Raw argument string, exactly as the user typed it after the subcommand.",
        }
    },
    "required": [],
}


def build_collector() -> ToolCollector:
    _load_package()
    collector = ToolCollector()

    mode = (os.environ.get("LUCIDPILOT_CONTROL_TOOLS") or "").strip().lower()

    try:
        licensing = importlib.import_module(f"{_PKG}.licensing")
        indicator_tools = importlib.import_module(f"{_PKG}.indicator_tools")
        auth_mod = importlib.import_module(f"{_PKG}.auth")
        bridge_mod = importlib.import_module(f"{_PKG}.bridge")
        chrome_tools = importlib.import_module(f"{_PKG}.chrome_tools")
        commands = importlib.import_module(f"{_PKG}.commands")
    except ImportError as exc:
        # Everything here is stdlib-only since licensing.py stopped verifying
        # keys (the `cryptography` dependency went with it), so this guard is
        # now only against a genuinely broken install - degrade to a stub /lp
        # that names the error instead of the whole server dying.
        _log(f"tools unavailable ({exc}); serving the /lp stub only")

        def h_stub(args: dict | None = None, **_kw: Any) -> str:
            return (
                f"LucidPilot failed to load its modules ({exc}). "
                "Reinstall LucidPilot, then restart Claude Code."
            )

        collector.tools["lucidpilot_command"] = {
            "description": "Run a /lp subcommand (currently unavailable - missing dependency; call to see the fix).",
            "schema": _ARGS_ONLY_SCHEMA,
            "handler": h_stub,
        }
        return collector

    # This host is Claude Code, not Hermes. Drives the overlay's toast/log
    # label, its accent colour, and the Chrome tab group name - all of which
    # said "Hermes" from any host before this, since that was the only host
    # when those strings were written.
    bridge_mod.set_agent("claude")

    indicator_tools.register_all_tools(collector)

    auth = auth_mod.ChromeAuth()
    bridge = bridge_mod.ChromeProfileBridge(auth=auth)
    # LUCIDPILOT_CONTROL_TOOLS=never skips the 21 duplicate CONTROL tools only.
    # /lp still registers either way: it is how a user runs `/lp doctor` and
    # `/lp status`, and losing those to a de-duplication knob would leave an
    # unlicensed "never" session with no way to even diagnose why.
    if mode != "never":
        chrome_tools.register_all_tools(collector, bridge, auth)
    commands.register_all_commands(collector, bridge, auth)
    atexit.register(bridge.stop)
    # Licence activation now happens in the extension popup, with no
    # tools/call in flight - the per-call visibility diff in serve() never
    # runs, so without this push the new my_browser_* tools would stay invisible
    # until the next call. The bridge fires this (from its assertion-handler
    # thread) when an incoming report flips the licensed verdict; _write
    # is lock-guarded for exactly this cross-thread case. Invalidate the
    # client-mode memo first or the flip is invisible for a couple more
    # seconds and the notification would announce an unchanged list.
    #
    # Registered BEFORE ensure_started, not after: the extension asserts the
    # moment the port answers, so a callback registered after the bind can
    # miss the very flip that licenses the session - the notification is
    # then never emitted at all (caught by CI, where the gap was wide enough
    # to lose it every run).
    def _licence_flipped() -> None:
        licensing.invalidate_status_cache()
        _write({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})

    bridge.on_license_change(_licence_flipped)

    # Bind port 16329 now instead of on the first send(). The popup's health
    # panel polls /status the moment it opens, so a lazy bridge reported
    # "Can't reach the LucidPilot bridge" for every user who checked the popup
    # before running a command. Failure here is never fatal: EADDRINUSE just
    # means another session owns the port (we become its client), and anything
    # else still gets raised properly on the first real send().
    try:
        bridge.ensure_started()
    except OSError:
        pass
    # Pre-popup-era installs keep their key in ~/.hermes/lucidpilot; hand it
    # to the extension once (background thread; no-op in client mode or when
    # there is nothing to migrate).
    bridge.start_legacy_key_migration()

    lp = collector.lp_handler
    assert lp is not None, "commands.register_all_commands did not register /lp"

    def h_lucidpilot_command(args: dict | None = None, **_kw: Any) -> str:
        raw = ((args or {}).get("args") or "").strip()
        tokens = raw.split()
        if tokens and tokens[0].lower() in ("authorize", "revoke"):
            return (
                "Authorization changes go through the my_browser_authorize tool, and only "
                "when the user explicitly asked for them (e.g. typed /lp authorize)."
            )
        return lp(raw)

    def h_my_browser_authorize(args: dict | None = None, **_kw: Any) -> str:
        raw = ((args or {}).get("args") or "").strip()
        tokens = raw.split()
        first = tokens[0].lower() if tokens else ""
        if first == "revoke":
            return lp("revoke")
        if first == "authorize":
            raw = " ".join(tokens[1:])
        return lp(f"authorize {raw}".strip())

    collector.tools["lucidpilot_command"] = {
        "description": (
            "Run a /lp subcommand: status | doctor | onboard | background [on|off|toggle|status] | "
            "license | help. Returns the command's exact output; relay it verbatim."
        ),
        "schema": _ARGS_ONLY_SCHEMA,
        "handler": h_lucidpilot_command,
    }
    collector.tools["my_browser_authorize"] = {
        "description": (
            "Unlock (or 'revoke' to re-lock) LucidPilot's Chrome control for this session. "
            "Accepts a duration: 15m | 30m | <minutes> | indefinite, or 'revoke'. "
            "ONLY call this when the user explicitly asked - typed /lp authorize, /lp revoke, "
            "or requested it in plain words. NEVER call it on your own initiative, and never "
            "to un-stick a locked my_browser_* tool: ask the user to authorize instead."
        ),
        "schema": _ARGS_ONLY_SCHEMA,
        "handler": h_my_browser_authorize,
    }
    return collector


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 over stdio
# ---------------------------------------------------------------------------

# stdout carries the protocol and is written from two threads: the stdin loop
# in serve() and the bridge's /next handler via the licence-change callback
# (build_collector). One lock keeps frames from interleaving.
_write_lock = threading.Lock()


def _write(msg: dict) -> None:
    with _write_lock:
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()


def _result(req_id: Any, result: dict) -> None:
    _write({"jsonrpc": "2.0", "id": req_id, "result": result})


def _error(req_id: Any, code: int, message: str) -> None:
    _write({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def serve(collector: ToolCollector) -> None:
    version = _read_version()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            _error(None, -32700, "Parse error")
            continue

        method = req.get("method")
        req_id = req.get("id")
        if req_id is None:
            continue  # notification (notifications/initialized etc.) - nothing to answer

        if method == "initialize":
            params = req.get("params") or {}
            _result(req_id, {
                "protocolVersion": params.get("protocolVersion") or "2025-06-18",
                # listChanged: this server's tool list is a live thing (see the
                # tools/call branch below) - authorizing, revoking or activating
                # a licence changes what is visible, and the client only re-lists
                # if we told it we can announce that.
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "lucidpilot", "version": version},
                "instructions": SERVER_INSTRUCTIONS,
            })
        elif method == "ping":
            _result(req_id, {})
        elif method == "tools/list":
            # Re-evaluated per listing, not cached at startup: activating a
            # licence mid-session makes the tools appear on the next listing.
            _result(req_id, {
                "tools": [
                    {"name": name, "description": tool["description"], "inputSchema": tool["schema"]}
                    for name, tool in collector.visible_tools().items()
                ]
            })
        elif method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            tool = collector.tools.get(name)
            if tool is None:
                _error(req_id, -32602, f"Unknown tool: {name}")
                continue
            # tools/list is re-evaluated per listing, but a client that never
            # re-lists still shows the startup set: /lp authorize would report
            # success while every my_browser_* tool stayed invisible until the session
            # was restarted (hit for real while driving Chrome from Claude
            # Code). Diffing visibility around EVERY call catches authorize,
            # revoke and `license <key>` alike, instead of hooking each handler.
            before = set(collector.visible_tools())
            try:
                # Handlers are _guard-wrapped upstream and shouldn't raise;
                # belt and braces so one bad call can't kill the server.
                out = tool["handler"](params.get("arguments") or {})
                is_error = False
            except Exception as exc:  # noqa: BLE001
                out = f"[lucidpilot] {type(exc).__name__}: {exc}"
                is_error = True
            _result(req_id, {"content": [{"type": "text", "text": str(out)}], "isError": is_error})
            if set(collector.visible_tools()) != before:
                _write({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        else:
            _error(req_id, -32601, f"Method not found: {method}")


def main() -> None:
    try:
        collector = build_collector()
    except Exception as exc:  # noqa: BLE001 - a broken install must still answer initialize
        _log(f"fatal during setup: {type(exc).__name__}: {exc}")
        raise
    _log(f"serving {len(collector.tools)} tools")
    serve(collector)  # returns on stdin EOF (host closed the pipe); atexit stops the bridge


if __name__ == "__main__":
    main()
