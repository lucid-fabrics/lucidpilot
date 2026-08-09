"""indicator_* tools: fire the AI Session Indicator extension's DOM events.

Purely visual (border/cursor/highlight/toast in the user's real Chrome), but
NOT free: LucidPilot has no free tier. Every handler calls
``licensing.require_pro_licensed()`` and every tool is registered with
``check_fn=licensing.is_pro_licensed``, so an unlicensed install sees no
indicator_* tools at all. Note the gate is licence-only, deliberately without
``auth.is_authorized()``: painting an overlay is not driving the browser, so it
must not require the Chrome-control grant that my_browser_* does.

Primary path: when targetId is supplied (a Chrome tab id, e.g. from
my_browser_tab(action='list')), fires directly through this project's own bridge.py
(LucidPilot's loopback connector) via the "overlay.fire" bridge action, one
tool call, nothing else to do. "overlay.fire" carries a known event name plus
a small validated detail object (no arbitrary JS), never a hand-built
expression string: chrome-extension/glue.js validates both strictly before
touching a tab and relays them to content.ts as a real CustomEvent, and
bridge.py license-gates it like every other action. Note my_browser_* actions already
paint this overlay automatically via LucidPilot's own Chrome extension, so
indicator_* is redundant (harmless, but unnecessary) while driving through
my_browser_*; see the fallback case below for its real use.

Fallback path: Hermes sessions don't all drive Chrome through LucidPilot,
some use hermes-chrome-plugin's own chrome_* tools (a separate companion
extension), chrome-devtools-mcp (mcp__chrome__* tools, a separate sandboxed
Chrome with its own, incompatible tab-id numbering), or other browser tools
entirely, none of which paint an overlay of their own. Without a compatible
targetId there is no bridge this plugin can call on its own, so targetId is
optional: if it's omitted, the tool returns the exact JavaScript to run
instead of a bare error, and the agent fires it via whichever Chrome evaluate
tool it's actually using (chrome_evaluate, mcp__chrome__evaluate, etc.), then
continues with the real action. Either way this plugin never blocks or
fails the real action, it's cosmetic only.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .licensing import is_pro_licensed, require_pro_licensed


def _bridge():
    """Import and start this project's own connector bridge, or raise a clear error."""
    from .bridge import ChromeProfileBridge, DEFAULT_TIMEOUT_MS  # may raise ImportError
    b = ChromeProfileBridge()
    b.ensure_started()
    return b, DEFAULT_TIMEOUT_MS


def _with_agent(detail: dict) -> dict:
    # Resolved per call, not captured at import: bridge.AGENT is set by whichever
    # host loaded the package (mcp_server -> "claude", Hermes -> "hermes").
    from .bridge import AGENT

    return {**detail, "agent": AGENT}


def _js(event: str, detail: dict) -> str:
    """Only used as a manual-run fallback (see _fire below) for a caller with
    NO my_browser_*-compatible targetId at all - a different Chrome automation tool
    entirely (chrome_evaluate, mcp__chrome__evaluate, ...), never something
    this project's own code executes. The real, bridge-driven path below no
    longer builds or sends a JS string; see _fire's "overlay.fire" call."""
    d = _with_agent(detail)
    return f"document.dispatchEvent(new CustomEvent({json.dumps(event)},{{detail:{json.dumps(d)}}}))"


def _fire(target_id: int | None, event: str, detail: dict) -> str:
    # Runtime gate (the check_fn on registration is only a visibility hint -
    # a host that ignores it, or a stale tool list, still lands here). Raises
    # LicenseRequiredError, which _guard turns into a clear string.
    require_pro_licensed()
    if target_id is None:
        js = _js(event, detail)
        return (
            "No targetId given (no my_browser_*-compatible tab id available in this "
            "session). Run this exact JavaScript yourself via "
            "whichever Chrome evaluate tool you're actually using right now "
            f"(chrome_evaluate, mcp__chrome__evaluate, or equivalent), then "
            f"continue with the real action:\n{js}"
        )
    try:
        b, timeout_ms = _bridge()
        # "overlay.fire", not "page.evaluate": a known event name + a small
        # validated detail object, never an arbitrary JS expression string.
        # glue.js validates both strictly and never license-gates this one
        # action - see bridge.py's _require_command_licensed.
        b.send(
            "overlay.fire",
            {"targetId": target_id, "event": event, "detail": _with_agent(detail)},
            timeout_ms,
        )
    except Exception as e:  # bridge unreachable/not installed, bad target_id, etc.
        js = _js(event, detail)
        return (
            f"Could not fire via the bridge ({type(e).__name__}: {e}). Run this "
            f"exact JavaScript yourself via whichever Chrome evaluate tool "
            f"you're actually using, then continue with the real action:\n{js}"
        )
    return f"{event} fired on tab {target_id}"


def _guard(fn: Callable[[dict], str]) -> Callable[..., str]:
    # Never raise out of a tool handler: these are purely cosmetic, nothing
    # here may block or fail the real action that follows.
    def wrapper(args: dict | None = None, **_kw: Any) -> str:
        try:
            return fn(args or {})
        except Exception as exc:  # noqa: BLE001
            return (
                f"indicator tool skipped ({type(exc).__name__}: {exc}). "
                "Purely cosmetic, continue with the real action."
            )
    return wrapper


def register_all_tools(ctx, **_kw) -> None:
    def _licensed() -> bool:
        # Resolved at call time (module global), not captured as a direct
        # reference - same shape as chrome_tools._authorized_and_licensed, and
        # what lets a host (or a test) see the current licence state rather
        # than whatever was bound at registration.
        return is_pro_licensed()

    target_prop = {
        "targetId": {
            "type": "integer",
            "description": (
                "Optional. Chrome tab id, e.g. from my_browser_tab(action='list') "
                "or chrome_tab(action='list'). Omit if you don't have a "
                "compatible one (e.g. driving Chrome via chrome-devtools-mcp's "
                "mcp__chrome__*, a separate sandboxed Chrome with its own tab "
                "ids): the tool then returns the JS to run yourself instead "
                "of firing it directly."
            ),
        }
    }
    xy_props = {
        **target_prop,
        "x": {"type": "integer", "description": "Viewport CSS pixel x (e.g. element.getBoundingClientRect() center)."},
        "y": {"type": "integer", "description": "Viewport CSS pixel y."},
    }

    def add(name: str, description: str, properties: dict, handler: Callable[[dict], str], *, required: list) -> None:
        # description= is part of the real hermes_cli register_tool signature
        # (default ""); forwarded so non-Hermes hosts (the MCP server) get it.
        # check_fn is licence-only (no auth): the overlay is not browser
        # control, so it must not need the Chrome-control grant my_browser_* requires.
        ctx.register_tool(
            name=name,
            toolset="lucidpilot",
            schema={"type": "object", "properties": properties, "required": required},
            handler=_guard(handler),
            check_fn=_licensed,
            description=description,
            emoji="👁️",
        )

    def _xy(args: dict) -> tuple[int, int] | str:
        """Returns (x, y) or a clear error string, never raises. The schema
        marks x/y required but nothing enforces that before the handler
        runs, a model that omits them must get a real message, not a bare
        KeyError with no indication of what was actually wrong."""
        x, y = args.get("x"), args.get("y")
        if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
            return f"indicator tool needs numeric x and y, got x={x!r} y={y!r}. Purely cosmetic, continue with the real action."
        return int(x), int(y)

    def h_show(args: dict) -> str:
        return _fire(args.get("targetId"), "__claude-indicator-show", {})

    def h_hide(args: dict) -> str:
        return _fire(args.get("targetId"), "__claude-indicator-hide", {})

    def h_move(args: dict) -> str:
        xy = _xy(args)
        if isinstance(xy, str):
            return xy
        return _fire(args.get("targetId"), "__claude-cursor-move", {"x": xy[0], "y": xy[1]})

    def h_click(args: dict) -> str:
        xy = _xy(args)
        if isinstance(xy, str):
            return xy
        return _fire(args.get("targetId"), "__claude-cursor-click", {"x": xy[0], "y": xy[1]})

    def h_type(args: dict) -> str:
        xy = _xy(args)
        if isinstance(xy, str):
            return xy
        return _fire(args.get("targetId"), "__claude-cursor-type", {"x": xy[0], "y": xy[1]})

    def h_scroll(args: dict) -> str:
        direction = args.get("direction", "down")
        return _fire(args.get("targetId"), "__claude-cursor-scroll", {"direction": direction})

    add(
        "indicator_show",
        "Turn on the AI Session Indicator (border) in the user's Chrome. Call once "
        "at the start of a visible browsing task; any indicator_click/type/scroll "
        "call also turns it on automatically, so this is optional. targetId is "
        "optional too, see its description.",
        target_prop,
        h_show,
        required=[],
    )
    add(
        "indicator_hide",
        "Turn off the AI Session Indicator across every open tab.",
        target_prop,
        h_hide,
        required=[],
    )
    add(
        "indicator_move",
        "Glide the indicator's cursor to (x, y) without a click. Rarely needed "
        "on its own; indicator_click/type already move the cursor.",
        xy_props,
        h_move,
        required=["x", "y"],
    )
    add(
        "indicator_click",
        "Show a mouse-like click at (x, y): cursor glides there, presses, "
        "ripples, highlights the target element, and toasts 'Click'. Call this "
        "immediately before every real click on a visible tab, whatever tool "
        "performs that real click.",
        xy_props,
        h_click,
        required=["x", "y"],
    )
    add(
        "indicator_type",
        "Show the cursor landing on (x, y) and toast 'Type'. Call before every "
        "real type/fill action on a visible tab.",
        xy_props,
        h_type,
        required=["x", "y"],
    )
    add(
        "indicator_scroll",
        "Toast a scroll direction ('up'|'down'|'left'|'right'). Call before "
        "every real scroll action on a visible tab.",
        {**target_prop, "direction": {"type": "string", "enum": ["up", "down", "left", "right"]}},
        h_scroll,
        required=["direction"],
    )
