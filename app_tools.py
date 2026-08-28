"""The 14 my_app_* tools: native macOS app control through the LucidPilot for
Mac menu bar helper.

Structural sibling of ``chrome_tools.py`` on purpose (same ``_err`` / ``_clean``
/ ``_wire`` / ``_send`` / ``_guard`` / ``register_all_tools(ctx, bridge, auth)``
shape, no shared base class - two files with the same shape are cheaper to
read than one file with a strategy parameter). The wire actions are ``app.*``,
which bridge.py routes ONLY to a poller that authenticated as the Mac helper;
everything the model learned about uids and snapshots on the browser side
transfers because the helper returns page.snapshot-shaped payloads and the
same formatters render them.

Handlers are sync (``handler(args, **kw) -> str``) and registered with a
``check_fn`` that requires auth + licence (the same two gates as
my_browser_*) AND a connected helper - on Linux/Windows, or on a Mac without
the helper running, the tools simply stay out of the agent's context. No
platform branching anywhere.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable

from . import bridge as bridge_module
from .auth import ChromeAuth, ChromeAuthError
from .bridge import ChromeProfileBridge, BridgeError, DEFAULT_TIMEOUT_MS
from .formatters import (
    MAX_ELEMENTS,
    decode_data_url,
    format_chrome_snapshot,
    safe_json,
    truncate_text,
)
from .licensing import (
    LicenseRequiredError,
    helper_state,
    is_pro_licensed,
    require_pro_licensed,
)

# Mutating verbs get the long budget, not DEFAULT_TIMEOUT_MS: the helper
# pauses for the user's first-use consent prompt on an unallowlisted app, and
# 30s would kill the command while the human is still reading the dialog.
# Matches chrome_tools._CLICK_TIMEOUT_MS for the same reason (confirm gates).
_MUTATE_TIMEOUT_MS = 200_000

# Prepended to the description of every entry-point tool (see add()). The
# my_browser_* prefix says "the user's own signed-in browser"; this one says
# the corresponding thing for the native side, at the exact moment the model
# chooses between the two families.
_REAL_MAC_PREFIX = "[native macOS apps on the user's own Mac - only apps the user has allowlisted in the LucidPilot helper, driven visibly with a second cursor]"

_SNAPSHOT_MODES = ["auto", "interactive", "text", "full"]
_MENU_ACTIONS = ["list", "invoke"]
_IMAGE_FORMATS = ["png", "jpeg"]
_CLICK_BUTTONS = ["left", "right"]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _err(msg: str) -> str:
    if msg.startswith("[lucidpilot"):
        return msg
    return f"[lucidpilot] {msg}"


def _app_target_props() -> dict:
    return {
        "bundleId": {"type": "string", "description": "Target app bundle id, e.g. 'com.apple.mail'. Prefer this."},
        "pid": {"type": "number", "description": "Target process id, if two copies of one app are running."},
        "windowId": {"type": "string", "description": "Window id from my_app_list, to target one specific window."},
        "windowTitleIncludes": {"type": "string", "description": "Target the window whose title contains this substring."},
    }


def _bg_prop() -> dict:
    return {
        "background": {
            "type": "boolean",
            "description": "If true (default), drive the app without raising it - accessibility actions work on background apps. False activates the app so the user can watch. Synthetic keystrokes into a background app may be dropped; prefer my_app_fill for text, or background=false.",
        }
    }


def _clean(args: dict) -> dict:
    """Drop None values so omitted optionals don't reach the wire as nulls."""
    return {k: v for k, v in (args or {}).items() if v is not None}


def _wire(bridge: ChromeProfileBridge, args: dict, *, background_aware: bool = True) -> dict:
    """Build wire params: cleaned args + foreground flag (from background or
    session default - the existing /lp background toggle governs both tool
    families)."""
    params = _clean(args)
    if background_aware:
        background = params.pop("background", None)
        if background is None:
            background = bridge.background_default
        params["foreground"] = not background
    return params


def _send(auth: ChromeAuth, bridge: ChromeProfileBridge, action: str, params: dict, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Any:
    # Every my_app_* handler funnels through here, so this is the one place
    # both runtime gates need to live (root cause, not one guard per handler).
    # Helper liveness is NOT re-checked here: bridge._send_local fail-fasts
    # with the helper-specific wording when no helper polls.
    auth.require_authorized()
    require_pro_licensed()
    # agent drives the overlay accent/label; sessionId is the helper's
    # per-session app/window affinity key, the exact contract glue.js
    # implements for tabs (see bridge.SESSION_ID).
    params = {**params, "agent": bridge_module.AGENT, "sessionId": bridge_module.SESSION_ID}
    # remotable: same reason as chrome_tools._send - an agent tool call is
    # exactly what an assist session carries, and this process's own internals
    # are not.
    return bridge.send(action, params, timeout_ms, remotable=True)


def _guard(fn: Callable[[dict], str]) -> Callable[..., str]:
    def wrapper(args: dict | None = None, **_kw: Any) -> str:
        try:
            return fn(args or {})
        except ChromeAuthError as exc:
            return _err(str(exc))
        except LicenseRequiredError as exc:
            return _err(str(exc))
        except BridgeError as exc:
            return _err(str(exc))
        except Exception as exc:  # noqa: BLE001 - never raise out of a tool handler
            return _err(f"{type(exc).__name__}: {exc}")
    return wrapper


def _describe_target(args: dict) -> str:
    return (
        args.get("uid")
        or args.get("bundleId")
        or args.get("windowTitleIncludes")
        or (f"{args.get('x')},{args.get('y')}" if args.get("x") is not None else "the target app")
    )


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register_all_tools(ctx, bridge: ChromeProfileBridge, auth: ChromeAuth) -> None:
    def _authorized_licensed_and_helper() -> bool:
        # Visibility layer: my_app_* stays out of the agent's context unless
        # auth + licence are open AND the Mac helper is actually connected.
        # helper_state() is a pure in-memory read in server mode and rides
        # the same memoized /status as the licence reads in client mode -
        # cheap enough for a check_fn evaluated on every tools listing.
        return auth.is_authorized() and is_pro_licensed() and helper_state()["helperConnected"] is True

    def add(
        name: str,
        description: str,
        properties: dict,
        handler: Callable[[dict], str],
        *,
        required: list | None = None,
        emoji: str = "💻",
        entry_point: bool = False,
    ) -> None:
        if entry_point:
            description = f"{_REAL_MAC_PREFIX} {description}"
        ctx.register_tool(
            name=name,
            toolset="lucidpilot",
            schema={"type": "object", "properties": properties, "required": required or []},
            handler=_guard(handler),
            check_fn=_authorized_licensed_and_helper,
            description=description,
            emoji=emoji,
        )

    # -- my_app_list -------------------------------------------------------
    def h_list(args: dict) -> str:
        result = _send(auth, bridge, "app.list", _clean(args))
        apps = result.get("apps") if isinstance(result, dict) else None
        if not isinstance(apps, list):
            return truncate_text(safe_json(result))
        lines = ["name\tbundleId\tpid\tflags"]
        for app in apps:
            if not isinstance(app, dict):
                continue
            flags = []
            if app.get("frontmost"):
                flags.append("frontmost")
            flags.append("granted" if app.get("granted") else "NOT granted")
            lines.append(f"{app.get('name')}\t{app.get('bundleId')}\t{app.get('pid')}\t{','.join(flags)}")
            for win in app.get("windows") or []:
                if not isinstance(win, dict):
                    continue
                state = " (minimized)" if win.get("minimized") else ""
                lines.append(f"  window {win.get('id')}\t{truncate_text(str(win.get('title') or ''), 120)}{state}")
        lines.append(
            "\nApps marked NOT granted cannot be controlled until the user allows them "
            "in the LucidPilot menu bar helper - the agent cannot grant them."
        )
        return "\n".join(lines)

    add(
        "my_app_list",
        "List running Mac apps and their windows: names, bundle ids, pids, window ids/titles, and which apps the user has granted to LucidPilot. The entry point for native app control.",
        {
            "includeWindows": {"type": "boolean", "description": "Include each app's windows (default true)."},
            "all": {"type": "boolean", "description": "Include background/agent processes too (default false: regular apps only)."},
        },
        h_list,
        entry_point=True,
    )

    # -- my_app_activate ---------------------------------------------------
    def h_activate(args: dict) -> str:
        result = _send(auth, bridge, "app.activate", _clean(args))
        activated = isinstance(result, dict) and result.get("activated")
        name = _describe_target(args)
        return f"Activated {name}" if activated else f"Asked macOS to activate {name}; it did not confirm frontmost - retry or check with my_app_list"

    add(
        "my_app_activate",
        "Bring a Mac app (and optionally one window) to the front.",
        {**_app_target_props()},
        h_activate,
    )

    # -- my_app_snapshot ---------------------------------------------------
    def h_snapshot(args: dict) -> str:
        params = _wire(bridge, args)
        params["maxElements"] = args.get("maxElements") or MAX_ELEMENTS
        snapshot = _send(auth, bridge, "app.snapshot", params)
        return format_chrome_snapshot(snapshot)

    add(
        "my_app_snapshot",
        "Inspect a Mac app's window via its accessibility tree. Returns the same element-ref observation as my_browser_snapshot: stable uids, roles, labels, values and rects. mode=text extracts the window's readable text.",
        {
            **_app_target_props(),
            "mode": {"type": "string", "enum": _SNAPSHOT_MODES},
            "query": {"type": "string", "description": "Find/rank elements matching this phrase, e.g. 'send button'."},
            "maxElements": {"type": "number", "description": f"Default {MAX_ELEMENTS}."},
            "containingText": {"type": "string", "description": "Only elements whose label/value contains this string (case-insensitive)."},
            "roleFilter": {"type": "string", "description": "Only elements of this accessibility role, e.g. 'AXButton', 'AXTextField'."},
            "nearUid": {"type": "string", "description": "Sort elements by proximity to this uid."},
            **_bg_prop(),
        },
        h_snapshot,
        entry_point=True,
    )

    # -- my_app_click ------------------------------------------------------
    def h_click(args: dict) -> str:
        result = _send(auth, bridge, "app.click", _wire(bridge, args), _MUTATE_TIMEOUT_MS)
        method = result.get("method") if isinstance(result, dict) else None
        suffix = f" (via {method})" if method else ""
        return f"Clicked {_describe_target(args)}{suffix}"

    add(
        "my_app_click",
        "Click in a Mac app: by uid (from my_app_snapshot; uses the accessibility press action when available, which works on background apps) or window-relative x/y. button=right for context menus, count=2 for double-click.",
        {
            "uid": {"type": "string", "description": "Element uid from my_app_snapshot."},
            "x": {"type": "number", "description": "Window-relative x (points, origin top-left)."},
            "y": {"type": "number", "description": "Window-relative y (points, origin top-left)."},
            "button": {"type": "string", "enum": _CLICK_BUTTONS, "description": "Default left."},
            "count": {"type": "number", "description": "1 (default) or 2 for double-click."},
            "hid": {"type": "boolean", "description": "Use a real hardware-level click (borrows the pointer for an instant, returns it). Needed only for surfaces that drop synthetic clicks; auto-on for iPhone Mirroring. Leave unset otherwise."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_click,
    )

    # -- my_app_type -------------------------------------------------------
    def h_type(args: dict) -> str:
        result = _send(auth, bridge, "app.type", _wire(bridge, args), _MUTATE_TIMEOUT_MS)
        verified = isinstance(result, dict) and result.get("verified")
        note = "" if verified else " (unverified - the app may have dropped background keystrokes; prefer my_app_fill or background=false)"
        return f"Typed {len(args.get('text') or '')} chars{note}"

    add(
        "my_app_type",
        "Type text into a Mac app as keystrokes (layout-independent, emoji-safe). Focuses the uid first when given. Blocked by macOS while secure input (a password field) is active. For plain text fields my_app_fill is more reliable.",
        {
            "text": {"type": "string"},
            "uid": {"type": "string", "description": "Element to focus before typing."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_type,
        required=["text"],
    )

    # -- my_app_fill -------------------------------------------------------
    def h_fill(args: dict) -> str:
        result = _send(auth, bridge, "app.fill", _wire(bridge, args), _MUTATE_TIMEOUT_MS)
        method = result.get("method") if isinstance(result, dict) else None
        suffix = f" via {method}" if method else ""
        return f"Filled {args.get('uid')}{suffix}"

    add(
        "my_app_fill",
        "Set a text field's value directly through the accessibility API - no keyboard, no focus steal, works on background apps and beside secure input. The preferred way to enter text; falls back to select-all + typing when the field rejects direct writes.",
        {
            "uid": {"type": "string", "description": "Text field uid from my_app_snapshot."},
            "text": {"type": "string"},
            "clear": {"type": "boolean", "description": "Replace existing content (default true); false appends."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_fill,
        required=["uid", "text"],
    )

    # -- my_app_key --------------------------------------------------------
    def h_key(args: dict) -> str:
        _send(auth, bridge, "app.key", _wire(bridge, args), _MUTATE_TIMEOUT_MS)
        return f"Pressed {args.get('key')}"

    add(
        "my_app_key",
        "Press a key or shortcut in a Mac app, e.g. 'enter', 'esc', 'cmd+s', 'cmd+shift+p'. For app menu commands my_app_menu is more reliable (it needs no focus at all).",
        {
            "key": {"type": "string", "description": "Key name or combo: modifiers cmd/shift/opt/ctrl joined with '+', e.g. 'cmd+shift+s'."},
            "repeat": {"type": "number", "description": "Press this many times (default 1)."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_key,
        required=["key"],
    )

    # -- my_app_copy / my_app_paste ---------------------------------------
    def h_copy(args: dict) -> str:
        result = _send(auth, bridge, "app.copy", _wire(bridge, args), _MUTATE_TIMEOUT_MS)
        text = result.get("text") if isinstance(result, dict) else None
        if not isinstance(text, str) or not text:
            return "Nothing copied (no selection, or the app exposed no selected text)"
        return truncate_text(text)

    add(
        "my_app_copy",
        "Read the selected text from a Mac app. Uses the accessibility selection when available (no clipboard touched); otherwise sends cmd+c and restores the user's clipboard afterwards. Returns the text.",
        {
            "uid": {"type": "string", "description": "Element whose selection to read (default: the focused element)."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_copy,
    )

    def h_paste(args: dict) -> str:
        _send(auth, bridge, "app.paste", _wire(bridge, args), _MUTATE_TIMEOUT_MS)
        chars = len(args.get("text") or "")
        return f"Pasted {chars} chars" if chars else "Pasted current clipboard contents"

    add(
        "my_app_paste",
        "Paste into a Mac app: writes text to the clipboard, sends cmd+v, then restores the user's previous clipboard. Omit text to paste whatever the clipboard already holds.",
        {
            "text": {"type": "string", "description": "Text to paste. Omitted = paste the current clipboard."},
            "uid": {"type": "string", "description": "Element to focus before pasting."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_paste,
    )

    # -- my_app_scroll -----------------------------------------------------
    def h_scroll(args: dict) -> str:
        _send(auth, bridge, "app.scroll", _wire(bridge, args))
        return f"Scrolled {_describe_target(args)} by {args.get('deltaY') or 0},{args.get('deltaX') or 0}"

    add(
        "my_app_scroll",
        "Scroll inside a Mac app at an element or point. Positive deltaY scrolls down (content moves up), same convention as my_browser_scroll. Auto hardware-level for iPhone Mirroring.",
        {
            "uid": {"type": "string"},
            "x": {"type": "number"},
            "y": {"type": "number"},
            "deltaY": {"type": "number"},
            "deltaX": {"type": "number"},
            "hid": {"type": "boolean", "description": "Real hardware-level scroll (auto-on for iPhone Mirroring)."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_scroll,
    )

    # -- my_app_drag -------------------------------------------------------
    def h_drag(args: dict) -> str:
        result = _send(auth, bridge, "app.drag", _wire(bridge, args), _MUTATE_TIMEOUT_MS)
        method = result.get("method") if isinstance(result, dict) else None
        return f"Dragged {args.get('fromX')},{args.get('fromY')} -> {args.get('toX')},{args.get('toY')}{f' (via {method})' if method else ''}"

    add(
        "my_app_drag",
        "Drag/swipe from one window-relative point to another. On iPhone Mirroring this is a swipe (auto hardware-level); use it to swipe between home screens, pull to refresh, or drag a slider.",
        {
            "fromX": {"type": "number"},
            "fromY": {"type": "number"},
            "toX": {"type": "number"},
            "toY": {"type": "number"},
            "steps": {"type": "number", "description": "Intermediate points along the drag (default 12); more = smoother/slower."},
            "holdMs": {"type": "number", "description": "Press and hold this long before moving (default 0 = a swipe). ~700 picks up an iOS home-screen icon for drag-and-drop into a folder."},
            "releaseHoldMs": {"type": "number", "description": "Hold at the destination before releasing (default 0). ~600 lets a folder merge register when dropping one app on another."},
            "hid": {"type": "boolean", "description": "Real hardware-level drag (auto-on for iPhone Mirroring)."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_drag,
        required=["fromX", "fromY", "toX", "toY"],
    )

    # -- my_app_screenshot -------------------------------------------------
    def h_screenshot(args: dict) -> str:
        fmt = args.get("format") or "png"
        cwd = os.getcwd()
        default_dir = os.path.join(cwd, ".lucidpilot-screenshots")
        stamp = time.strftime("%Y-%m-%dT%H-%M-%S")
        out_path = os.path.abspath(args.get("path")) if args.get("path") else os.path.join(default_dir, f"{stamp}.{fmt}")
        result = _send(auth, bridge, "app.screenshot", _wire(bridge, args))
        data_url = result.get("dataUrl") if isinstance(result, dict) else None
        if not data_url:
            raise BridgeError("Screenshot returned no dataUrl")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as fh:
            fh.write(decode_data_url(data_url))
        return f"Saved app screenshot to {out_path}"

    add(
        "my_app_screenshot",
        "Capture one Mac app window (works even when occluded or on another Space) and save it to disk. Needs the Screen Recording permission granted to the LucidPilot helper.",
        {
            "path": {"type": "string", "description": "Output path. Defaults to .lucidpilot-screenshots/<timestamp>.<format>."},
            "format": {"type": "string", "enum": _IMAGE_FORMATS},
            "maxWidth": {"type": "number", "description": "Downscale to at most this many pixels wide."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_screenshot,
        emoji="📸",
    )

    # -- my_app_wait_for ---------------------------------------------------
    def h_wait_for(args: dict) -> str:
        result = _send(auth, bridge, "app.waitFor", _wire(bridge, args))
        if isinstance(result, dict) and result.get("found"):
            elapsed = result.get("elapsedMs")
            if args.get("gone"):
                return f"Gone after {elapsed}ms"
            uid = result.get("uid")
            label = result.get("label") or result.get("role") or ""
            return f"Found {uid} {label} after {elapsed}ms"
        return truncate_text(safe_json(result))

    add(
        "my_app_wait_for",
        "Wait until an element appears in a Mac app (or disappears, with gone=true) instead of polling with snapshots. The helper polls internally - one round trip - and returns the element's uid the moment it exists, ready for my_app_click.",
        {
            "query": {"type": "string", "description": "Wait for an element whose role or label contains this text (case-insensitive), e.g. 'Save' or 'AXSheet'."},
            "uid": {"type": "string", "description": "Wait on a known uid instead of a query (usually with gone=true, to wait for it to vanish)."},
            "gone": {"type": "boolean", "description": "Invert: succeed when the element is absent (dialog closed, spinner gone)."},
            "timeoutMs": {"type": "number", "description": "Give up after this long (default 10000, capped at 15000)."},
            "intervalMs": {"type": "number", "description": "Poll interval inside the helper (default 250)."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_wait_for,
    )

    # -- my_app_menu -------------------------------------------------------
    def _format_menu_items(items: list, indent: str = "") -> list:
        lines: list = []
        for item in items:
            if not isinstance(item, dict):
                continue
            shortcut = f"  [{item.get('shortcut')}]" if item.get("shortcut") else ""
            disabled = "" if item.get("enabled", True) else "  (disabled)"
            lines.append(f"{indent}{item.get('title')}{shortcut}{disabled}")
            children = item.get("children")
            if isinstance(children, list):
                lines.extend(_format_menu_items(children, indent + "  "))
        return lines

    def h_menu(args: dict) -> str:
        params = _wire(bridge, args)
        params["action"] = args.get("action") or ("invoke" if args.get("path") else "list")
        result = _send(auth, bridge, "app.menu", params, _MUTATE_TIMEOUT_MS)
        if isinstance(result, dict) and isinstance(result.get("clicked"), list):
            shortcut = f" ({result.get('shortcut')})" if result.get("shortcut") else ""
            return f"Invoked menu {' > '.join(result['clicked'])}{shortcut}"
        if isinstance(result, dict) and isinstance(result.get("items"), list):
            return "\n".join(_format_menu_items(result["items"])) or "No menu items found"
        return truncate_text(safe_json(result))

    add(
        "my_app_menu",
        "Read or invoke a Mac app's menu bar commands via accessibility - the most reliable way to trigger app functionality (Save, Export, preferences...). Works without focusing the app. Omit path to list the menus; give path to invoke, e.g. [\"File\", \"Export as PDF...\"].",
        {
            "action": {"type": "string", "enum": _MENU_ACTIONS, "description": "Default: invoke when path is given, else list."},
            "path": {"type": "array", "items": {"type": "string"}, "description": "Menu titles from the top level down to the item to invoke. Matching is case-insensitive and ignores trailing '...'."},
            "depth": {"type": "number", "description": "For list: how many submenu levels to include (default 2)."},
            **_app_target_props(),
            **_bg_prop(),
        },
        h_menu,
        entry_point=True,
    )
