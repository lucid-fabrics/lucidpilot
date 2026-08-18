"""The ``/lp`` slash command: Python port of the unified command in
``pi-chrome/extensions/chrome-profile-bridge/index.ts`` (originally
``/chrome`` in hermes-chrome-plugin, renamed here to match the my_browser_* tool
namespace so both plugins' commands don't collide when both are installed).

A single command registered as ``lp`` whose handler parses the first token as
a subcommand: ``revoke | status | doctor | onboard | background | default |
license | upgrade``. Handlers return plain strings (the host renders them);
there is no terminal ``ctx.ui.confirm``: in CLI the act of typing the command
is the human action; in web-ui an explicit UI confirm precedes the
programmatic call.

1.2.0 design: there is no ``authorize`` subcommand. Licence activation is the
consent moment for browser control (see auth.auto_authorize_from_license).
``revoke`` stays as the kill switch.
"""

from __future__ import annotations

import os

from .auth import ChromeAuth, command_hint
from .bridge import (
    ChromeProfileBridge,
    BridgeError,
    check_plugin_update,
    suppress_update_notice,
    CHROME_WEB_STORE_URL,
    _compare_versions,
    _current_extension_version,
    _fetch_latest_release,
    extension_load_path,
    extension_version_is_known,
)
from . import licensing
from . import redirect_policy


def _help() -> str:
    """Built per call, not a module constant: the command's own name differs by
    host (see auth.command_hint), and printing the wrong one in the help text
    is exactly how a user ends up typing a command that does not exist."""
    cmd = command_hint()
    return f"""\
{cmd} - control the LucidPilot browser bridge

  {cmd} revoke                                    Lock Chrome control (auto-granted on licence activation; idle-locks after 1h).
  {cmd} status                                    One-line: connection, auth, license, background.
  {cmd} doctor                                    Full health check.
  {cmd} onboard                                   How to install the companion Chrome extension.
  {cmd} background [on|off|toggle|status]         Whether my_browser_* switches Chrome to the tab it drives.
  {cmd} default [on|off|status]                   Whether rival browser tools redirect to my_browser_* when it's ready.
  {cmd} upgrade                                   Update instructions for extension + plugin (re-install via plugin manager).
  {cmd} upgrade dismiss                           Silence the startup update notice for one week.
  {cmd} license                                   Where to activate a licence (the extension popup)."""

_BACKGROUND_DESC = {
    "on": "LucidPilot works quietly; the tab it drives is left where it is.",
    "off": "Chrome switches to the tab LucidPilot is driving so you can watch. It never raises the Chrome window, so your terminal keeps focus either way.",
}

_DEFAULT_DESC = {
    "on": "Rival browser tools (claude-in-chrome, chrome-devtools, hermes-chrome-plugin) are denied in favor of my_browser_* whenever it's licensed, authorized, and connected.",
    "off": "Rival browser tools are left alone; my_browser_* only runs when explicitly called.",
}


def _hostname(url: str) -> str:
    try:
        from urllib.parse import urlparse

        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _status_summary(bridge: ChromeProfileBridge, auth: ChromeAuth) -> str:
    parts = []
    try:
        version = bridge.send("tab.version", {}, 5_000) or {}
        ext_version = version.get("extensionVersion")
        # Only compare when this install actually bundles an extension to
        # compare against - see bridge.extension_version_is_known.
        if ext_version and extension_version_is_known() and ext_version != _current_extension_version():
            parts.append(f"⚠ Companion extension v{ext_version} (LucidPilot expects v{_current_extension_version()}, reload extension)")
        else:
            parts.append("✓ Browser connected")
    except BridgeError:
        # A first-time user hits this before ever installing the extension;
        # the state fields below read as jargon, so lead with the fix the
        # doctor already knows instead of leaving a bare failure.
        parts.append("✗ Browser not responding → run /lp onboard to install the companion extension")
    parts.append(f"auth: {auth.summary()}")
    parts.append(f"license: {licensing.license_status_summary()}")
    parts.append(f"background: {'on' if bridge.background_default else 'off'}")
    parts.append(f"default: {'on' if redirect_policy.is_enabled() else 'off'}")
    return " · ".join(parts)


def _doctor(bridge: ChromeProfileBridge, auth: ChromeAuth) -> str:
    # "LucidPilot v0.0.0-dev" is a lie on a Hermes zip install (the version is
    # simply not knowable there - no bundled extension to read it from), so
    # say that instead of printing a version nobody shipped.
    lines = [f"LucidPilot v{_current_extension_version()}" if extension_version_is_known() else "LucidPilot"]
    status = bridge.status()
    role = "sharing another session's connection" if status.get("mode") == "client" else "running the Chrome connection for this machine"
    lines.append(f"• This session is {role}.")

    # Same auth.is_authorized()/auth.summary() the popup's health panel reads
    # off GET /status (bridge.py's status() calls these through the same
    # ChromeAuth instance) - one source, so doctor and the popup can't
    # disagree about whether Chrome control is currently locked.
    if auth.is_authorized():
        lines.append(f"✓ Browser control: {auth.summary()}.")
    else:
        # 1.2.0: no /lp authorize. The only path to "unlocked" is a fresh
        # licence assertion: activation auto-grants, and after a manual
        # /lp revoke the killswitch clears only on a valid:false ->
        # valid:true round-trip (deactivate + re-activate in the popup).
        lines.append(
            "✗ Browser control is locked. Activate a licence in the extension "
            "popup to auto-grant; after a manual /lp revoke, deactivate and "
            "re-activate the licence there to re-enable."
        )

    if licensing.is_pro_licensed():
        lines.append(f"✓ License: {licensing.license_status_summary()}")
    else:
        # license_status_summary already names the cause (extension silent vs
        # no key activated); only the fix hint differs.
        lines.append(
            f"✗ License: {licensing.license_status_summary()}. "
            f"Enter your key in the LucidPilot extension popup; subscribe at {licensing.PURCHASE_URL} if you don't have one."
        )

    extension_alive = False
    version_mismatch = False
    try:
        import time as _time

        started = _time.time()
        version = bridge.send("tab.version", {}, 35_000) or {}
        latency_ms = round((_time.time() - started) * 1000)
        extension_alive = True
        ext_version = version.get("extensionVersion")
        if ext_version and extension_version_is_known() and ext_version != _current_extension_version():
            version_mismatch = True
            lines += [
                f"✗ The companion extension is on an old version ({ext_version}); this LucidPilot is {_current_extension_version()}.",
                "  Fix: open chrome://extensions and click the refresh icon on the LucidPilot extension.",
            ]
        else:
            lines.append(f"✓ Your browser is connected (companion extension v{ext_version or '?'}, responded in {latency_ms}ms).")
    except BridgeError as exc:
        lines.append(f"✗ Your browser isn't responding: {exc}")
        lines.append("  Fix: run /lp onboard to install the companion extension, then keep that browser window open.")

    if extension_alive and not version_mismatch:
        try:
            value = bridge.send("page.evaluate", {"expression": "1+1", "awaitPromise": True, "foreground": False}, 10_000)
            if value == 2:
                lines.append("✓ LucidPilot can run code in the active tab.")
            else:
                lines.append(f"⚠ LucidPilot ran code but got an unexpected result ({value}). The current tab may be a browser internal page or a strict site.")
        except BridgeError as exc:
            lines.append(f"✗ LucidPilot can't run code in the active tab: {exc}")
        try:
            probe = bridge.send("page.probe", {"foreground": False}, 10_000) or {}
            if probe.get("arithmetic") == 2:
                lines.append(f"✓ The active tab is {_hostname(str(probe.get('location')))} and accepts LucidPilot's commands.")
            if probe.get("webdriver"):
                lines.append("⚠ Your browser is reporting itself as automated to websites. Some sites use this signal to block sign-ins.")
        except BridgeError as exc:
            lines.append(f"⚠ Couldn't inspect the active tab: {exc}")
    elif version_mismatch:
        lines.append("… Skipped the remaining checks until you reload the companion extension.")

    # Version section (last - the rest of doctor is more urgent).
    try:
        latest = check_plugin_update()
        current = _current_extension_version()
        if latest is None:
            lines.append(f"• Plugin version: v{current}.")
        elif _compare_versions(current, latest["version"]) >= 0:
            lines.append(f"✓ Plugin version: v{current} (latest).")
        else:
            lines.append(f"⚠ Plugin version: v{current} → v{latest['version']} available.")
            lines.append("  Fix: run `/lp upgrade`.")
    except Exception:
        pass  # never break /lp doctor on a flaky update check

    return "\n".join(lines)


def _upgrade() -> str:
    """Print upgrade instructions for both the extension and the plugin.

    Extension: user opens the CWS URL and Chrome handles the update in place.
    Plugin: re-install via the plugin manager. Both channels are user-
    controlled; we never auto-install.
    """
    current = _current_extension_version()
    # Fetch the release directly rather than via check_plugin_update: that
    # helper returns None BOTH when you are up to date AND on a network
    # error, so _upgrade could not tell "you're current" from "offline" and
    # wrongly told an up-to-date user the check had failed. A direct fetch
    # disambiguates: None == genuinely unreachable; a dict == compare it.
    if os.environ.get("LUCIDPILOT_NO_UPDATE_CHECK"):
        latest = None
        why = "update checks are disabled (LUCIDPILOT_NO_UPDATE_CHECK is set)"
    else:
        latest = _fetch_latest_release()
        why = "could not reach the update check (offline?)"
    if latest is None:
        return (
            f"Current: v{current}. The {why}, so I can't confirm whether a "
            f"newer version exists. Manual install paths below.\n\n"
            f"Extension (Chrome Web Store):\n  {CHROME_WEB_STORE_URL}\n\n"
            f"Plugin:\n"
            f"  claude plugin install https://github.com/lucid-fabrics/lucidpilot.git\n"
            f"  hermes plugins install https://github.com/lucid-fabrics/lucidpilot.git"
        )
    if _compare_versions(current, latest["version"]) >= 0:
        return f"Already on the latest version (v{current})."

    notes = latest.get("notes") or ""
    notes_block = f"\nRelease notes: {notes}\n" if notes else "\n"
    return (
        f"Update available: v{current} → v{latest['version']}.{notes_block}\n"
        f"Extension (Chrome Web Store - updates in place):\n  {CHROME_WEB_STORE_URL}\n\n"
        f"Plugin (re-install via plugin manager):\n"
        f"  claude plugin install https://github.com/lucid-fabrics/lucidpilot.git\n"
        f"  hermes plugins install https://github.com/lucid-fabrics/lucidpilot.git\n\n"
        f"Release page: {latest.get('url', '')}\n\n"
        f"To silence this notice for a week: /lp upgrade dismiss"
    )


def _upgrade_dismiss() -> str:
    """Suppress the startup one-liner for one week. /lp doctor still shows status."""
    suppress_update_notice(weeks=1)
    return "Update notice suppressed for one week. /lp doctor still reports version status."


def _onboard() -> str:
    ext_path = extension_load_path()
    if ext_path is None:
        return (
            "Install the companion Chrome extension from the Chrome Web Store:\n"
            f"  {CHROME_WEB_STORE_URL}\n"
            "New listings can sit in Google's review queue for a couple of weeks before\n"
            "they go live - if the link 404s or shows 'pending', that's why, not a broken link.\n"
            f"Once installed, keep that browser window open and run {command_hint('doctor')} to confirm."
        )
    return (
        "Install the LucidPilot companion extension in your normal Chrome profile:\n"
        "  1. Open chrome://extensions\n"
        "  2. Turn on 'Developer mode' (top-right).\n"
        "  3. Click 'Load unpacked' and choose this folder:\n"
        f"     {ext_path}\n"
        f"  4. Keep that browser window open, then run {command_hint('doctor')} to confirm."
    )


def _license(key: str) -> str:
    # Kept as a subcommand so old muscle memory gets an explanation, not
    # "unknown command". Keys are never entered here anymore - the extension
    # popup is the single activation point, and it reports the licence back
    # over the bridge on its own.
    if (key or "").strip():
        return (
            "[lucidpilot] Licence keys are no longer entered here. Open the LucidPilot "
            "Chrome extension popup and enter your key there - this session "
            "picks the licence up automatically within seconds. "
            f"Current state: {licensing.license_status_summary()}."
        )
    return (
        "Licences are activated in the LucidPilot Chrome extension popup (click "
        "the extension icon, enter your key). Subscribe at "
        f"{licensing.PURCHASE_URL} if you don't have one. "
        f"Current state: {licensing.license_status_summary()}."
    )


def _background(bridge: ChromeProfileBridge, arg: str) -> str:
    arg = (arg or "").strip().lower()
    current = "on" if bridge.background_default else "off"
    if arg == "status":
        return f"Run in background is {current}. {_BACKGROUND_DESC[current]}"
    if arg in ("on", "true", "1"):
        bridge.background_default = True
    elif arg in ("off", "false", "0"):
        bridge.background_default = False
    elif arg in ("toggle", ""):
        bridge.background_default = not bridge.background_default
    else:
        return f"Unknown background setting '{arg}'. Pick one of: on | off | toggle | status."
    nxt = "on" if bridge.background_default else "off"
    return f"Run in background → {nxt}. {_BACKGROUND_DESC[nxt]}"


def _default(arg: str) -> str:
    arg = (arg or "").strip().lower()
    current = "on" if redirect_policy.is_enabled() else "off"
    if arg == "status":
        return f"Redirect is {current}. {_DEFAULT_DESC[current]}"
    if arg in ("on", "true", "1"):
        redirect_policy.set_enabled(True)
    elif arg in ("off", "false", "0"):
        redirect_policy.set_enabled(False)
    elif arg in ("toggle", ""):
        redirect_policy.set_enabled(not redirect_policy.is_enabled())
    else:
        return f"Unknown default setting '{arg}'. Pick one of: on | off | toggle | status."
    nxt = "on" if redirect_policy.is_enabled() else "off"
    return f"Redirect → {nxt}. {_DEFAULT_DESC[nxt]}"


def register_all_commands(ctx, bridge: ChromeProfileBridge, auth: ChromeAuth) -> None:
    def handler(raw_args: str) -> str:
        tokens = (raw_args or "").strip().split()
        if not tokens or tokens[0] in ("help", "-h", "--help"):
            # Even bare `/lp` (or `/lp help`) re-winds the grant. Project rule
            # (memory: lucidpilot-never-extend): user never manually extends;
            # typing the slash command IS the manual consent moment, so
            # honor it. No-op when nothing is locked, so it's free.
            auth.extend_on_use()
            return _help()
        sub, rest = tokens[0], " ".join(tokens[1:])
        try:
            if sub == "authorize":
                # 1.2.0: removed. Licence activation auto-grants Chrome control
                # (see auth.auto_authorize_from_license); no separate /lp
                # authorize step. Tell the user rather than silently succeed.
                return (
                    "Browser control is granted automatically when a valid "
                    "licence is activated in the extension popup. To lock it "
                    f"manually, use `{command_hint('revoke')}`."
                )
            if sub == "revoke":
                return auth.revoke()
            if sub == "status":
                auth.extend_on_use()
                return _status_summary(bridge, auth)
            if sub == "doctor":
                auth.extend_on_use()
                return _doctor(bridge, auth)
            if sub == "onboard":
                return _onboard()
            if sub == "background":
                auth.extend_on_use()
                return _background(bridge, rest)
            if sub == "default":
                auth.extend_on_use()
                return _default(rest)
            if sub == "license":
                return _license(rest)
            if sub == "upgrade":
                # `upgrade dismiss` -> suppress; bare `upgrade` -> instructions.
                if rest.strip().lower() == "dismiss":
                    return _upgrade_dismiss()
                return _upgrade()
        except Exception as exc:  # noqa: BLE001
            return f"[lucidpilot] {type(exc).__name__}: {exc}"
        return (
            f"Unknown subcommand '{sub}'. Try: {command_hint()} "
            "revoke | status | doctor | onboard | background | default | license | upgrade."
        )

    ctx.register_command(
        "lp",
        handler=handler,
        description="Control the LucidPilot browser bridge (revoke/status/doctor/onboard/background/default/upgrade).",
        args_hint="revoke|status|doctor|onboard|background|default|upgrade",
    )
