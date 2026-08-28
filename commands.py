"""The ``/lp`` slash command: Python port of the unified command in
``pi-chrome/extensions/chrome-profile-bridge/index.ts`` (originally
``/chrome`` in hermes-chrome-plugin, renamed here to match the my_browser_* tool
namespace so both plugins' commands don't collide when both are installed).

A single command registered as ``lp`` whose handler parses the first token as
a subcommand: ``revoke | status | doctor | onboard | background | default |
license | upgrade | share | assist``. Handlers return plain strings (the host
renders them); there is no terminal ``ctx.ui.confirm``: in CLI the act of
typing the command is the human action; in web-ui an explicit UI confirm
precedes the programmatic call.

1.2.0 design: there is no ``authorize`` subcommand. Licence activation is the
consent moment for browser control (see auth.auto_authorize_from_license).
``revoke`` stays as the kill switch.
"""

from __future__ import annotations

import hmac
import os
import threading
import time
from typing import Any, Callable, Optional

from .auth import ChromeAuth, command_hint
from .bridge import (
    ChromeProfileBridge,
    BridgeError,
    check_plugin_update,
    set_remote_sender,
    set_remote_stop,
    suppress_update_notice,
    CHROME_WEB_STORE_URL,
    UNKNOWN_EXTENSION_VERSION,
    _compare_versions,
    _current_extension_version,
    _fetch_latest_release,
    _plugin_version,
    extension_load_path,
    extension_version_is_known,
)
from . import licensing
from . import redirect_policy

# Remote assist ships with the Mac app, NOT with the public plugin. The protocol,
# the scope fence, the crypto and the trust store live in remote*.py, which the
# published snapshot deliberately withholds - so this package has to import and
# work without them.
#
# Optional rather than removed, because the same commands.py runs in both places:
# bundled inside LucidPilot for Mac, where these are present and share/assist
# work, and published as the browser-control plugin, where they are not and the
# two commands say so. A hard import here is what made the published plugin die
# on load with ImportError instead of simply not offering a feature it does not
# carry.
try:
    from . import remote
    from . import remote_trust
    from .remote_scope import ScopePolicy
    REMOTE_ASSIST_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by the packaging tests
    remote = None  # type: ignore[assignment]
    remote_trust = None  # type: ignore[assignment]
    ScopePolicy = None  # type: ignore[assignment,misc]
    REMOTE_ASSIST_AVAILABLE = False


# What to say when somebody asks for a feature this build does not carry. Names
# where it does live rather than reporting a fault, because nothing is broken.
_NO_REMOTE_ASSIST = (
    "Sharing your screen with someone needs LucidPilot for Mac, which carries\n"
    "that part. This is the browser-control plugin on its own.\n"
    "\n"
    "    https://github.com/lucid-fabrics/lucidpilot/releases/latest"
)


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
  {cmd} license                                   Where to activate a licence (the extension popup).
  {cmd} share [--browser|--chrome|--app <bundle id>|--screen] [--video]
                                                Let someone you trust use one Chrome tab, or one Mac app.
                                                Add --video to also let them SEE it.
  {cmd} share y                                   Let them in, once they have typed your code.
  {cmd} share stop                                End the share now.
  {cmd} share trust <name>                        Let the person connected right now come back later.
  {cmd} share trusted                             Who can come back without a code.
  {cmd} share untrust <id|all>                    Take that back, immediately.
  {cmd} share listen [rounds]                     Wait for a trusted helper, no code to read out.
  {cmd} assist <code>                             Help someone who ran {cmd} share.
  {cmd} assist trusted                            Machines that let you back in without a code.
  {cmd} assist machine <name>                     Reconnect to one of them, with no code.
  {cmd} assist stop                               Stop helping; your own browser comes back."""

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
    # Pure in-memory/memoized read - NO extra bridge.send: this function
    # already spends up to 5s on tab.version, and a second live probe would
    # double /lp status latency for everyone, including non-macOS users.
    helper = licensing.helper_state()
    if helper["helperConnected"]:
        info = helper.get("helper") or {}
        ax = "✓" if info.get("tccAccessibility") else "✗"
        screen = "✓" if info.get("tccScreenRecording") else "✗"
        apps = len(info.get("grantedApps") or [])
        parts.append(f"helper: v{info.get('helperVersion') or '?'} · AX {ax} · screen {screen} · {apps} apps")
    else:
        parts.append("helper: not running")
    parts.extend(_share_status())
    return " · ".join(parts)


def _share_status() -> "list[str]":
    """What /lp status says about a live share, or nothing at all.

    Three states rather than two, and the distinction is not pedantry: a share is
    "live" from the moment a code is printed, which is well before anybody has
    claimed it. Calling that live tells somebody a stranger is already in, and
    "someone is in my browser" is the one thing this line must not say wrongly.

    The picture segment is ABSENT when no picture was asked for, rather than
    "off". Off and never-requested look identical to a reader and mean completely
    different things - one of them is a capture that died.

    ponytail: this line is the only channel this feature has for telling somebody
    their capture stopped, because nothing pushes (see _video_note). A person
    with the terminal in another window learns when they next type something.
    """
    if not _share_is_running():
        return []
    if _SHARE.get("session") is None:
        return ["share: waiting for a helper"]
    if _SHARE.get("stop") is None:
        return ["share: waiting for your six digits"]
    parts = ["share: live"]
    if _SHARE.get("video"):
        # The note wins when there is one: it says the picture stopped, which is
        # the whole reason this segment exists.
        note = _SHARE.get("note")
        if note:
            parts.append(f"picture: {note}")
        elif _SHARE.get("capturing"):
            parts.append("picture: on")
        else:
            parts.append("picture: waiting for you to pick what to share")
    return parts


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

    # -- LucidPilot for Mac helper (native app control) --------------------
    helper = licensing.helper_state()
    if helper["helperConnected"]:
        info = helper.get("helper") or {}
        try:
            import time as _time

            started = _time.time()
            bridge.send("app.ping", {}, 5_000)
            latency_ms = round((_time.time() - started) * 1000)
            lines.append(f"✓ LucidPilot for Mac is connected (v{info.get('helperVersion') or '?'}, responded in {latency_ms}ms).")
        except BridgeError as exc:
            # Polling but wedged - the stored status alone cannot catch this.
            lines.append(f"⚠ LucidPilot for Mac is polling but did not answer a ping: {exc}")
        if info.get("tccAccessibility"):
            lines.append("✓ Accessibility permission granted.")
        else:
            lines.append("✗ Accessibility permission not granted - my_app_* cannot read or control apps.")
            lines.append("  Fix: System Settings › Privacy & Security › Accessibility → enable LucidPilot.")
        if info.get("tccScreenRecording"):
            lines.append("✓ Screen Recording permission granted.")
        else:
            lines.append("⚠ Screen Recording not granted - my_app_screenshot and session replay won't work; every other my_app_* tool does.")
        if info.get("secureInputActive"):
            # A genuinely baffling macOS failure with no visible cause - a
            # password field ANYWHERE holds the keyboard system-wide.
            lines.append("⚠ macOS secure input is active (a password field somewhere holds the keyboard) - my_app_type/my_app_key are blocked until it's dismissed.")
        granted = info.get("grantedApps") or []
        if granted:
            lines.append(f"✓ Apps granted to LucidPilot: {', '.join(granted)}.")
        else:
            lines.append("• No apps granted yet - allow apps from the LucidPilot menu bar icon to enable control.")
        # Report-only, never blocking: a signed .app can't hot-reload, and a
        # skew still works - blocking on it would brick the feature on every
        # half-updated install. Skipped when the plugin version is not
        # knowable (Hermes zips without VERSION would nag forever).
        helper_version = info.get("helperVersion")
        expected = _plugin_version()
        if helper_version and expected != UNKNOWN_EXTENSION_VERSION and helper_version != expected:
            lines.append(f"⚠ Helper v{helper_version} vs plugin v{expected} - update the older side when convenient.")
    else:
        lines.append("• LucidPilot for Mac: not running - native app control (my_app_*) is unavailable. Install and launch the helper app to enable it.")

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


# ---------------------------------------------------------------------------
# Remote assist
# ---------------------------------------------------------------------------
#
# Two people on a phone call. One runs `share`, reads out two strings, and
# hands one Chrome tab (or one Mac app) over for a few minutes.
# The other runs `assist` and their agent's my_browser_* calls land on the
# first machine instead of their own.
#
# WHY THIS IS TWO INVOCATIONS PER SIDE and not one blocking call, which is
# what the protocol itself would prefer: a subcommand here returns ONE string
# and cannot prompt. mcp_server.py owns stdout for JSON-RPC (see its module
# docstring) and stdin is the protocol's own reader, so there is no print()
# and no input() available to a handler. remote.share() blocks until a helper
# claims the code, so "print the code, then wait for y" has to be split at the
# only point where the human is doing something anyway: reading strings down a
# phone. The share runs on a background thread and the second invocation is
# the consent moment the plan calls typing y.
#
# The six digits go the strong way round. The requester types in the digits
# their HELPER reads out, and we compare those against ours, so the check is
# an active one rather than two people nodding at their own screens. It also
# means this side never has to display its own short authentication string.

# How long a share may live, counted from the moment the code is minted. It
# lands in ScopePolicy.expiresAt, which check() enforces per command, and
# _share_confirm hands serve() whatever is left of it rather than letting the
# loop start a second half-hour of its own. One clock, one ceiling.
_SHARE_CAP_S = 1800.0

# How long /rc/open may take before we stop waiting for a code to show. It is
# one round trip to Cloudflare; being generous costs a slow share, being mean
# costs a share that failed while it was about to work.
_OPEN_WAIT_S = 30.0

# What the requester's own overlay calls the person driving. It is injected by
# remote_scope.check and never read off the wire (a hostile helper would
# otherwise name itself "Claude"), and a host with no stdin cannot ask a human
# for a nicer name, so it is fixed.
_HELPER_LABEL = "Remote helper"

# The label remote.share prints the pairing code behind. remote.share mints
# nothing itself - /rc/open does, inside the call - and it does not return
# until a helper has claimed, so its announcement is the only place the code
# can be read while a human still needs to say it out loud. Parsing our own
# module's copy is ugly; tests/python/test_commands_remote.py pins the string
# against remote.share's source so a reword there fails a test rather than a
# share, and _code_from falls back to showing the line verbatim regardless.
_CODE_LABEL = "Code "

_SCOPE_HELP = ("Pick one: --browser (the default), --chrome (the whole browser), "
              "--app <bundle id>, or --screen (a whole display).")

# Why --screen is refused rather than offered. remote_scope.check injects a pin
# for browser and app scope and none for screen (remote_scope.py:339-344), so a
# screen-scope command carries no bundleId at all and Session.swift falls back
# to session.target, the last app anything drove on this Mac. On a Mac that has
# driven nothing this session that is nil, and every command comes back "no
# matching app is running, call app.list" while app.list is itself in DENIED, so
# the helper is handed advice they are forbidden to follow. Where an app HAS
# been driven it is worse: the helper silently gets an app the requester never
# named. The pixel fence that would make this scope mean something is plan step
# 10 (SCContentFilter(display:excludingWindows:)) and it is not built.
#
# ponytail: the flag comes back when step 10 lands, and the copy has to say
# plainly that nothing is fenced off, because .cghidEventTap is unscoped by
# construction. Until then a scope nobody can describe truthfully is worse than
# no scope, so this refuses in both commands rather than half-working in one.
# One share and one assist per process, same reasoning as bridge's
# _REMOTE_SENDER: a process is in one session or in none. Rebound rather than
# mutated in place, so a background thread that finishes after a stop writes
# into the dict it captured instead of resurrecting the live one.
_SHARE: "dict[str, Any]" = {}
_ASSIST: "dict[str, Any]" = {}


def _parse_scope(tokens: "list[str]") -> "tuple[str, Optional[str], list[str]]":
    """(kind, bundle id, whatever was not a flag). Raises ValueError with the fix.

    Unknown options are refused rather than ignored: `--sceen` silently
    sharing the whole browser is the failure mode this exists to prevent.
    """
    kind, bundle, rest = "browser", None, []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        flag = token.lower()
        if flag == "--browser":
            kind = "browser"
        elif flag == "--chrome":
            kind = "chrome"
        elif flag == "--screen":
            kind = "screen"
            # An optional display id, the same shape as --app <bundle id>. A
            # picker that knows WHICH screen it drew can name it here, and that
            # is what makes a multi-display whole-screen share possible at all:
            # without an id there is no way to tell which screen a fraction is a
            # fraction of, and it has to be refused.
            if index + 1 < len(tokens) and not tokens[index + 1].startswith("--"):
                index += 1
                bundle = tokens[index]
        elif flag.startswith("--screen="):
            kind, bundle = "screen", token.split("=", 1)[1]
        elif flag == "--app":
            kind = "app"
            index += 1
            if index < len(tokens) and not tokens[index].startswith("--"):
                bundle = tokens[index]
        elif flag.startswith("--app="):
            kind, bundle = "app", token.split("=", 1)[1]
        elif flag.startswith("-"):
            raise ValueError(f"I don't know the option '{token}'. {_SCOPE_HELP}")
        else:
            rest.append(token)
        index += 1
    return kind, bundle, rest


def _plain(text: Any, limit: int = 60) -> str:
    """One bounded line of somebody else's string, safe to put in the block.

    A page title is the least trusted input in this whole flow and it lands in
    the one block a worried person reads top to bottom and reads out loud. A
    title containing newlines can otherwise print a complete fake "Share code"
    and "One-time password" pair above the real one, in the real one's exact
    format, and a long title pushes the real code off the screen. Same shape as
    glue.js's remoteHelperName sanitiser, for the same reason.

    ponytail: this makes the title one bounded line, which is what stops it
    imitating the block's own layout. It cannot stop a title from containing
    something code-shaped inline, which is why the caller quotes it: no cap
    turns an attacker-chosen sentence into a safe one, and the real strings are
    the ones on their own labelled, indented lines.
    """
    collapsed = " ".join(str(text or "").split())
    return collapsed[: limit - 1] + "..." if len(collapsed) > limit else collapsed


def _scope_pin(bridge: ChromeProfileBridge, kind: str, bundle: "Optional[str]") -> "tuple[Any, str]":
    """The thing the helper is pinned to, and how to say it to a human.

    The pin is what remote_scope.check injects on every command, and a browser
    or app scope with no pin refuses everything, so resolving it here is the
    difference between a share and a session that answers nothing. Both scopes
    refuse here, before a code is read out loud: a pin that resolves to nothing
    spends the whole human ceremony and then answers no command at all.

    ponytail: the active tab is the first tab that says it is active, and
    Chrome reports one per window. Whichever window the person is actually
    looking at is not knowable from tab.list, so a two-window user can pin the
    wrong tab; the fix is a lastFocusedWindow flag on tab.list, which is an
    extension change and not this piece.
    """
    if kind == "screen":
        # app.status doubles as the reachability check (a screen share needs the
        # Mac helper for the input) and reports how many screens there are.
        try:
            status = bridge.send("app.status", {}, 10_000) or {}
        except BridgeError:
            raise ValueError(
                "The Mac helper isn't running, so I can't share your screen. Run "
                f"{command_hint('doctor')}; it says how to start it."
            ) from None
        displays = (status.get("displayCount") or 1) if isinstance(status, dict) else 1
        if bundle:
            # A display was named, so which screen a fraction is OF is known.
            # Validated against the ids this Mac actually has: an id that
            # resolves to nothing would fall through to the main display on the
            # far side, which is the wrong-screen bug wearing a different hat.
            known = status.get("displayIds") if isinstance(status, dict) else None
            if isinstance(known, list) and known and str(bundle) not in {str(i) for i in known}:
                raise ValueError(
                    f"This Mac has no screen with id {bundle}. Open the picker again and "
                    "choose from the screens it lists."
                )
            return str(bundle), "the screen you picked"
        if displays > 1:
            # No id, more than one screen: there is no way to tell which one a
            # fraction is a fraction of, so refuse HERE rather than let the pair
            # finish the whole code/password/digits ceremony only for the first
            # click to be refused. See ScreenScope.swift's own refusal, the same
            # decision one layer down.
            raise ValueError(
                "You have more than one screen, and nothing told me which one you'd be sharing, "
                "so I won't set up a whole-screen share that might send clicks to the wrong one.\n"
                "\n"
                "Share from the app's picker, which knows which screen you chose - or share one "
                "thing instead: --browser for a Chrome tab, --chrome for the whole browser, or "
                "--app <bundle id> for a Mac app."
            )
        return None, "your whole screen"
    if kind == "chrome":
        # No tab pin: the helper drives whichever tab is in front and may bring
        # another forward. There is nothing to resolve, but the browser has to
        # be reachable, so a bare tab.list stands in as the reachability check.
        try:
            bridge.send("tab.list", {}, 10_000)
        except BridgeError:
            raise ValueError(
                "I can't reach your browser. Run "
                f"{command_hint('doctor')} and try again once it says your browser is connected."
            ) from None
        return None, "your whole browser"
    if kind == "browser":
        tabs = bridge.send("tab.list", {}, 10_000) or []
        active = next((tab for tab in tabs if isinstance(tab, dict) and tab.get("active")), None)
        if not active or active.get("id") is None:
            raise ValueError(
                "I can't tell which tab you're looking at. Open the page you want help "
                "with, click on it, then run this again."
            )
        # Quoted, because the next thing that happens is a human reading this
        # line out loud and the tab's own title is the one string here that
        # somebody else wrote.
        title = _plain(active.get("title") or active.get("url"))
        return active["id"], f'"{title}"' if title else "the tab you're on"
    if not bundle:
        raise ValueError(
            f"--app needs the app's bundle id, like --app com.apple.Safari. {_SCOPE_HELP}"
        )
    # includeWindows off: this only needs the bundle ids, and walking every
    # app's window tree costs 383ms on a good day (AppList.swift:5-8).
    try:
        listing = bridge.send("app.list", {"includeWindows": False}, 10_000) or {}
    except BridgeError:
        raise ValueError(
            "The Mac helper isn't running, so I can't share an app. Run "
            f"{command_hint('doctor')}; it says how to start it."
        ) from None
    apps = listing.get("apps") if isinstance(listing, dict) else None
    match = next(
        (
            app
            for app in (apps or [])
            if isinstance(app, dict) and str(app.get("bundleId", "")).lower() == bundle.lower()
        ),
        None,
    )
    if match is None:
        raise ValueError(
            f"Nothing running on this Mac calls itself {bundle}. Open the app you want "
            "help with, then run this again, and check the bundle id if you typed it "
            "from memory."
        )
    # The bundle id as the running app spells it, not as it was typed: this
    # string becomes the pin every command is addressed to.
    pin = str(match.get("bundleId"))
    name = _plain(match.get("name"), 40)
    return pin, f"{name} ({pin})" if name and name != pin else pin


def _scope_headline(kind: str) -> str:
    if kind == "chrome":
        return "Sharing your whole browser."
    if kind == "screen":
        return "Sharing your whole screen."
    return "Sharing one Chrome tab." if kind == "browser" else "Sharing one app."


def _scope_copy(kind: str, where: str, video: bool = False) -> str:
    """What the helper can and cannot do, in the scope actually chosen.

    Present tense and specific on both halves. "Read-only where possible" is
    not one of the halves: the session lets the helper click and type, because
    a helper who can only look cannot fix anything, and saying so plainly is
    the whole job of this string.
    """
    if kind == "screen":
        # `where` is interpolated rather than fixed prose, because on a
        # multi-display Mac "which screen" is consent information: a person with
        # three monitors needs the block to say the one they picked, not "your
        # screen" as though there were only one.
        return (
            f"They can move your mouse and type anywhere on {where} - in\n"
            "any app, and in your Mac's own prompts, not just the one you're working\n"
            "in. This is the widest thing you can share: treat it like handing someone\n"
            "your unlocked Mac. Your Mac asks you once more, on screen, before it lets\n"
            "them, and that permission lasts only for this session.\n"
            "\n"
            "You can watch every move, it pauses the moment you touch your mouse or\n"
            "keyboard, and Esc ends it.\n"
            "\n"
            f"{_video_copy(video)}"
        )
    if kind == "chrome":
        return (
            "They can use any tab in your browser, switch between them, and open the\n"
            "pages you already have open. Nothing they send reaches your files or any\n"
            "app outside Chrome - but this is your whole browser, including anything\n"
            "you're signed in to, so share it the way you would hand someone your\n"
            "unlocked laptop for a minute.\n"
            "\n"
            f"{_video_copy(video)}"
        )
    if kind == "browser":
        # The pin lands at the end of its own line on purpose, and _scope_pin
        # has already collapsed and capped it: a long title that wraps
        # mid-sentence is the line a worried person is trying to read.
        return (
            f"They can use one tab, the one showing {where}.\n"
            "They can click, type and follow links in it. Nothing they send reaches\n"
            "your other tabs, your other windows, your files or anything outside that\n"
            "one tab.\n"
            "\n"
            f"{_video_copy(video)}"
        )
    return (
        f"They can use one app: {where}.\n"
        "They can click and type in it. Nothing they send reaches your browser or\n"
        "any other app, and your Mac still asks you, here, before LucidPilot touches\n"
        "an app you haven't already allowed.\n"
        "\n"
        f"{_video_copy(video)}"
    )


def _assist_scope_copy(kind: str) -> str:
    if kind == "screen":
        scope = (
            "Your Mac-app tools now point at THEIR whole screen: your clicks and keys\n"
            "land wherever you aim them on the screen they shared, in any app of theirs.\n"
            "You aim by pointing at the picture, never by coordinates. Their Mac asked\n"
            "them to allow this, they can take over any time by touching their own mouse,\n"
            "and it ends the moment they press Esc.\n"
            "\n"
            "Your own Mac and browser are untouched."
        )
    elif kind == "chrome":
        scope = (
            "Your browser tools now run on THEIR whole browser: any tab, and you can\n"
            "switch between them. You still can't reach their files or any app outside\n"
            "Chrome, and your own browser is untouched.\n"
            "\n"
            "If they start screen sharing you'll see whatever they chose to share.\n"
            "That choice is theirs, not yours."
        )
    elif kind == "browser":
        scope = (
            "Your browser tools now run on one tab of their Chrome, not on yours. You\n"
            "can't reach their other tabs, their other windows or their files, and your\n"
            "own browser is untouched.\n"
            "\n"
            "If they start screen sharing you'll see whatever they chose to share, which\n"
            "may be more than that tab. That choice is theirs, not yours."
        )
    else:
        scope = (
            "Your Mac app tools now run on one app on their Mac, not on yours. You can't\n"
            "reach their browser or any other app.\n"
            "\n"
            "If they start screen sharing you'll see whatever they chose to share, which\n"
            "may be more than that app. That choice is theirs, not yours."
        )
    # The tab is not a button they press, at either end, and both ends surprise
    # people the first time. Nothing opens when this command returns: the tab
    # appears when the OTHER machine answers Chrome's picker, because that is
    # what puts an offer on the channel. And it closes on assist stop, because a
    # live view of somebody else's screen left open after "I'm done" is not a
    # tidiness problem.
    return (
        f"{scope}\n"
        "\n"
        "If they do, a live view opens here on its own in a new tab, and closes when\n"
        f"you run {command_hint('assist stop')}. You don't have to open anything."
    )


# Screen sharing is the one part of a share whose limits are NOT ours to set, and
# the copy has to say so rather than inherit the confident tone of the sentences
# above it.
#
# Control is genuinely fenced: the tab pin, remote_scope.py's per-parameter
# allowlist, the navigation host check and Commands.swift's refusal all really do
# stop a helper reaching past the one tab or the one app. Viewing is not. Video
# comes from getDisplayMedia, and the Screen Capture spec forbids a site narrowing
# the picker for the user: "The specified options can't be used to limit the
# choices available to the user." monitorTypeSurfaces and displaySurface are hints
# a browser may ignore, and displaySurface is applied AFTER the choice is made.
#
# So do not "fix" this by adding constraints to the getDisplayMedia call in
# rtc.ts. They cannot deliver what a reader would take them to mean. The person
# choosing in the picker is the fence, and telling them that is the only honest
# thing we can do.
_VIDEO_CAVEAT = (
    "Screen sharing is separate, and off until someone starts it. When it starts,\n"
    "Chrome asks you what to share and they see whatever you pick: pick that one\n"
    "thing and that is all they see, pick a whole screen and they see the whole\n"
    "screen. Chrome doesn't let us shorten that list for you, so what you pick in\n"
    "that box is the only thing deciding what they watch."
)

# The same warning, for a share that IS starting a picture, plus the three things
# a person needs before they answer that picker.
#
# It never contradicts the caveat above and it repeats the picker sentence word
# for word on purpose: the two are alternatives, never both printed, and the one
# sentence that has to survive being read twice by the same worried person is the
# one saying that their answer in that box is the whole fence.
#
# The macOS permission is here because its failure is silent and specific. Chrome
# itself needs Screen Recording in System Settings; without it getDisplayMedia
# still succeeds, the picker still appears, and the helper gets a black
# rectangle. A person watching that has no way to guess which of six things went
# wrong, so the answer is printed before it happens rather than diagnosed after.
_VIDEO_ON = (
    "You're also starting a picture of your screen.\n"
    "\n"
    "The picture is separate from what they can click. What they SEE is whatever\n"
    "you pick in Chrome's box; what they can TOUCH is only the one thing named\n"
    "above. Neither one widens the other.\n"
    "\n"
    "Chrome asks you what to share and they see whatever you pick: pick that one\n"
    "thing and that is all they see, pick a whole screen and they see the whole\n"
    "screen. Chrome doesn't let us shorten that list for you, so what you pick in\n"
    "that box is the only thing deciding what they watch.\n"
    "\n"
    "On a Mac, Chrome itself needs Screen Recording permission in System Settings\n"
    "before it can capture anything. If your helper says they're getting a\n"
    "black picture, that grant is what's missing - nothing else looks like that.\n"
    "\n"
    'To stop the picture but keep helping, use Chrome\'s own "Stop sharing" bar.\n'
    "It ends the video and leaves the rest of the session exactly as it is."
)

def _video_copy(video: bool) -> str:
    """One of the two, never both. A share has a picture or it does not.

    The off branch names the flag, so that "there is no video here" and "you
    could have had video and didn't ask" stop being the same silence - somebody
    who does not know the flag exists cannot decide not to use it.
    """
    if video:
        return _VIDEO_ON
    return (
        f"{_VIDEO_CAVEAT}\n"
        "\n"
        "If you also want them to SEE your screen, stop and start again with\n"
        f"{command_hint('share --video')}. Nothing starts a picture on its own, and\n"
        "a helper joining can't start one either."
    )


def _stop_copy(kind: str, video: bool = False) -> str:
    """How to stop, naming only the controls that exist for THIS scope.

    They are not the same list for both scopes, and promising all three every
    time is how someone ends up hunting the menu bar for a row that was never
    going to be there. The in-page button is painted by the extension into the
    tab being driven, so a browser share has it and an app share cannot. The
    menu-bar row belongs to the Mac helper app, which an app share proves is
    running (that is how the bundle got pinned) and a browser share does not.
    """
    if kind == "browser":
        seen = (
            "While they're working there's a Stop button in the corner of that tab,\n"
            "and a Stop row in the LucidPilot menu bar if you run the Mac app."
        )
    else:
        seen = (
            "While they're working there's a Stop row in the LucidPilot menu bar.\n"
            "Nothing appears inside the app itself: LucidPilot doesn't draw in other\n"
            "people's windows."
        )
    # Named here rather than beside the picker copy because this is the
    # paragraph a person comes back to when they want out. Chrome's own bar
    # stops the video alone; every control listed here stops the whole session,
    # and somebody who has just decided to stop should not have to work out
    # which half each button covers.
    picture = "\nEvery one of those ends the picture as well." if video else ""
    return (
        f"To stop, at any point: {command_hint('share stop')}. It stops this machine\n"
        f"from answering immediately, whether or not the network is working.\n{seen}{picture}"
    )


def _relay_ticket(*, joining: bool = False) -> str:
    """The audience-scoped ticket /rc/open demands, or a plain refusal.

    The environment wins over the live minter, not the other way around: the
    env var exists for an operator running their OWN relay with their own
    signing key (the rig, a self-hoster), and a hand-set override that gets
    silently outranked by licensing.relay_ticket() would make that setup
    impossible to test against. Nobody sets LUCIDPILOT_RELAY_TICKET by
    accident, and it dies with the shell that exported it.
    """
    ticket = (os.environ.get("LUCIDPILOT_RELAY_TICKET") or "").strip()
    if ticket:
        return ticket
    mint = getattr(licensing, "relay_ticket", None)
    if callable(mint):
        return mint(joining=joining)
    raise ValueError(
        "This build can't start a share yet: it has no way to get a ticket for the "
        f"relay. Run {command_hint('upgrade')} for the newer version."
    )


def _code_from(announcement: str) -> str:
    """The pairing code out of remote.share's announcement, or "" if it moved.

    Normalised, not as it was printed: the announcement groups it with a dash
    and this is regrouped for display below, so handing back the printed form
    would group it twice.
    """
    _, _, tail = announcement.partition(_CODE_LABEL)
    token = remote.normalise(tail.split()[0]) if tail.split() else ""
    # The announcement now carries ONE string, code and password together, so
    # the code is its first CODE_LEN characters. Length-checked rather than
    # sliced blindly: a reworded announcement should give back "" and let the
    # caller fall back, not a confident prefix of the wrong thing.
    if len(token) == remote.PAIR_LEN:
        return token[:remote.CODE_LEN]
    return token if len(token) == remote.CODE_LEN else ""


def _share_is_running() -> bool:
    # `error` counts as ended, not as running. The commonest failure of this
    # whole flow is a code nobody claims inside 120s, which sets error and
    # never sets over, and the obvious next thing a human types is /lp share
    # again. Refusing that with "end the one you have first" would be refusing
    # them a retry for a share that is already dead.
    return bool(_SHARE) and not _SHARE.get("over") and _SHARE.get("error") is None


def _share(bridge: ChromeProfileBridge, auth: ChromeAuth, tokens: "list[str]") -> str:
    first = tokens[0].lower() if tokens else ""
    if first in ("y", "yes", "ok"):
        return _share_confirm(bridge, tokens[1:])
    if first == "stop":
        # Never gated on anything: a stop that can refuse is not a stop.
        return _share_stop()
    if first == "trust":
        return _share_trust(tokens[1:])
    if first == "trusted":
        return _share_trusted()
    if first == "untrust":
        return _share_untrust(tokens[1:])
    if first in ("listen", "unattended"):
        return _share_listen(bridge, auth, tokens[1:])
    return _share_start(bridge, auth, tokens)


def _share_listen(bridge: ChromeProfileBridge, auth: ChromeAuth,
                  tokens: "list[str]") -> str:
    """Requester side of unattended access: wait, with no code to read out.

    The mirror of `assist machine`. Both ends derive the meeting point from a
    grant established during an earlier verified session, so there is nothing to
    say to anybody - which is the whole point, and also why this is the one
    command here that can start a session with no human in the loop.

    Bounded in windows rather than left running, deliberately. A machine sitting
    at a rendezvous forever is a machine anybody holding a grant can walk into
    at any hour, and 'until I said stop' is a promise a terminal command cannot
    keep across a sleep. The Mac app is the right home for an always-listening
    version; this is the honest version of it for a command line.
    """
    if auth is not None and auth.user_revoked():
        return (
            "Control is locked on this machine, so nothing can connect to it.\n"
            "Deactivate and re-activate your licence in the LucidPilot popup in Chrome\n"
            "to unlock it."
        )

    grants = remote_trust.requester_store().list()
    if not grants:
        return (
            "Nobody has unattended access to this Mac, so there is nobody to wait for.\n"
            f"Grant it during a session with {command_hint('share trust <name>')}."
        )

    rounds = 1
    if tokens:
        try:
            rounds = max(1, min(12, int(tokens[0])))
        except ValueError:
            return f"'{_plain(tokens[0], 20)}' is not a number of windows to wait."

    # One grant per listener: each has its own secret and so its own meeting
    # point, and sitting at several at once needs a thread apiece. Refused
    # rather than silently picking, for the same reason the helper side refuses
    # an ambiguous name.
    if len(grants) > 1:
        names = "\n".join(f"  {g['label']}" for g in grants)
        return (
            "More than one person has unattended access, and this can only wait at\n"
            "one meeting point at a time:\n"
            "\n" + names + "\n"
            "\n"
            "Revoke the ones you are not expecting with "
            f"{command_hint('share untrust <id>')}, then run this again."
        )

    grant = grants[0]
    secret = remote_trust.requester_store().secret_for(grant["id"])
    if secret is None:
        return "That grant has just expired. Nothing is waiting."

    kind = grant.get("scopeKind") or "browser"
    try:
        pin, where = _scope_pin(bridge, kind, None)
    except ValueError as exc:
        return str(exc)
    except BridgeError:
        return (
            "I can't reach your browser, so there's nothing to hand over yet. Run "
            f"{command_hint('doctor')} and try again once it says your browser is connected."
        )

    scope = ScopePolicy(kind=kind, pin=pin, allowMutating=True,
                        expiresAt=time.time() + _SHARE_CAP_S)
    global _SHARE
    try:
        session = remote.listen_unattended(
            scope,
            _relay_ticket(),
            secret,
            remote_trust,
            rounds=rounds,
        )
    except licensing.LicenseRequiredError as exc:
        return str(exc)
    if session is None:
        return (
            f"{_plain(grant['label'], 40)} did not connect. Nothing was shared, and\n"
            "nothing is still waiting."
        )

    # The pin was resolved before the wait, and the wait can be the better part
    # of an hour: the tab can close, or be swapped out from under its id by a
    # prerender, while nobody is looking. Going live anyway announces "They're
    # in" and then refuses every single command with a hard stop - seen live,
    # once - so the pin is re-checked the moment somebody actually arrives.
    # Refused rather than re-pinned to whatever is active NOW: the grant was
    # made against a machine, but the session's scope was read out against a
    # tab, and silently substituting a different one is the wrong-tab bug with
    # a handshake on top.
    if kind == "browser":
        try:
            tabs = bridge.send("tab.list", {}, 10_000) or []
            alive = any(isinstance(t, dict) and t.get("id") == scope.pin for t in tabs)
        except BridgeError:
            alive = False
        if not alive:
            try:
                session.close()
            except Exception:  # noqa: BLE001 - closing is best-effort on a refusal
                pass
            return (
                "The tab this was going to share went away while nothing was\n"
                f"connected, so nobody was let in. Open the page and run\n"
                f"{command_hint('share listen')} again."
            )

    # The same state the spoken flow builds, so _share_go_live and every stop
    # control work on this session exactly as they do on a typed one. No "otp"
    # key: there is nothing to display and nothing for anybody to read out,
    # which is the entire difference between the two flows.
    _SHARE = {
        "scope": scope,
        "where": where,
        "session": session,
        "ready": threading.Event(),
        "video": False,
        "kind": kind,
        "unattended": True,
    }
    _SHARE["ready"].set()
    return _share_go_live(bridge)


def _machine_name() -> str:
    """What this Mac calls itself, for the other side's list."""
    try:
        import socket
        name = socket.gethostname().split(".")[0].strip()
    except Exception:  # noqa: BLE001
        name = ""
    return _plain(name, 40) or "a Mac"


def _share_trusted() -> str:
    """Who can come back, and until when. The list is the revoke control."""
    grants = remote_trust.TrustStore().list()
    if not grants:
        return (
            "Nobody can come back without a code. That is the default, and it is\n"
            "the safe one."
        )
    lines = []
    for grant in grants:
        left = max(0, int((grant["expiresAt"] - time.time()) // 86400))
        used = grant.get("lastUsedAt")
        when = time.strftime("%d %b", time.localtime(used)) if used else "never since"
        lines.append(f"  {grant['label']}  ({grant['scopeKind']}, {left} days left, "
                     f"last in: {when})   id {grant['id']}")
    return (
        "These people can reach this Mac without a code:\n"
        "\n" + "\n".join(lines) + "\n"
        "\n"
        f"Take one back with {command_hint('share untrust <id>')}, or all of them\n"
        f"with {command_hint('share untrust all')}."
    )


def _share_untrust(args: "list[str]") -> str:
    """Take it back. Never gated on a session: this is a stop control."""
    target = " ".join(args).strip()
    store = remote_trust.TrustStore()
    if not target:
        return (
            "Say which one, or 'all':\n"
            "\n"
            f"    {command_hint('share untrust all')}\n"
            "\n"
            f"{command_hint('share trusted')} lists them with their ids."
        )
    if target.lower() == "all":
        count = store.revoke_all()
        return (
            f"Took it back from {count} " + ("person" if count == 1 else "people") + ".\n"
            "Nobody can reach this Mac without a code now."
        )
    if store.revoke(target):
        return (
            "Took it back. They cannot reach this Mac without a code any more, and\n"
            "that is true immediately - not at the end of anything they are doing."
        )
    return (
        f"Nothing here is granted to '{target}'. "
        f"{command_hint('share trusted')} lists what is."
    )


def _share_trust(args: "list[str]") -> str:
    """Let the helper in THIS session come back later, without the ceremony.

    Only from inside a live session, and that is the whole security argument:
    the secret is derived from key material both sides only hold because they
    completed a handshake somebody consented to. There is no way to type one in,
    which is what stops "turn on unattended access" being a thing a stranger on
    the phone can talk somebody into.
    """
    session = _SHARE.get("session") if _SHARE else None
    if session is None or _SHARE.get("stop") is None:
        return (
            "Nobody is connected, so there is nobody to let back in. Do this while\n"
            "they are working with you: it is their being here, now, that makes the\n"
            "grant mean anything."
        )
    label = " ".join(args).strip() or _HELPER_LABEL
    scope = _SHARE["scope"]
    material = remote_trust.session_material(session.keys)
    # The label goes into the derivation, so two grants to the same person from
    # two sessions are different secrets and revoking one cannot be undone by
    # replaying the other.
    stamp = f"{label}@{int(time.time())}"
    secret = remote_trust.derive_trust_secret(material, label=stamp)
    store = remote_trust.TrustStore()
    first_ever = not store.list()
    helper_id = store.grant(secret=secret, label=label, scope_kind=scope.kind)
    expires_at = time.time() + remote_trust.DEFAULT_TTL_S

    # Handed over on their next action rather than sent now: an answer is the
    # only frame this side gets to write. The secret is NOT in it - they derive
    # the same one from the session keys they already hold.
    _SHARE["trustOffer"] = {"label": stamp, "display": label, "expiresAt": expires_at}

    days = int(remote_trust.DEFAULT_TTL_S // 86400)
    # Once, on the first grant this Mac has ever made. "Turn on unattended access
    # so I do not have to call you each time" is the highest-value thing a scam
    # caller can ask for in this whole product, and this is the only moment left
    # to say so. Every time would train people straight past it.
    warning = ""
    if first_ever:
        warning = (
            "\n"
            "This is the first time you have done this. If somebody rang YOU and\n"
            "asked you to set this up, stop and take it back now - that is what a\n"
            "scam looks like, and this is the part they actually want.\n"
        )
    return (
        f"{label} can come back for the next {days} days, without a code.\n"
        f"{warning}"
        "\n"
        "They will be able to reach this Mac when you are not here, so only do this\n"
        "for somebody you would hand your unlocked laptop to. It takes effect on\n"
        "their next action in this session.\n"
        "\n"
        f"To take it back at any time: {command_hint('share untrust')}\n"
        f"To see who has it: {command_hint('share trusted')}"
    )


def _share_start(bridge: ChromeProfileBridge, auth: ChromeAuth, tokens: "list[str]") -> str:
    if _share_is_running():
        return (
            "You're already sharing. End that one first with "
            f"{command_hint('share stop')}."
        )
    # Before the ceremony, not after it. Every remote command goes through
    # execute_gated, which refuses outright while control is locked, so without
    # this check a person reads a code and a 16-character password down a phone,
    # pairs, compares six digits, and only then finds out that nothing can run.
    # The dispatcher already called extend_on_use(), which revives an idle lock
    # but deliberately not a revoke or a passed hard cap (auth.py:332-347).
    # Only a REVOKE stops a share being offered, not the absence of a licence.
    # Being helped is free: the paid thing is driving somebody else's machine,
    # and that is checked on the helper's side before anything leaves them. A
    # requester installs this because someone they trust told them to, and
    # charging them admission to be helped was charging for the one moment that
    # brings new people to the product at all.
    #
    # The check that remains is the one this comment block was always about: a
    # person who pressed revoke must not read a code and a sixteen-character
    # password down a phone, pair, compare six digits, and only then find out
    # that nothing can run.
    if auth is not None and auth.user_revoked():
        return (
            "Control is locked on this Mac, so a helper couldn't do anything anyway.\n"
            "Deactivate and re-activate your licence in the LucidPilot popup in Chrome\n"
            "to unlock it - a fresh licence assertion is what re-grants control."
        )
    # OPT IN, and the reasoning belongs right here where the flag is read rather
    # than in a design note nobody opens.
    #
    # A picture is the thing people picture when they hear "screen sharing", so
    # defaulting it on is tempting. It is wrong for this command for two reasons.
    # First, what "share" has meant here from the beginning is CONTROL of one tab
    # or one app, fenced and describable; a picture is a second, wider thing with
    # a fence we do not own (Chrome's picker), and quietly bundling the wide one
    # into the narrow one's name is how consent copy stops being true. Second,
    # the picker is a modal box, and it would land on somebody who is mid-
    # ceremony reading a code and a sixteen-character password down a phone. A
    # dialog nobody asked for, at that exact moment, is answered by dismissing
    # it - which is the worst outcome available, because it is a person learning
    # to click past this feature's only real fence.
    #
    # The flag changes nothing about who acts. The picker is answered on this
    # machine by the person sitting at it, and a helper joining still starts
    # nothing: video.* has no ACTION_PARAMS row and never will.
    tokens = list(tokens)
    video = any(token.lower() == "--video" for token in tokens)
    tokens = [token for token in tokens if token.lower() != "--video"]
    try:
        kind, bundle, extra = _parse_scope(tokens)
        if extra:
            return f"I don't know what '{extra[0]}' means here. {_SCOPE_HELP}"
        pin, where = _scope_pin(bridge, kind, bundle)
        ticket = _relay_ticket()
    except ValueError as exc:
        return str(exc)
    except BridgeError:
        return (
            "I can't reach your browser, so there's no tab to share yet. Run "
            f"{command_hint('doctor')} and try again once it says your browser is "
            "connected."
        )

    otp = remote.mint_otp()
    scope = ScopePolicy(
        kind=kind,
        pin=pin,
        allowMutating=True,
        expiresAt=time.time() + _SHARE_CAP_S,
        agent=_HELPER_LABEL,
    )
    state: "dict[str, Any]" = {
        "scope": scope,
        "where": where,
        # Kept so a UI driving this flow (share_api.py) can display the password
        # it has to read out; the typed flow gets it from the announce text.
        # Cleared at confirm: past the handshake it authenticates nothing, and a
        # one-time password that outlives its one time is just exposure. Never
        # served by share_api.state() - only returned by the call that mints it.
        "otp": otp,
        "ready": threading.Event(),
        # Asked for, not yet running. The capture starts at /lp share y, after
        # the six digits match, and never before: a picker raised while the
        # pairing is still unconfirmed would be asking somebody to share their
        # screen with whoever happened to claim the code.
        "video": video,
        # What Chrome's picker was answered with, and the input to the app-scope
        # pointer fence. None means no picture, which refuses.
        "surface": None,
    }

    def announce(message: str) -> None:
        # remote.share announces twice: the two strings, then its own six
        # digits. setdefault keeps the first, and the second is dropped on
        # purpose - this side compares the helper's digits instead of showing
        # its own, so printing ours would only invite someone to type them
        # back in and call that a check.
        state.setdefault("announced", message)
        state["ready"].set()

    def run() -> None:
        try:
            state["session"] = remote.share(scope, ticket, otp=otp, announce=announce)
        except BaseException as exc:  # noqa: BLE001
            state["error"] = exc
        finally:
            state["ready"].set()

    thread = threading.Thread(target=run, name="lucidpilot-share", daemon=True)
    state["thread"] = thread
    global _SHARE
    _SHARE = state
    opened_after = time.time()
    thread.start()
    state["ready"].wait(_OPEN_WAIT_S)

    # The code, structurally, for a UI that has to show it. It exists from the
    # announce onwards but the session object does not appear until somebody
    # claims, so a panel with nothing but `session` to read has nothing to
    # display during exactly the step where the person reads it out loud.
    #
    # Time-guarded: the pairing record is machine-wide and outlives the process,
    # so trusting it blindly would happily show a code from a share that ended
    # yesterday - and somebody would read that out.
    pairing = remote.active_pairing() or {}
    if pairing.get("code") and float(pairing.get("openedAt") or 0) >= opened_after - 1:
        state["code"] = pairing["code"]

    if "announced" not in state:
        # Either it failed outright, or the relay has not answered inside
        # _OPEN_WAIT_S. The thread is a daemon polling against its own 120s
        # claim deadline, so abandoning it costs one dead code at the relay.
        error = state.get("error")
        _SHARE = {}
        if error is not None:
            return f"That share didn't start: {error}"
        return (
            "The relay isn't answering, so there's no code to read out yet. Try "
            "again in a moment."
        )

    code = _code_from(state["announced"])
    if not code:
        # The copy moved under us. Show what we were handed rather than a
        # share with no code in it.
        strings = state["announced"]
    else:
        # ONE labelled string. It used to be two, on separate lines and never
        # the same one, because they were two different secrets and running them
        # together invited reading one and skipping the other. Merged there is
        # nothing to keep apart: the whole thing is the secret, and one line to
        # find your place on beats two.
        strings = (
            "  Read this out:\n"
            f"      {remote.merge_pair(code, otp)}"
        )

    return (
        f"{_scope_headline(kind)}\n"
        "\n"
        f"{_scope_copy(kind, where, video)}\n"
        "\n"
        f"{_stop_copy(kind, video)}\n"
        "\n"
        "One thing to read to your helper.\n"
        "\n"
        f"{strings}\n"
        "\n"
        "It never leaves this machine any other way. Nobody should ever ask you for\n"
        "it by email or chat - read it out on the call you're already on.\n"
        "\n"
        "Once they've typed it in, say yes here and they're in:\n"
        "\n"
        f"    {command_hint('share y')}\n"
        "\n"
        "Nothing they do reaches this machine until you do. Only say yes if this is\n"
        "somebody you called - not somebody who called you."
    )


def _share_confirm(bridge: ChromeProfileBridge, args: "list[str]") -> str:
    if not _SHARE:
        return f"Nothing is waiting to start. Begin with {command_hint('share')}."
    error = _SHARE.get("error")
    if error is not None:
        _share_stop()
        return f"That share is over: {error}"
    session = _SHARE.get("session")
    if session is None:
        return (
            "Your helper hasn't typed the code and the password in yet, so there are\n"
            "no six digits to check. Give them a moment and run this again."
        )
    if _SHARE.get("over"):
        # Confirming a session that already ended would start a second serve
        # loop on a channel the relay has buried.
        _share_stop()
        return (
            "That share has already ended. Run "
            f"{command_hint('share')} to start a fresh one."
        )
    if _SHARE.get("stop") is not None:
        # Already confirmed. The second yes is not a yes to anything, and doing
        # it again would do real damage rather than nothing: a second _Channel
        # over one pairing starts its sequence counter at zero again, which the
        # peer reads as a replay and treats as the end of the session. With a
        # picture running it would also raise a second picker in front of
        # somebody who has already answered one.
        return (
            "You're already in that session - the digits matched and they're in. To end "
            f"it, use {command_hint('share stop')}."
        )

    digits = "".join(args).strip()
    # The digits are now OPTIONAL, and that is a deliberate loosening.
    #
    # What they buy is narrow: the crypto already refuses anybody who does not
    # hold the password, so comparing them only ever catches the case where the
    # password LEAKED and somebody raced the real helper with it. Every session
    # was paying a second spoken exchange for that one case, and the attack that
    # actually costs people their machines - a scam caller talking somebody
    # through it - walks straight past a digit comparison, because the victim
    # reads the digits out to the scammer quite happily.
    #
    # So the default is an explicit yes to a prompt that says what is being
    # handed over. Anyone who does want the stronger check can still pass the
    # digits and they are still compared, exactly as before: a mismatch remains
    # fatal, and remains a torn-down session rather than a warning.
    if digits:
        if len(digits) != 6 or not digits.isdigit():
            return f"'{digits}' isn't six digits. Ask your helper to read them out again."
        if not hmac.compare_digest(digits, session.sas):
            _share_stop()
            return (
                "Those six digits are not the ones on this side, so somebody is sitting\n"
                "between you and whoever you think you're talking to. I've stopped the\n"
                "share and nothing ran. Don't reuse that code: run "
                f"{command_hint('share')} for a fresh one."
            )

    return _share_go_live(bridge)


# How many actions the panel keeps. Enough to scroll a little and see a pattern,
# short enough that a busy session cannot grow the panel's memory without bound.
_RECENT_ACTIONS = 40

# Raw action names to something a person watching would recognise. Deliberately
# a verb and its object: "clicked" tells somebody watching more than
# "page.click", and this feed exists for the person being helped, not for us.
_ACTION_WORDS = {
    "page.click": "clicked something",
    "page.tap": "tapped something",
    "page.fill": "filled in a field",
    "page.type": "typed",
    "page.key": "pressed a key",
    "page.scroll": "scrolled",
    "page.navigate": "opened a page",
    "page.screenshot": "took a screenshot",
    "page.inspect": "looked at the page",
    "page.snapshot": "read the page",
    "page.drag": "dragged something",
    "page.upload": "chose a file",
    "page.hover": "hovered over something",
    "tab.list": "listed your tabs",
    "tab.activate": "switched tab",
    "app.click": "clicked something",
    "app.type": "typed",
    "app.fill": "filled in a field",
    "app.key": "pressed a key",
    "app.scroll": "scrolled",
    "app.menu": "used a menu",
    "app.screenshot": "took a screenshot",
    "app.snapshot": "read the window",
    "app.activate": "brought an app forward",
    "app.paste": "pasted",
    "app.copy": "copied",
}


def _describe_action(action: str) -> str:
    """One short phrase for the watching panel."""
    known = _ACTION_WORDS.get(action)
    if known:
        return known
    # An unmapped action is still worth showing, and the raw name is better than
    # silence: a feed that quietly drops what it does not recognise is a feed
    # that under-reports exactly when something unusual is happening.
    return action


def _record_action(state: "dict[str, Any]") -> "Callable[[str, bool, Optional[str]], None]":
    """Append to the panel's activity feed, and never get in the way.

    A ring buffer rather than a growing list: a half-hour session at speed is
    thousands of commands, and the panel only ever shows the tail of it.
    """
    def note(action: str, ok: bool, error: "Optional[str]") -> None:
        entry = {
            "at": time.time(),
            "what": _describe_action(action),
            "ok": bool(ok),
        }
        if not ok and error:
            # Trimmed: this lands in a narrow panel, and the first clause of a
            # refusal is the part that says which fence stopped it.
            entry["why"] = _plain(error.split(".")[0], 90)
        recent = state.setdefault("recent", [])
        recent.append(entry)
        if len(recent) > _RECENT_ACTIONS:
            del recent[:-_RECENT_ACTIONS]
        state["actionCount"] = int(state.get("actionCount", 0)) + 1

    return note


def _share_go_live(bridge: ChromeProfileBridge) -> str:
    """Take the pending share live. Everything after the far side is trusted.

    Two callers, and the difference between them is only WHY the far side is
    trusted. The spoken flow trusts it because two people compared six digits
    out loud. The unattended flow trusts it because the one-time password was
    derived from a grant that only exists after a completed verified session,
    and was never transmitted by either side - so a middle cannot produce it
    and the handshake it just passed IS the proof the digits used to provide.

    Everything from here is identical, which is the point of extracting it:
    the session caps, the courier threads and the scope fence must not have
    two implementations that can drift apart.
    """
    global _SHARE
    scope = _SHARE["scope"]
    state = _SHARE
    # Read here rather than inherited from the caller. The extraction that
    # created this function left `session` behind in _share_confirm's scope,
    # where run()'s `except BaseException` swallowed the resulting NameError
    # into state["ended"] - so the command still answered "They're in." and the
    # session never served a single command. Bind what this body actually uses.
    session = state.get("session")
    # Somebody has now been let in here, which is what a first-run warning asks
    # about. Recorded on the confirm rather than on the share, because a share
    # that nobody ever claimed is not somebody having been let in.
    try:
        remote.note_session_completed()
    except Exception:  # noqa: BLE001 - a bookkeeping write must not end a session
        pass
    # The password's one time is over: it salted the HKDF during the handshake
    # and authenticates nothing from here on, so it stops being held.
    state.pop("otp", None)

    # Two clocks, and they have to be the same clock. expiresAt was stamped when
    # the code was minted and remote_scope.check enforces it per command;
    # serve()'s own hard cap would otherwise start here, ten minutes of phone
    # call later, and the difference is a session that stops answering while the
    # loop keeps politely polling and this terminal still says it is sharing.
    # Handing serve the remaining time makes the loop end exactly when the scope
    # does.
    remaining = scope.expiresAt - time.time()
    if remaining <= 0:
        _share_stop()
        return (
            "That share ran out of time before it started, so I've ended it. Run "
            f"{command_hint('share')} for a fresh code."
        )

    # The kill switch, created here and handed to the loop that has to obey it.
    # Three things set it and none of them needs the network: /lp share stop in
    # this terminal, the Stop control in the in-page indicator, and the Stop row
    # in the Mac helper's menu bar. The last two are in other processes, so they
    # arrive through the bridge's POST /remote-stop and land on the same event.
    stop = threading.Event()
    state["stop"] = stop
    state["bridge"] = bridge
    set_remote_stop(_share_stop_hook(stop))
    # ONE channel for the whole session, built here and shared, because two would
    # not be a second path - they would be the end of the first. Every _Channel
    # starts its outbound sequence counter at zero and the peer kills the session
    # permanently on a number that repeats, so video and commands are not two
    # things that happen to travel together: they are one session, and this line
    # is where that is decided. A share with no picture builds none at all and
    # lets serve() make its own.
    channel = remote.channel(session, stop=stop) if state.get("video") else None
    state["channel"] = channel
    # Serialises the teardown, so a second thread arriving at _end_video waits
    # for the farewell rather than racing past it into /close.
    state["video_lock"] = threading.Lock()
    # And tell the bridge a share is live, which is how the Mac helper's menu
    # bar knows to show its row for the whole session - including a browser
    # share, which never sends that helper a command to infer it from.
    bridge.set_remote_share(scope.agent)

    # Passed only when there is a picture, rather than passed as None. A share
    # with no video wants serve()'s own defaults, and asking for them by name
    # would be three arguments' worth of noise saying "the way it has always
    # been".
    def _take_trust_offer() -> "Optional[dict]":
        """Hand the pending grant over exactly once.

        Popped rather than read: an offer that rode out on one answer must not
        ride out on the next, or a helper collects the same grant repeatedly and
        the requester's list grows a row per command.
        """
        offer = state.pop("trustOffer", None)
        if not offer:
            return None
        return {"label": offer["label"], "expiresAt": offer["expiresAt"],
                "scopeKind": scope.kind,
                # Not a secret, and the helper's list is unusable without it:
                # "a Mac" is not something a person can pick out of a list of
                # five. They are being granted access to this machine, so its
                # name is the least of what they know about it.
                "machine": _machine_name()}

    video_kwargs: "dict[str, Any]" = {}
    if channel is not None:
        video_kwargs = {
            "channel": channel,
            "on_signal": remote.video_signal_handler(bridge, _video_actions_of(state)),
            # The fence's own input, read per command. A lambda over the state
            # dict rather than a captured value, because the picker is answered
            # after this loop starts and the capture can end before it does -
            # see remote.serve's docstring.
            "surface": lambda: state.get("surface"),
        }

    def run() -> None:
        try:
            remote.serve(session, bridge, session_cap_s=remaining, stop=stop,
                         trust_offer=_take_trust_offer,
                         on_action=_record_action(state), **video_kwargs)
        except BaseException as exc:  # noqa: BLE001
            state["ended"] = str(exc)
        finally:
            state["over"] = True
            # Whatever ended the session ends the picture with it, including the
            # endings nothing here chose: the idle cap, the half-hour cap, the
            # helper saying goodbye, a channel that died. Every one of those
            # leaves Chrome's "you are sharing your screen" bar up over a session
            # that is over unless this runs. Idempotent, so the stop controls
            # that got here first are not undone or repeated.
            #
            # _share_video would also call _end_video once its courier noticed
            # the event, and this is deliberately not waiting for that: the
            # courier can be parked in a drain for up to _DRAIN_TIMEOUT_MS, which
            # is two minutes of a capture nobody is watching. Ending it here and
            # letting the courier find it already done is the right way round.
            stop.set()
            _end_video(state)
            # A loop that ended on its own (a cap, a goodbye) must take the
            # hook with it, or a later Stop press would be answered "yes, I
            # ended a session" for a session that was already over - and the
            # extension reads exactly that answer to decide whether its own
            # refusal is still the only thing holding. Identity-checked so a
            # share started since cannot have its hook cleared by this one.
            if _SHARE is state:
                set_remote_stop(None)
                bridge.set_remote_share(None)

    thread = threading.Thread(target=run, name="lucidpilot-share-serve", daemon=True)
    state["thread"] = thread
    thread.start()
    if channel is not None:
        # Its own thread because both halves of it block: the picker waits on a
        # human, and the courier that follows runs for the whole session. serve()
        # is already blocking on the other one.
        threading.Thread(
            target=_share_video, args=(state,), name="lucidpilot-share-video", daemon=True
        ).start()

    return (
        "They're in.\n"
        "\n"
        f"{_scope_copy(scope.kind, state['where'], bool(channel))}\n"
        "\n"
        f"{_stop_copy(scope.kind, bool(channel))}\n"
        "It also ends itself after five quiet minutes, and half an hour after you\n"
        "started sharing no matter what."
    )


# How long the picker may stay unanswered. It is a human reading a dialog while
# on the phone, so it is generous; the point of having a ceiling at all is that a
# picker somebody walked away from does not hold a thread for the session's whole
# half hour.
_PICKER_WAIT_MS = 120_000

# What video.stop and video.refused may spend on a loopback call. Same reasoning
# as remote._SIGNAL_TIMEOUT_MS: one of these taking ten seconds means Chrome is
# gone, not that it is busy.
_VIDEO_CALL_MS = 10_000


def _video_actions_of(state: "dict[str, Any]") -> Any:
    """The family this share is actually using.

    Read off the state rather than recomputed, because a courier draining one
    side while the picture runs on the other is a session that looks alive and
    carries nothing - and it would fail silently, which is the worst way.
    Defaults to the browser family so a state built before video started (or by
    an older path) behaves exactly as it always did.
    """
    return state.get("videoActions") or remote.BROWSER_VIDEO


def _video_actions_for(kind: str) -> Any:
    """Which side answers for the picture, decided by the scope and nothing else.

    Not a preference and not a setting. A whole screen cannot be captured by the
    browser with a display id anybody can act on - getDisplayMedia never says
    which display it handed over, which is why a multi-display whole-screen share
    was refused outright - and a browser tab cannot be captured natively at all.
    So screen scope goes to the Mac helper and everything else to the extension.

    App scope stays on the browser path for now: its pointer already resolves
    against a WINDOW frame, and capturing one window natively is a different
    filter (SCContentFilter on a window) than the display capture that exists.
    """
    return remote.NATIVE_VIDEO if kind == "screen" else remote.BROWSER_VIDEO


def _share_video(state: "dict[str, Any]") -> None:
    """Put the picker up, then carry this machine's signalling until it ends.

    Runs on its own thread beside serve(). Everything it touches lives in
    ``state`` rather than in _SHARE, so a share that has already been stopped and
    replaced writes into the dict it was handed instead of resurrecting the live
    one - the same rule the rest of this file follows.
    """
    bridge, session, stop = state["bridge"], state["session"], state["stop"]
    channel = state["channel"]
    # Checked here and again after the relay round trip below. A picker that
    # appears straight after somebody typed stop is the single worst moment for
    # this feature to look like it ignored them, and the round trip is long
    # enough to fit a stop inside.
    if stop.is_set():
        return
    try:
        # Only the requester may call this, which is why the credentials cannot
        # simply be sent by the helper: they are minted against this session's
        # own code. An empty answer is legitimate - two machines on one LAN find
        # each other with host candidates - so a failure here is not fatal.
        #
        # POST, and the method is load bearing. The relay answers GET on exactly
        # two routes, /next and /handshake, and everything else with 405 (see
        # worker.ts's `expected` check). This asked for GET until a real deploy
        # answered 405, which the except below turned into "no ICE servers" -
        # so video would have worked on a LAN, where host candidates are enough,
        # and silently never connected across the internet, which is the one
        # place TURN exists for. Every test mocked one side or the other, so
        # nothing caught it until the two halves met.
        answer = session.relay.call(
            "POST", f"/rc/{session.code}/turn", peer=session.peer_token
        ) or {}
        ice = answer.get("iceServers") or []
    except remote.RemoteError as exc:
        ice = []
        # Recorded rather than swallowed. An empty ICE list means the two
        # machines have only their own host candidates, which is enough on one
        # LAN and enough nowhere else - so the picture works when you test it at
        # home and silently never appears for the person on a phone network, who
        # is the case the whole feature exists for. Whoever is watching the
        # session deserves to know that before they wait for a picture that is
        # not coming.
        state["iceMissing"] = str(exc)
    if stop.is_set():
        return

    share_params: "dict[str, Any]" = {"iceServers": ice}
    scope = state["scope"]
    actions = _video_actions_for(scope.kind)
    state["videoActions"] = actions
    if actions.native and scope.pin is not None:
        # The display the person picked. The native side refuses without it on a
        # multi-screen Mac rather than guessing, the same decision the pointer
        # fence makes one layer down.
        share_params["display"] = str(scope.pin)
    if scope.kind == "browser" and scope.pin is not None:
        # The compositor fallback (glue.js's lp-compositor) captures the pinned
        # tab when this machine's native capture is broken. The id travels only
        # from this Python to its own extension - video.* never crosses the
        # relay, and remote_scope refuses `tabId` on the wire outright.
        share_params["tabId"] = scope.pin
    try:
        started = bridge.send(actions.share, share_params, _PICKER_WAIT_MS) or {}
    except Exception as exc:  # noqa: BLE001
        # A cancelled picker arrives here, and so does a Chrome that is not
        # answering. Both leave the CONTROL session running, which is the right
        # answer: they are still on the phone and their helper can still work.
        #
        # Capped through _plain because this string lands in a " · " joined
        # status line, and a browser error with a newline in it would break that
        # line in half - the same reason a page title is capped before it goes
        # in the share block.
        if "screen capture is broken" in str(exc):
            # rtc.ts's combined failure: native capture refused AND the tab
            # fallback could not start (an app share on a broken machine, or
            # the worker had no tab to capture). Say both halves plainly.
            state["note"] = (
                f"no picture: {_plain(exc, 160)}. Control still works - they "
                "can click and type in what you shared"
            )
        else:
            state["note"] = f"didn't start ({_plain(exc, 80)}) - they can still click in what you shared"
        return
    surface = started.get("displaySurface")
    state["surface"] = surface if isinstance(surface, str) and surface else None
    state["capturing"] = True
    source = started.get("source")
    state["source"] = source if isinstance(source, str) and source else None

    if state["source"] == "compositor":
        # Native capture is broken on this Mac and the extension fell back to
        # streaming the shared tab out of Chrome's own compositor. Two truths
        # the person sharing needs, in order. First: the picture is exactly the
        # shared tab - there was no picker, and nothing else can appear in it,
        # which is TIGHTER than the native path, not looser. Second, checked a
        # few seconds in: a fallback that armed but delivers no frames means
        # Chrome itself is compositing on the broken GPU, and the one fix that
        # exists is naming --disable-gpu out loud - nothing else looks like
        # that failure.
        state["note"] = (
            "the picture is the tab fallback: it shows exactly the shared tab, "
            "nothing else can appear in it"
        )

        def _frames_check() -> None:
            time.sleep(6)
            if state.get("over") or stop.is_set():
                return
            try:
                status = bridge.send(_video_actions_of(state).status, {}, 10_000) or {}
            except Exception:  # noqa: BLE001
                return
            if status.get("source") == "compositor" and not status.get("framesSent"):
                state["note"] = (
                    "the tab fallback is up but no frames are arriving. On this "
                    "machine that means Chrome is compositing on a GPU whose "
                    "capture is broken - relaunch Chrome with --disable-gpu so the "
                    "fallback gets software frames. Control works either way"
                )

        threading.Thread(
            target=_frames_check, name="lucidpilot-share-video-frames", daemon=True
        ).start()

    # Blocks for the rest of the session. It returns on the kill switch, on a
    # dead channel, on a Chrome that quit, or on the browser's own `bye` - which
    # is what Chrome's "Stop sharing" bar produces, and the one ending that is
    # the picture stopping rather than the session doing so.
    remote.video_courier(bridge, channel, stop=stop, actions=_video_actions_of(state))
    if not stop.is_set():
        state["note"] = _video_note()
    _end_video(state)


def _video_note() -> str:
    """What /lp status says about a picture that ended on its own.

    ponytail: this is a note, not a message - nothing pushes it anywhere. A
    person whose capture just stopped finds out the next time they type
    something, which for a terminal command is the only channel there is. The
    upgrade is the bridge's own toast, the same one the in-page indicator
    already paints, driven from here; it is a bridge action and an extension
    change, and this slice is what makes it reachable enough to be worth one.
    """
    return "stopped - they can still click in what you shared"


def _end_video(state: "dict[str, Any]") -> None:
    """Stop the capture and get the farewell to the peer. Safe to call twice.

    Idempotent through ``pop``, because several things legitimately end one
    share: /lp share stop, either Stop button, /lp revoke, and serve()'s own
    finally when a cap or a goodbye ended the session. A second video.stop would
    be harmless; a second ``bye`` sealed onto the channel would not be, since by
    then the session may be over and the frame would be arriving at a peer who
    has stopped listening.

    The farewell goes out BEFORE anything buries the channel, and that ordering
    is the whole reason this returns signals at all: closing a peer connection
    tells the peer nothing, so without the bye the person watching keeps this
    person's screen on display until ICE gives up on it.
    """
    # Held across the whole teardown rather than only around the pop, and that is
    # what makes the ORDER right as well as the count. Two threads legitimately
    # arrive here at once - a stop control, and serve()'s own finally woken by
    # the same event - and which one wins is a race on how much of a relay
    # long-poll was left to run. The loser has to wait, because its very next
    # move can be _tell_the_relay, and /close buries the channel the winner's
    # farewell is still going out on. Uncontended, which is the usual case and
    # every case with no picture at all, it costs nothing.
    with state.get("video_lock") or threading.Lock():
        if not state.pop("capturing", False):
            return
        # Cleared first and before anything that can throw. A session that is
        # over shares no surface, and a stale value here is a fence that would
        # wave a hand-driven pointer through on the strength of a share that
        # ended.
        state["surface"] = None
        state["source"] = None
        bridge, channel = state.get("bridge"), state.get("channel")
        if bridge is None:
            return
        try:
            answer = bridge.send(_video_actions_of(state).stop, {}, _VIDEO_CALL_MS) or {}
        except Exception:  # noqa: BLE001 - a Chrome that already quit stopped it for us
            return
        if channel is None:
            return
        for signal in answer.get("signals") or []:
            try:
                channel.send_signal(signal)
            except remote.RemoteError:
                # Including ChannelDead. There is nobody left to tell, and the
                # capture is already stopped either way.
                break


def _share_stop_hook(stop: threading.Event) -> "Callable[[], None]":
    """What the bridge's POST /remote-stop calls: the Stop buttons, from here.

    The event is set first and inline, because that is the half of a stop that
    depends on nothing answering and it has to have happened by the time this
    returns - the button reads the answer to decide whether its own local
    refusal is still the only thing holding. The rest is exactly what
    /lp share stop does, and that no longer waits on the relay either, so it
    runs here rather than on a thread of its own.
    """

    def _pressed() -> None:
        stop.set()
        _share_stop()

    return _pressed


def _share_stop() -> str:
    global _SHARE
    state, _SHARE = _SHARE, {}
    if not state:
        return "You're not sharing anything right now."
    # Before anything that can block or fail, and before the early return below:
    # this is the stop, and every line after it is bookkeeping or courtesy. The
    # serving loop checks this event between polls and again with a command in
    # hand, so no command runs after this line whatever the network does next.
    stop = state.get("stop")
    if stop is not None:
        stop.set()
    set_remote_stop(None)
    bridge = state.get("bridge")
    if bridge is not None:
        bridge.set_remote_share(None)
    session = state.get("session")
    if session is None:
        return (
            "Stopped waiting. That code and that password are no good to anyone now; "
            f"run {command_hint('share')} again if you still want help."
        )
    state["over"] = True
    # Telling the relay is a courtesy to the HELPER: it turns their next command
    # into an immediate "this session is over" instead of one that hangs until
    # its own timeout. It is not what stops anything here, so it does not get to
    # hold up the answer either. On a hung relay - a load balancer keeping the
    # connection open, which is what _HungCloseRelay models - this call sits for
    # the whole _HTTP_TIMEOUT_S, and half a minute of dead terminal is exactly
    # when a frightened person decides the stop did not work and goes looking
    # for something else to press. So it goes on a daemon thread and this
    # returns now, with the one thing that is already true.
    threading.Thread(
        target=_farewell, args=(state,), name="lucidpilot-share-close", daemon=True
    ).start()
    return (
        "Stopped. This machine has stopped answering, and nothing your helper sends "
        "will run on it. I'm telling the relay so their screen says why; if the "
        "network is in the way they'll see it time out instead. To lock LucidPilot "
        f"out entirely, use {command_hint('revoke')}."
    )


def _farewell(state: "dict[str, Any]") -> None:
    """The two courtesies a stop owes the other machine, in the order they work.

    Both are on this thread rather than on the caller's for the same reason the
    /close call always was: neither is what stops anything here, and half a
    minute of frozen terminal is exactly when a frightened person decides the
    stop did not work. Stopping the capture is local and immediate; only TELLING
    the peer needs the network.

    The picture goes first, and the order is load bearing rather than tidy.
    _end_video seals a `bye` onto this session's own channel, and /close buries
    that channel at the relay - so a /close that went first would take the
    farewell with it and leave the person watching looking at this person's
    screen until ICE gives up on a connection nobody is feeding.
    """
    _end_video(state)
    session = state.get("session")
    if session is not None:
        _tell_the_relay(session)


def _tell_the_relay(session: "remote.RemoteSession") -> None:
    """The /close courtesy, off the caller's thread and allowed to fail.

    Called directly rather than through relay.close() for the same reason that
    one swallows errors: there is nobody left to report a failure to. The share
    is already over on this machine by the time this runs.
    """
    try:
        session.relay.call("POST", f"/rc/{session.code}/close", {}, peer=session.peer_token)
    except remote.RemoteError:
        pass


def _assist(bridge: ChromeProfileBridge, tokens: "list[str]") -> str:
    global _ASSIST
    if tokens and tokens[0].lower() == "stop":
        return _assist_stop()
    if tokens and tokens[0].lower() in ("trusted", "reachable", "machines"):
        return _assist_reachable()
    if tokens and tokens[0].lower() in ("machine", "unattended"):
        return _assist_machine(bridge, tokens[1:])
    try:
        kind, bundle, rest = _parse_scope(tokens)
    except ValueError as exc:
        return str(exc)
    # Whatever they typed, spelled back the way it has to be typed again. kind
    # is digested into the HKDF info string (remote.scope_digest), so a next
    # step that quietly dropped --app pairs the two sides on different keys and
    # remote.assist reports it as "that one-time password does not match",
    # which sends two people back to re-reading a password that was never
    # wrong. The bundle id rides along because it is what they were told.
    flag = "" if kind == "browser" else f" --app{' ' + bundle if bundle else ''}"

    if not rest:
        return (
            "Type in the share code the other person read out to you:\n"
            "\n"
            f"    {command_hint('assist K7M4-9PQR')}\n"
            "\n"
            "If they told you they're sharing a Mac app rather than a browser tab, add\n"
            "--app on the end."
        )

    # One string now, and the sharer's screen shows exactly one. Joined here
    # rather than demanded as one argument so a person who pastes it with the
    # groups spaced out gets the session they meant instead of a lecture - the
    # dashes and spaces are how it was READ, not part of it.
    #
    # The two-argument form still works. Anyone mid-call with an older build in
    # front of them is looking at two labelled lines, and refusing those would
    # break a session in progress to enforce a format change.
    try:
        code, otp = remote.split_pair("".join(rest))
    except remote.RemoteError as exc:
        return (
            f"{exc}\n"
            "\n"
            f"    {command_hint('assist 6311-VSAV-XM32-5XYZ-GFRR-BQZK' + flag)}\n"
            "\n"
            "Take it by voice on the call you're on. If it arrived by email or chat,\n"
            "stop: that isn't how this is meant to reach you."
        )

    if _ASSIST.get("session") is not None:
        return (
            "You're already helping someone. Finish that first with "
            f"{command_hint('assist stop')}."
        )
    try:
        session = remote.assist(
            code,
            otp,
            # The licensed end. Opening a channel is free so a stranger can ask
            # for help without ever buying anything; joining one is what costs,
            # and the relay checks this before it lets us in.
            ticket=_relay_ticket(joining=True),
            scope_kind=kind,
            # Fixed on both sides rather than a flag: kind and this bool are
            # digested into the HKDF info string, so two sides that disagree
            # fail the handshake. A knob here would be a knob that has to be
            # said out loud correctly on a phone call to work at all.
            allow_mutating=True,
            announce=lambda _message: None,
        )
    except remote.RemoteError as exc:
        return str(exc)

    # One channel for this session, same arithmetic as the sharing side: two
    # would each start their sequence counter at zero and the second frame
    # numbered zero ends the session as a replay.
    return _assist_wire(bridge, session, kind)


def _assist_wire(bridge: ChromeProfileBridge, session: Any, kind: str,
                 *, unattended: bool = False) -> str:
    """Everything after a helper's handshake succeeds, whichever way it began.

    Extracted so the unattended path reuses it rather than growing a second
    copy: the couriers, the sender swap and the trust hook are the parts that
    make a session a session, and two copies of them would drift.
    """
    global _ASSIST
    stop = threading.Event()
    channel = remote.channel(session, stop=stop)
    _ASSIST = {"session": session, "kind": kind, "stop": stop,
               "channel": channel, "bridge": bridge}
    # If the person being helped grants unattended access mid-session, it
    # arrives on an ordinary answer and this is what stores this side's half.
    _ASSIST["on_trust"] = _remember_reachable(session)
    # From here every my_browser_*/my_app_* call in this process leaves over the
    # relay instead of touching this machine. bridge.send consults this on the
    # remotable branch only, so this session's own /lp doctor stays local.
    #
    # on_signal is what makes the live view possible at all, and not as a
    # convenience: passing it starts helper_sender's reader thread, and without
    # that thread nothing polls the relay between commands - so the requester's
    # offer, which is produced when a human over there answers Chrome's picker
    # rather than while anybody is running a command, would sit in the queue
    # until this agent happened to make a tool call.
    sender = remote.helper_sender(
        session,
        channel=channel,
        on_signal=remote.video_signal_handler(bridge),
        on_trust=_ASSIST.get("on_trust"),
        stop=stop,
    )
    set_remote_sender(sender)
    # Both couriers start now rather than when a picture appears. Neither one
    # needs a session to exist: video.drain and video.drainInput both answer
    # empty until there is one, which is exactly what a loop entitled to start
    # first has to get. Waiting for the picture instead would mean watching for
    # it, and the thing that would tell us is the offer these threads exist to
    # carry.
    for target, args in (
        (remote.video_courier, (bridge, channel)),
        (remote.drive_courier, (bridge, sender, kind)),
    ):
        threading.Thread(
            target=target, args=args, kwargs={"stop": stop},
            name=f"lucidpilot-assist-{target.__name__}", daemon=True,
        ).start()

    if unattended:
        # No digits here, and saying them would be worse than useless: an
        # unattended reconnect happens because a grant exists, and there is
        # nobody on the phone to read anything to. Telling the helper to do the
        # spoken ceremony anyway teaches them the digits are decorative, which
        # is the one habit the spoken flow depends on them not having.
        return (
            "You're in, on the access they granted you earlier. Nobody was asked, so\n"
            "keep it to what they expected you to come back for - they can see every\n"
            "action, and can take the access back at any time.\n"
            "\n"
            f"{_assist_scope_copy(kind)}\n"
            "\n"
            f"When you're done: {command_hint('assist stop')}."
        )
    return (
        "Read these six digits back to the person you're helping:\n"
        "\n"
        f"    {session.sas}\n"
        "\n"
        "They type them in on their side. Nothing you do reaches their machine until\n"
        "they do, and if the digits they have are different, neither of you should go\n"
        "any further.\n"
        "\n"
        f"{_assist_scope_copy(kind)}\n"
        "\n"
        f"When you're done: {command_hint('assist stop')}."
    )


def _assist_machine(bridge: ChromeProfileBridge, tokens: "list[str]") -> str:
    """Reconnect to a machine that granted unattended access, with no code.

    The grant is what a spoken code used to be, and it is strictly harder to
    obtain: it only exists because these two machines completed a verified
    session together, and both ends derive the meeting point from it plus the
    clock. Nothing is stored on a server and nothing crosses the wire.

    Named by label rather than by id, because the label is what the list shows
    and what a person remembers. An ambiguous label is refused rather than
    guessed: connecting to the wrong machine unattended is the one mistake here
    with no human in the loop to catch it.
    """
    wanted = " ".join(tokens).strip()
    grants = remote_trust.helper_store().list()
    if not grants:
        return (
            "No machines have given you unattended access yet. They grant it from\n"
            "their end while you are connected, and can take it back at any time."
        )
    if not wanted:
        listed = "\n".join(f"  {g['label']}" for g in grants)
        return (
            "Which machine? These have given you unattended access:\n"
            "\n" + listed + "\n"
            "\n"
            f"    {command_hint('assist machine <name>')}"
        )

    matches = [g for g in grants if g["label"].lower() == wanted.lower()]
    if not matches:
        matches = [g for g in grants if wanted.lower() in g["label"].lower()]
    if not matches:
        return (
            f"No machine called '{_plain(wanted, 40)}' has given you unattended access.\n"
            f"Run {command_hint('assist trusted')} to see the ones that have."
        )
    if len(matches) > 1:
        names = "\n".join(f"  {g['label']}" for g in matches)
        return (
            f"'{_plain(wanted, 40)}' matches more than one machine, and connecting to the\n"
            "wrong one unattended is not a mistake anybody is watching for:\n"
            "\n" + names + "\n"
            "\n"
            "Type the whole name."
        )

    grant = matches[0]
    secret = remote_trust.helper_store().secret_for(grant["id"])
    if secret is None:
        # Expiry is enforced on read, so this is the normal way a grant ends.
        return (
            f"Your unattended access to {_plain(grant['label'], 40)} has run out or been\n"
            "taken back. Ask them to share the ordinary way and they can grant it again."
        )

    kind = grant.get("scopeKind") or "browser"
    try:
        session = remote.assist_unattended(
            secret,
            remote_trust,
            ticket=_relay_ticket(joining=True),
            scope_kind=kind,
            # Same reason as the spoken path: kind and this bool are digested
            # into the HKDF info string, so a knob here is a knob that has to
            # match on the far side to work at all.
            allow_mutating=True,
            announce=lambda _message: None,
        )
    except remote.RemoteError as exc:
        return str(exc)
    except licensing.LicenseRequiredError as exc:
        return str(exc)

    return _assist_wire(bridge, session, kind, unattended=True)


def _remember_reachable(session: Any) -> "Callable[[dict], None]":
    """Store this machine's half of an unattended grant the requester just made.

    The offer carries no secret: this side derives the same one from the session
    keys it already holds, which is why a relay that read every frame of the
    session still cannot reach the machine afterwards.

    Best effort by construction. A grant that fails to save is a session that
    keeps working and an unattended connection that will not happen later, which
    is the right way round - the alternative is tearing down a live session
    somebody is relying on because a file would not write.
    """
    # One per session. Nothing stops a peer attaching an offer to every answer,
    # and each distinct label derives a distinct secret and therefore a new row -
    # so an unbounded list on this machine, from a peer, for free. A machine
    # granting the same helper twice in one session is not a thing that needs
    # supporting.
    granted: "list[bool]" = []

    def _on_trust(offer: dict) -> None:
        if granted:
            return
        label = offer.get("label")
        # Bounded, because it is peer-supplied and goes into a key derivation.
        # 200 is far more than a name plus a timestamp and far less than a
        # denial of service.
        if not isinstance(label, str) or not label or len(label) > 200:
            return
        try:
            # An offer whose expiry has already passed is not a short grant, it
            # is no grant. `ttl or None` fell through to the ninety-day default
            # for exactly that case, which turned a stale offer into the longest
            # grant the product issues - the opposite of what it says.
            ttl = float(offer.get("expiresAt") or 0) - time.time()
            if ttl <= 0:
                return
            material = remote_trust.session_material(session.keys)
            secret = remote_trust.derive_trust_secret(material, label=label)
            # The label comes from what THIS side knows, not from the wire.
            #
            # remote_scope refuses the agent name a helper sends and injects a
            # local one, because "a hostile helper would otherwise name itself
            # Claude". The same is true pointing the other way: a machine that
            # chose its own row in this list could call itself "Mum's iMac" and
            # be picked months later by somebody reading a list. So the name it
            # claims is kept as a claim, and the identity is the date this side
            # was actually let in.
            claimed = _plain(offer.get("machine") or "", 40)
            when = time.strftime("%d %b %Y", time.localtime())
            label = f"Helped {when}" + (f" (calls itself {claimed})" if claimed else "")
            remote_trust.helper_store().grant(
                secret=secret,
                label=label,
                scope_kind=str(offer.get("scopeKind") or "browser"),
                ttl_s=ttl,
            )
            granted.append(True)
        except Exception:  # noqa: BLE001 - see the docstring
            pass

    return _on_trust


def _assist_reachable() -> str:
    """The machines this helper can reach without a code.

    Local to this machine, deliberately: a server-side directory of computers
    somebody can take over is the highest-value thing this product could
    possibly store, and not building one is cheaper than defending it.
    """
    grants = remote_trust.helper_store().list()
    if not grants:
        return (
            "No machines have given you unattended access. They grant it from\n"
            "their end, while you are connected, and can take it back any time."
        )
    lines = []
    for grant in grants:
        left = max(0, int((grant["expiresAt"] - time.time()) // 86400))
        lines.append(f"  {grant['label']}  ({grant['scopeKind']}, {left} days left)")
    return (
        "Machines you can reach without a code:\n"
        "\n" + "\n".join(lines) + "\n"
        "\n"
        "Each of them can take this back at any moment, and you will not be asked."
    )


def _assist_stop() -> str:
    global _ASSIST
    state, _ASSIST = _ASSIST, {}
    # Unconditional, and before anything that can fail: leaving this set would
    # point every later browser call in this process at a relay that is gone.
    set_remote_sender(None)
    if not state:
        return "You're not helping anyone right now."
    # Before anything that can block. Three threads are polling on this event -
    # the reader and both couriers - and two of them are asking a local browser
    # about a session that is over.
    stop = state.get("stop")
    if stop is not None:
        stop.set()
    # Closes the live view, and it is this side's own tab: a window showing
    # somebody else's screen left open after "I'm done helping" is not tidiness.
    #
    # Deliberately NOT a video `bye` to the requester. Their capture is theirs,
    # and their Python is what fences on it: a bye would stop it behind their own
    # side's back, leaving them holding "we are sharing a window" - which is the
    # input to their app-scope pointer fence - for a share that is over. Closing
    # the relay channel below ends their serve() instead, and their own finally
    # then stops the capture and clears the surface.
    bridge = state.get("bridge")
    if bridge is not None:
        try:
            bridge.send(_video_actions_of(_SHARE).stop, {}, _VIDEO_CALL_MS)
        except Exception:  # noqa: BLE001 - a Chrome that quit closed it already
            pass
    session = state["session"]
    session.relay.close(session.code, session.peer_token)
    return (
        "Done. Your browser tools point at your own machine again, and the live view "
        "is closed."
    )


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
                # The killswitch has to reach the two things it never used to.
                # execute_gated's lock stops COMMANDS, on both sides, and that
                # is genuinely everything revoke used to have to stop. It stops
                # neither of these:
                #
                #   * a capture of this person's own screen, which is not a
                #     command and does not pass through the gate at all, and
                #   * an assist session, where the gate is the wrong gate -
                #     it guards LOCAL execution, and a helper's commands leave
                #     through helper_sender rather than through it, so Take
                #     control would keep driving the other machine and the
                #     viewer tab would keep showing their screen.
                #
                # Somebody pressing the kill switch means stop. Both of these
                # are what stop looks like from where they are sitting.
                ended = "\n\n".join(
                    text
                    for text in (
                        _share_stop() if _share_is_running() else "",
                        _assist_stop() if _ASSIST.get("session") is not None else "",
                    )
                    if text
                )
                locked = auth.revoke()
                return f"{ended}\n\n{locked}" if ended else locked
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
            if sub == "share":
                if not REMOTE_ASSIST_AVAILABLE:
                    return _NO_REMOTE_ASSIST
                auth.extend_on_use()
                return _share(bridge, auth, tokens[1:])
            if sub == "assist":
                if not REMOTE_ASSIST_AVAILABLE:
                    return _NO_REMOTE_ASSIST
                auth.extend_on_use()
                return _assist(bridge, tokens[1:])
            if sub == "upgrade":
                # `upgrade dismiss` -> suppress; bare `upgrade` -> instructions.
                if rest.strip().lower() == "dismiss":
                    return _upgrade_dismiss()
                return _upgrade()
        except Exception as exc:  # noqa: BLE001
            return f"[lucidpilot] {type(exc).__name__}: {exc}"
        return (
            f"Unknown subcommand '{sub}'. Try: {command_hint()} "
            "revoke | status | doctor | onboard | background | default | license | "
            "upgrade | share | assist."
        )

    ctx.register_command(
        "lp",
        handler=handler,
        description="Control the LucidPilot browser bridge (revoke/status/doctor/onboard/background/default/upgrade/share/assist).",
        args_hint="revoke|status|doctor|onboard|background|default|upgrade|share|assist",
    )
