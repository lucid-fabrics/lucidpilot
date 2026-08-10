<p align="center">
  <img src=".github/media/logo.png" width="96" alt="LucidPilot logo">
</p>

<h1 align="center">LucidPilot</h1>

<p align="center">
  <b>See what your AI agent is doing in your browser - and, when you want, let it drive.</b>
</p>

<p align="center">
  <a href="https://pilot.lucidfabrics.com">Website</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#the-safety-model">Safety model</a> ·
  <a href="https://pilot.lucidfabrics.com/privacy">Privacy</a>
</p>

<p align="center">
  <img alt="Licence" src="https://img.shields.io/badge/code-MIT-green">
  <img alt="Chrome Web Store" src="https://img.shields.io/badge/Chrome_Web_Store-in_review-orange">
  <img alt="Version" src="https://img.shields.io/badge/version-1.1.0-blue">
  <img alt="Works with" src="https://img.shields.io/badge/works_with-Claude_Code_·_Hermes-8A2BE2">
</p>

![Watch your AI drive Chrome: glowing border, real cursor, timestamped toasts](.github/media/hero.png)

Claude Code and Hermes can already browse for you. LucidPilot makes that
visible and keeps it under your control:

- **You see everything.** A glowing border marks the driven tab, a real cursor
  glides to every target, and a timestamped toast names each action as it lands.
- **You stay in charge.** Browser control starts locked. The agent can never
  unlock it. You authorize a session, and one command revokes it mid-flight.
- **You can prove it.** A local audit log keeps the last 500 actions,
  written by the extension itself, so a web page cannot fake the record.

It drives the Chrome profile you are already signed into, over the Chrome
DevTools Protocol. Not a headless copy, no separate browser.

## Quickstart

Three steps. Each one tells you what success looks like.

### 1. Install the Chrome extension

Install from the
[Chrome Web Store](https://chromewebstore.google.com/detail/bfebfknclgjglelmlocldhnjkpngelfl)
(listing in review - it goes live at that link the moment Google approves it).

> **You'll know it worked** when a new LucidPilot icon appears in your toolbar.
> Click it any time for the session log, the test-drive demo, and health checks.

The extension installs free and does nothing until a licence is activated -
neither the overlay nor the tools. Licences are $2.99/mo or $19.99/yr at
[pilot.lucidfabrics.com](https://pilot.lucidfabrics.com), 3 devices each,
14-day refund, no questions asked. Your key arrives by email; paste it into
the extension popup.

### 2. Connect your agent

**Claude Code:**

```
/plugin marketplace add lucid-fabrics/lucidpilot
/plugin install lucidpilot@lucidpilot
```

**Or Hermes:**

```
hermes plugins install https://github.com/lucid-fabrics/lucidpilot.git
hermes gateway restart
```

Requires `python3` on PATH and nothing else - no pip packages.

Both commands install straight from
[GitHub releases](https://github.com/lucid-fabrics/lucidpilot/releases) -
each tag publishes the two plugin zips plus `SHA256SUMS` there for an offline
or air-gapped install. That repo ships the plugins only: the Chrome extension
itself is Chrome-Web-Store-only, never bundled into a plugin download.

> **You'll know it worked** when you restart your agent and `/lp status`
> (Claude Code namespaces it as `/lucidpilot:lp`, autocomplete finds it from
> `/lp`) reports the extension connected.

Approve the `lucidpilot_command` permission prompt when it appears - but do
NOT add `my_browser_authorize` to an always-allow list: approving each
authorization individually is the human gate that keeps the agent from
unlocking browser control on its own.

### 3. Authorize a session

![Locked until you say go: authorize, watch, revoke](.github/media/authorize.png)

```
/lp authorize            # 8 hours, auto-locking after 60 min idle
/lp authorize 60m        # or a shorter window
/lp authorize indefinite # until /lp revoke, no idle lock (alias: yolo)
```

> **You'll know it worked** when your agent's next browser action paints a
> glowing border around the tab and a toast names the move.

To skip typing this every session, set a standing grant in your environment:

```
LUCIDPILOT_AUTO_AUTHORIZE=8h         # every new session starts authorized for 8h
LUCIDPILOT_AUTO_AUTHORIZE=indefinite # no clocks at all, same as authorize indefinite
```

Setting the env var IS the human consent (same power-user opt-out as
`indefinite`); the agent still cannot grant itself anything. The auto-grant is
an ordinary grant - hard cap and idle lock still apply unless `indefinite` -
and it never extends a window that is already running.

### Making LucidPilot the default browser tool

Once authorized, LucidPilot steps in front of rival browser tools
(claude-in-chrome, chrome-devtools, hermes-chrome-plugin's chrome_*) so your
agent drives your real Chrome instead of a separate, signed-out one. This is
on by default. To turn it off:

```
/lp default off  # leave rival browser tools alone
/lp default on   # back to redirecting them to my_browser_*
```

## What you get

One licence unlocks everything - both halves, both integrations.

| The overlay | The control engine |
|---|---|
| Glowing border on the driven tab | 21 `my_browser_*` tools over CDP |
| A real cursor that glides, then marks what it hit | Click, type, fill, scroll, drag, upload |
| Action toasts, color-coded per agent | Navigate, wait, launch |
| Local session log: 500 actions, timestamped | Snapshot, screenshot, find, inspect |
| Red alert border on flagged sensitive domains | Console and network inspection |

![Every action logged locally: 500 entries, timestamped, never leaves your device](.github/media/audit-log.png)

The log never records what was typed, only that typing happened. It never
leaves your device: no analytics, no telemetry. The only network calls are
checkout and a daily licence check
([privacy policy](https://pilot.lucidfabrics.com/privacy)).

## The safety model

- **Locked until a human says otherwise.** Sessions are time-boxed (8 hours,
  auto-locking after 60 minutes idle) and the agent can never authorize itself.
- **One command ends it.** `/lp revoke` locks the tools instantly, mid-session.
- **The log is written by the extension.** A page can fake the overlay. It
  cannot fake the log.
- **A submit/buy/pay click pauses for you first.** Clicking something that
  resolves to a submit button, or a label like "Buy Now", "Place Order",
  "Pay Now", or "Checkout", shows an on-page approve/deny prompt before the
  click fires - not just an overlay you watch, one that can stop the click.
  It denies by default: click Deny, or don't answer, and nothing happens.

### What it does not do

The parts a demo will not tell you:

- The overlay itself cannot stop an agent - it's a window, not a lock. The
  submit/buy/pay pause above is the one real exception, and only when the
  agent resolved a specific element (a selector or a snapshot uid); a bare
  coordinate click skips it.
- Sensitive domains are a build-time list, not a settings screen.
- Chrome on the desktop only. No Edge, no Brave, no mobile.
- It drives the browser you are signed into. That is the point, and the risk.

<details>
<summary><b>Coexistence with hermes-chrome-plugin</b></summary>

LucidPilot is a fork-and-rename of hermes-chrome-plugin's connector, built to
run side by side with an existing hermes-chrome-plugin install on the same
machine, not replace it:

| | hermes-chrome-plugin | LucidPilot |
|---|---|---|
| Bridge port | 16319 | 16329 (`LUCIDPILOT_BRIDGE_PORT`) |
| Tool prefix | `chrome_*` | `my_browser_*` |
| Slash command | `/chrome` | `/lp` |
| Extension | its own, separate id | its own, separate id (pinned via manifest key) |

If both plugins are installed, the `control_tools` config knob decides
whether `my_browser_*` registers at all:

```yaml
# ~/.hermes/config.yaml
lucidpilot:
  control_tools: auto   # auto (default) | always | never
```

(or `LUCIDPILOT_CONTROL_TOOLS=auto|always|never`, env wins over config).
`auto` skips registering `my_browser_*` and `/lp` when hermes-chrome-plugin
looks installed, so one session doesn't end up with two near-identical sets
of browser-control tools. `indicator_*` always registers regardless, it's
cosmetic and has nothing to double up on.

With `always`, both tool sets register at once. When that happens, LucidPilot
denies `chrome_*` calls in favor of `my_browser_*` under the same conditions
as the "default browser tool" behavior above (licensed, authorized,
connected) - `/lp default off` turns it off here too.

</details>

<details>
<summary><b>How it's put together</b></summary>

The Chrome extension itself (MV3: overlay content script, session log popup,
and the connector that polls the bridge) ships through the Chrome Web Store;
this repo holds the two agent plugins that drive it:

```
bridge.py            loopback HTTP server on 127.0.0.1:16329, queues/delivers
                     commands between a Hermes/Claude Code session and the
                     extension's service worker
auth.py               Chrome-control gate: locked by default, /lp authorize
                     grants a time-boxed (or indefinite) window
licensing.py          Pro license gate: reads the verdict the extension
                     asserts to the bridge
chrome_tools.py       the 21 my_browser_* tool handlers (gated on auth + license)
indicator_tools.py    the 6 indicator_* tools (cosmetic, licence-gated)
commands.py           the /lp slash command
mcp_server.py         MCP stdio server: the same tools + /lp for Claude Code
redirect_policy.py    shared policy: which rival tools redirect to
                     my_browser_*, and the /lp default on|off preference
pretooluse_hook.py    Claude Code's PreToolUse hook entry point (Claude Code only)
plugin.yaml, __init__.py   Hermes plugin entry point (repo root)
```

The extension talks to `bridge.py` the same way hermes-chrome-plugin's own
extension talks to its own bridge: long-poll `/next` for a queued command,
`POST /result` to answer it. `GET /status` folds in auth and license state so
the popup's health panel and `/lp doctor` read one source of truth.

Licence keys live only in the extension popup, which re-checks online about
once a day; `bridge.py` verifies the server-signed session token the
extension forwards, so a tampered extension cannot vouch for itself. The
licence check is stdlib-only (`ed25519_verify.py`) - no pip packages.

</details>

<details>
<summary><b>Running the plugin tests</b></summary>

```bash
python3 -m pytest tests/python/
```

</details>

## Licence

The code in this repo is [MIT](LICENSE). The product is licence-gated at
runtime: the extension and tools activate with a key from
[pilot.lucidfabrics.com](https://pilot.lucidfabrics.com). One activation
covers both Claude Code and Hermes on up to 3 devices, with a 14-day
no-questions refund.

Built by [Lucid Fabrics](https://pilot.lucidfabrics.com). Support:
[support@lucidfabrics.com](mailto:support@lucidfabrics.com).
