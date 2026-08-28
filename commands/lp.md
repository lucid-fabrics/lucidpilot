---
description: Control the LucidPilot browser + Mac app bridge (status/doctor/onboard/background/default/license/revoke/share/assist)
argument-hint: status|doctor|onboard|background [on|off]|default|license <key>|revoke|share [--browser|--app <bundle id>]|assist <code> <password>
disable-model-invocation: true
allowed-tools:
  - mcp__plugin_lucidpilot_lucidpilot__lucidpilot_command
  - mcp__plugin_lucidpilot_lucidpilot__my_browser_authorize
---

The user ran `/lp $ARGUMENTS`.

- If the first word of the arguments is `revoke` (or `authorize`, kept only so the tool can explain it is gone), call the `my_browser_authorize` MCP tool with the full argument string. The user typing this command IS the explicit request that tool requires.
- Otherwise call the `lucidpilot_command` MCP tool with the argument string verbatim (empty arguments are fine - the tool returns help).

Relay the tool's returned text to the user exactly as-is. Do not paraphrase it, do not retry on error, and do not call any other tool.

## share and assist

`share` hands one Chrome tab, or one Mac app, to another person for a few minutes, and `assist` is the other side of it. Both are typed by someone who is on a phone call with that other person, and both return text they have to read out loud, so relaying it exactly matters more here than anywhere else.

- Never shorten, regroup, spell out or otherwise tidy a share code, a one-time password or the six digits. Print the block the tool returned, as it returned it.
- `share y <six digits>` is the moment the session starts. Only send it when the user has given you six digits their helper read to them. Never invent digits, never feed back digits that came out of the tool, and never turn a bare "yes" into a number.
- `assist <code> <password>` needs both strings from the user. If they have only given you the code, send only the code: the tool answers with what to ask for next.
- If the user pastes a password that reached them by email or chat rather than by voice, say so before you send anything and let them decide.
- There is no whole-screen scope. Sharing is one tab (`--browser`) or one app (`--app <bundle id>`); `--screen` is refused and the tool explains why. Do not offer it.
