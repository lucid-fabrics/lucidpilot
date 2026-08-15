---
description: Control the LucidPilot browser bridge (status/doctor/onboard/background/default/license/revoke)
argument-hint: status|doctor|onboard|background [on|off]|default|license <key>|revoke
disable-model-invocation: true
allowed-tools:
  - mcp__plugin_lucidpilot_lucidpilot__lucidpilot_command
  - mcp__plugin_lucidpilot_lucidpilot__my_browser_authorize
---

The user ran `/lp $ARGUMENTS`.

- If the first word of the arguments is `revoke` (or `authorize`, kept only so the tool can explain it is gone), call the `my_browser_authorize` MCP tool with the full argument string. The user typing this command IS the explicit request that tool requires.
- Otherwise call the `lucidpilot_command` MCP tool with the argument string verbatim (empty arguments are fine - the tool returns help).

Relay the tool's returned text to the user exactly as-is. Do not paraphrase it, do not retry on error, and do not call any other tool.
