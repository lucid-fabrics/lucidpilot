---
name: lp
description: LucidPilot browser-bridge control. Use when the user types "lp", "/lp", "lp status", "lp doctor", "lp revoke", or asks about LucidPilot's connection, licence, or browser-control state.
---

# LucidPilot control (lp)

When the user asks for an lp command (status, doctor, license, revoke, help,
or a bare "lp"), call the LucidPilot MCP tool `lucidpilot_command` with
arguments `{"args": "<everything after lp, or empty string>"}` and relay the
tool's returned text to the user exactly as-is. Do not paraphrase it, do not
retry on error, and do not call any other tool for this.
