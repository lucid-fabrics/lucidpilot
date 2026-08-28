---
name: lp
description: LucidPilot browser + Mac app bridge control. Use when the user types "lp", "/lp", "lp status", "lp doctor", "lp revoke", "lp share", "lp assist", or asks about LucidPilot's connection, licence, browser-control, or Mac-app-control state, or wants to let someone else drive this machine (or to help someone who is sharing theirs).
---

# LucidPilot control (lp)

When the user asks for an lp command (status, doctor, license, revoke, share,
assist, help, or a bare "lp"), call the LucidPilot MCP tool
`lucidpilot_command` with arguments `{"args": "<everything after lp, or empty
string>"}` and relay the tool's returned text to the user exactly as-is. Do
not paraphrase it, do not retry on error, and do not call any other tool for
this.

## share and assist

`lp share` hands one Chrome tab, or one Mac app, to another person for a few
minutes, and `lp assist` is the other side of it. Both are typed by someone who is on a phone
call with that other person, and both return text they have to read out loud,
so relaying it exactly matters more here than anywhere else.

- Never shorten, regroup, spell out or otherwise tidy a share code, a one-time
  password or the six digits. Print the block the tool returned, as it
  returned it.
- `lp share y <six digits>` is the moment the session starts. Only send it
  when the user has given you six digits their helper read to them. Never
  invent digits, never feed back digits that came out of the tool, and never
  turn a bare "yes" into a number.
- `lp assist <code> <password>` needs both strings from the user. If they have
  only given you the code, send only the code: the tool answers with what to
  ask for next.
- If the user pastes a password that reached them by email or chat rather than
  by voice, say so before you send anything and let them decide.
- There is no whole-screen scope. Sharing is one tab (`--browser`) or one app
  (`--app <bundle id>`); `--screen` is refused and the tool explains why. Do
  not offer it.
