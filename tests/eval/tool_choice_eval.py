"""Does the model pick the right TOOL FAMILY for a given request?

Tool-selection guidance (the pre_llm_call primer, MCP `instructions`, the
entry-point description prefix) is the one part of this plugin that cannot be
unit-tested: it either shifts a model's choice or it doesn't, and the only
honest way to know is to ask a real model and count. Everything else here is
pinned by pytest; this is the piece that needs a scoreboard.

Runs against a live Hermes session, so it costs real tokens. Not part of the
pytest suite for that reason - run it deliberately, before and after touching
any of the guidance text:

    python3 tests/eval/tool_choice_eval.py                  # score current state
    python3 tests/eval/tool_choice_eval.py --no-primer      # score without it

Each case names the family that SHOULD win. "research" and "sandbox" cases
matter as much as "lucidpilot" ones: guidance that wins every browser task by
dragging research into a browser has made the agent worse, and a scoreboard
that only counted my_browser_* wins would call that a success.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERMES_AGENT = Path.home() / ".hermes" / "hermes-agent"

CASES = [
    # (request, expected family)
    ("open my linkedin profile", "lucidpilot"),
    ("check my gmail inbox for anything from stripe", "lucidpilot"),
    ("go to my github notifications and tell me what's waiting", "lucidpilot"),
    ("open the tab I have open with the pricing page and read it back", "lucidpilot"),
    ("post this comment on the PR I have open in my browser", "lucidpilot"),
    ("log into my bank and check the balance", "lucidpilot"),
    ("find how people structure a monorepo for python and typescript", "research"),
    ("what's the best way to rate-limit a cloudflare worker", "research"),
    ("how do people usually test chrome extensions", "research"),
    ("what does the MCP spec say about the instructions field", "research"),
    ("summarise this blog post: https://example.com/post", "research"),
    ("scrape the titles from this public listing page without touching my session", "sandbox"),
    ("check whether example.com renders correctly for a logged-out visitor", "sandbox"),
]

FAMILIES = {
    "lucidpilot": lambda n: n.startswith("lp_"),
    "research": lambda n: n.startswith(("web_", "x_search")) or n in {"web_search", "web_extract"},
    "sandbox": lambda n: n.startswith("browser_"),
    "other-chrome": lambda n: n.startswith("chrome_"),
}


def family_of(tool_name: str) -> str:
    for family, match in FAMILIES.items():
        if match(tool_name):
            return family
    return "none"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-primer", action="store_true", help="score without the plugin primer")
    parser.add_argument("--json", action="store_true", help="emit raw results as JSON")
    args = parser.parse_args()

    sys.path.insert(0, str(HERMES_AGENT))
    from hermes_cli.plugins import get_plugin_manager  # noqa: E402
    from tools.registry import registry, discover_builtin_tools  # noqa: E402

    discover_builtin_tools()
    pm = get_plugin_manager()
    pm.discover_and_load(force=True)
    tools = registry.all_tools() if hasattr(registry, "all_tools") else registry._tools

    primer = ""
    if not args.no_primer:
        for chunk in pm.invoke_hook("pre_llm_call", is_first_turn=True):
            if isinstance(chunk, dict) and chunk.get("context"):
                primer += chunk["context"] + "\n\n"

    catalogue = "\n".join(
        f"- {name}: {(entry.description or '')[:160]}"
        for name, entry in sorted(tools.items())
        if family_of(name) != "none"
    )

    from agent.plugin_llm import PluginLlm  # noqa: E402

    llm = PluginLlm(plugin_id="lucidpilot-eval")

    results = []
    for request, expected in CASES:
        prompt = (
            f"{primer}"
            "You are choosing ONE tool to start with. Available tools:\n"
            f"{catalogue}\n\n"
            f"User request: {request}\n\n"
            "Answer with the tool name alone, nothing else."
        )
        reply = str(llm.complete(prompt)).strip().split()[0].strip(".,`'\"")
        got = family_of(reply)
        results.append({"request": request, "expected": expected, "tool": reply, "family": got,
                        "ok": got == expected})

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    width = max(len(r["request"]) for r in results)
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"{mark}  {r['request']:<{width}}  want {r['expected']:<11} got {r['family']:<12} ({r['tool']})")
    score = sum(r["ok"] for r in results)
    print(f"\n{score}/{len(results)} correct" + ("  [primer disabled]" if args.no_primer else ""))
    # Non-zero exit when the model would visibly misroute, so this can gate a
    # guidance change without anyone having to eyeball the table.
    return 0 if score == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
