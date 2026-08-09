"""summarize_action_result: the one line an agent reads to learn what its
click actually did.

Loaded by path, same approach as the other suites here - formatters.py sits at
the repo root and has no relative imports, so importlib avoids depending on
how pytest happens to have set sys.path.
"""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

spec = importlib.util.spec_from_file_location("formatters_under_test", REPO_ROOT / "formatters.py")
assert spec and spec.loader
formatters = importlib.util.module_from_spec(spec)
sys.modules["formatters_under_test"] = formatters
spec.loader.exec_module(formatters)

class TestActionEffectsSummary:
    """glue.js's layer 6 attaches observed effects and a coordinate hit report
    to every interaction result. Both were computed and then dropped on the
    floor here, so the agent saw a bare "Clicked el-7" and could not tell a
    real click from one that landed on a spinner."""

    def test_zero_mutations_is_stated_plainly(self):
        summary = formatters.summarize_action_result({"effects": {"mutations": 0}})
        assert summary == "changed nothing on the page"

    def test_navigation_wins_over_the_mutation_count(self):
        summary = formatters.summarize_action_result(
            {"effects": {"mutations": 12, "navigated": "https://example.com/next"}}
        )
        assert summary == "navigated to https://example.com/next"

    def test_a_working_click_stays_quiet(self):
        assert formatters.summarize_action_result({"effects": {"mutations": 5}}) is None

    def test_observed_effects_replace_the_coarse_heuristic(self):
        """Both present: the real observation should not be doubled up with
        upstream's hedged guess."""
        summary = formatters.summarize_action_result({"effects": {"mutations": 3}, "pageMutated": False})
        assert summary is None

    def test_coordinate_clicks_report_what_they_hit(self):
        summary = formatters.summarize_action_result(
            {"hit": {"tag": "button", "id": "buy", "text": "Buy now"}}
        )
        assert summary == 'landed on <button#buy> "Buy now"'
