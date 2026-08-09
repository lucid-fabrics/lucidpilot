"""ChromeAuth's two clocks: the hard cap (default 8h) and the 1h idle lock.

Time is driven by monkeypatching auth.time.time - no sleeps, no flakes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# auth.py has no intra-package imports, so a direct file load is safe here
# (unlike the full-package loaders other test files need).
import importlib.util

_spec = importlib.util.spec_from_file_location("browser_auth_under_test", REPO_ROOT / "auth.py")
assert _spec is not None and _spec.loader is not None
auth_mod = importlib.util.module_from_spec(_spec)
sys.modules["browser_auth_under_test"] = auth_mod
_spec.loader.exec_module(auth_mod)

ChromeAuth = auth_mod.ChromeAuth
ChromeAuthError = auth_mod.ChromeAuthError
IDLE_LOCK_S = auth_mod.IDLE_LOCK_S


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Never read or write the developer's real ~/.hermes/lucidpilot/auth.json."""
    monkeypatch.setattr(auth_mod, "_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(auth_mod, "_STATE_FILE", str(tmp_path / "auth.json"))


@pytest.fixture
def clock(monkeypatch):
    """Controllable clock for auth_mod.time.time."""
    state = {"now": 1_000_000.0}
    monkeypatch.setattr(auth_mod.time, "time", lambda: state["now"])

    def advance(seconds: float) -> None:
        state["now"] += seconds

    return advance


def test_default_grant_is_8_hours(clock):
    a = ChromeAuth()
    msg = a.authorize()
    assert "8 hours" in msg
    assert a.is_authorized()


def test_idle_lock_after_an_hour_of_inactivity(clock):
    a = ChromeAuth()
    a.authorize()
    clock(IDLE_LOCK_S + 1)
    assert not a.is_authorized()
    assert a.summary() == "locked"
    with pytest.raises(ChromeAuthError):
        a.require_authorized()


def test_active_use_keeps_the_idle_clock_wound(clock):
    a = ChromeAuth()
    a.authorize()
    # Simulate an agent driving for 3 hours with a call every 30 minutes -
    # each require_authorized() stamps last-use, so it never idle-locks.
    for _ in range(6):
        clock(1800)
        a.require_authorized()
    assert a.is_authorized()


def test_hard_cap_expires_even_with_constant_activity(clock):
    a = ChromeAuth()
    a.authorize()
    # Constant activity (stamp every 30min) can never outlive the 8h cap.
    for _ in range(16):
        clock(1800)
        try:
            a.require_authorized()
        except ChromeAuthError:
            break
    clock(1)
    assert not a.is_authorized()


def test_indefinite_skips_both_clocks(clock):
    a = ChromeAuth()
    msg = a.authorize("indefinite")
    assert "indefinitely" in msg
    clock(30 * 24 * 3600)  # a month of total inactivity
    assert a.is_authorized()
    assert a.authorized_until() == "indefinite"


def test_authorized_until_reports_deadline_and_lazy_expires(clock):
    a = ChromeAuth()
    a.authorize("30m")
    until = a.authorized_until()
    assert isinstance(until, float)
    assert until - auth_mod.time.time() == pytest.approx(1800)
    clock(1801)
    assert a.authorized_until() is None


def test_authorized_until_is_none_after_idle_lock(clock):
    a = ChromeAuth()
    a.authorize()  # 8h cap
    clock(IDLE_LOCK_S + 1)  # idle-locked long before the cap
    assert a.authorized_until() is None


def test_revoke_locks_immediately(clock):
    a = ChromeAuth()
    a.authorize("indefinite")
    a.revoke()
    assert not a.is_authorized()
    assert a.authorized_until() is None


def test_hour_suffix_and_bad_duration(clock):
    a = ChromeAuth()
    assert "2 hours" in a.authorize("2h")
    assert "Unknown authorize duration" in a.authorize("soon")
    # The failed parse must not have clobbered the existing grant.
    assert a.is_authorized()


# ---------------------------------------------------------------------------
# Persistence across processes. A new ChromeAuth() stands in for a restarted
# agent: same on-disk state, fresh object, no shared memory.
# ---------------------------------------------------------------------------

def test_grant_survives_a_restart(clock):
    ChromeAuth().authorize()  # the human authorizes once...
    assert ChromeAuth().is_authorized(), "a restart must not drop a live grant"


def test_restored_grant_keeps_its_original_deadline(clock):
    ChromeAuth().authorize("2h")
    clock(3600)  # an hour passes, agent restarts
    restored = ChromeAuth()
    assert restored.is_authorized()
    remaining = restored.authorized_until() - auth_mod.time.time()
    assert remaining == pytest.approx(3600), "restart must not restart the clock"


def test_expired_grant_is_not_restored(clock):
    ChromeAuth().authorize("30m")
    clock(1801)
    assert not ChromeAuth().is_authorized()


def test_idle_locked_grant_is_not_restored(clock):
    ChromeAuth().authorize()  # 8h cap, but...
    clock(IDLE_LOCK_S + 1)  # ...untouched for over an hour
    assert not ChromeAuth().is_authorized(), "idle lock must survive a restart too"


def test_revoke_is_visible_to_other_processes(clock):
    ChromeAuth().authorize("indefinite")
    ChromeAuth().revoke()
    assert not ChromeAuth().is_authorized(), "revoke must lock every process, not just this one"


def test_indefinite_survives_a_restart(clock):
    ChromeAuth().authorize("indefinite")
    clock(30 * 24 * 3600)
    assert ChromeAuth().is_authorized()


def test_corrupt_state_file_fails_closed(clock):
    ChromeAuth().authorize()
    with open(auth_mod._STATE_FILE, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    assert not ChromeAuth().is_authorized()


def test_unwritable_state_dir_still_authorizes_in_memory(clock, monkeypatch):
    """Losing persistence must never break authorizing outright."""
    monkeypatch.setattr(auth_mod, "_STATE_DIR", "/proc/nonexistent/nope")
    monkeypatch.setattr(auth_mod, "_STATE_FILE", "/proc/nonexistent/nope/auth.json")
    a = ChromeAuth()
    a.authorize()
    assert a.is_authorized()


# ---------------------------------------------------------------------------
# LUCIDPILOT_AUTO_AUTHORIZE: standing consent that unlocks fresh sessions.
# ---------------------------------------------------------------------------

def test_auto_authorize_env_grants_at_construction(clock, monkeypatch):
    monkeypatch.setenv("LUCIDPILOT_AUTO_AUTHORIZE", "8h")
    assert ChromeAuth().is_authorized()


def test_auto_authorize_truthy_value_uses_default_window(clock, monkeypatch):
    monkeypatch.setenv("LUCIDPILOT_AUTO_AUTHORIZE", "1")
    a = ChromeAuth()
    assert a.is_authorized()
    remaining = a.authorized_until() - auth_mod.time.time()
    assert remaining == pytest.approx(480 * 60)


def test_auto_authorize_grant_still_idle_locks(clock, monkeypatch):
    monkeypatch.setenv("LUCIDPILOT_AUTO_AUTHORIZE", "8h")
    a = ChromeAuth()
    clock(IDLE_LOCK_S + 1)
    assert not a.is_authorized()
    # ...but the next session (fresh construction) re-grants.
    assert ChromeAuth().is_authorized()


def test_auto_authorize_indefinite_skips_clocks(clock, monkeypatch):
    monkeypatch.setenv("LUCIDPILOT_AUTO_AUTHORIZE", "indefinite")
    a = ChromeAuth()
    clock(30 * 24 * 3600)
    assert a.is_authorized()


def test_auto_authorize_bad_or_falsy_values_grant_nothing(clock, monkeypatch):
    for value in ("soon", "0", "false", "off", "  "):
        monkeypatch.setenv("LUCIDPILOT_AUTO_AUTHORIZE", value)
        assert not ChromeAuth().is_authorized(), value


def test_auto_authorize_never_extends_a_live_grant(clock, monkeypatch):
    ChromeAuth().authorize("30m")
    clock(600)
    monkeypatch.setenv("LUCIDPILOT_AUTO_AUTHORIZE", "8h")
    remaining = ChromeAuth().authorized_until() - auth_mod.time.time()
    assert remaining == pytest.approx(1200), "restored grant keeps its own deadline"


# ---------------------------------------------------------------------------
# The command name differs per host; printing the wrong one sends users to a
# command that does not exist ("Unknown command: /lp").
# ---------------------------------------------------------------------------

def _with_agent(monkeypatch, agent: str) -> None:
    """Point auth.command_hint's lazy `from .bridge import AGENT` at a stub.

    auth.py is loaded here standalone (no real package), so the relative import
    would otherwise raise and silently take the "hermes" fallback - which would
    make the hermes assertion below pass for the wrong reason.
    """
    import sys
    import types

    fake = types.ModuleType("fake_bridge")
    fake.AGENT = agent
    monkeypatch.setitem(sys.modules, "browser_auth_under_test.bridge", fake)
    monkeypatch.setattr(auth_mod, "__package__", "browser_auth_under_test", raising=False)


def test_command_hint_is_namespaced_for_claude_code(monkeypatch):
    _with_agent(monkeypatch, "claude")
    assert auth_mod.command_hint("license") == "/lucidpilot:lp license"


def test_command_hint_is_bare_for_hermes(monkeypatch):
    _with_agent(monkeypatch, "hermes")
    assert auth_mod.command_hint("license") == "/lp license"


def test_command_hint_stub_is_actually_consulted(monkeypatch):
    """Guards the two tests above: proves the stub drives the result, so
    "hermes" passing is a real branch and not the import-failure fallback."""
    _with_agent(monkeypatch, "totally-made-up-host")
    assert auth_mod.command_hint() == "/lp"  # any non-claude host -> bare
    _with_agent(monkeypatch, "claude")
    assert auth_mod.command_hint() == "/lucidpilot:lp"
