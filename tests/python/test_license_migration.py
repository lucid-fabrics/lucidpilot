"""The legacy-key migration: pre-popup-era installs hold a key in
~/.hermes/lucidpilot/license.json. bridge.migrate_legacy_key() hands it to the
extension EXACTLY ONCE (a license.adopt command over the normal /next//result
channel) and deletes the local copy only after the extension confirms
activation. This is the path most likely to be silently broken (per the task),
so it gets its own file.

Loader: same synthetic-package trick as test_security_drills.py's
load_bridge_module_as_package - migrate_legacy_key does `from . import
licensing`, which needs a parent package to resolve.
"""

from __future__ import annotations

import http.client
import importlib
import importlib.util
import json
import sys
import threading
import time
import types
from pathlib import Path

import pytest

import ed25519_sign

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_pkg():
    pkg_name = "license_migration_pkg_under_test"
    for name in list(sys.modules):
        if name == pkg_name or name.startswith(pkg_name + "."):
            sys.modules.pop(name, None)
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = [str(REPO_ROOT)]
    sys.modules[pkg_name] = pkg
    spec = importlib.util.spec_from_file_location(f"{pkg_name}.bridge", REPO_ROOT / "bridge.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"{pkg_name}.bridge"] = module
    spec.loader.exec_module(module)
    licensing_module = importlib.import_module(f"{pkg_name}.licensing")
    return module, licensing_module


@pytest.fixture
def migration_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LUCIDPILOT_LICENSE_DIR", str(tmp_path))
    bridge_module, licensing_module = load_pkg()
    # The env var is read at licensing import time - repoint the loaded module
    # directly so the fixture works regardless of import-time environment.
    licensing_module._STATE_DIR = str(tmp_path)
    licensing_module._STATE_FILE = str(tmp_path / "license.json")
    bridge = bridge_module.ChromeProfileBridge(host="127.0.0.1", port=0)
    bridge.ensure_started()
    assert bridge._mode == "server"
    port = bridge._httpd.server_address[1]
    yield bridge, port, bridge_module, licensing_module, tmp_path
    bridge.stop()


LEGACY_KEY = "LUCIDPILOT-PR-legacy-payload.legacy-sig"


def write_legacy_state(tmp_path: Path) -> None:
    (tmp_path / "license.json").write_text(
        json.dumps({"license_key": LEGACY_KEY, "machine_id": "legacy-m", "locked": False}),
        encoding="utf-8",
    )


def _request(port: int, method: str, path: str, headers: dict, body: bytes | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read().decode() or "{}")
    finally:
        conn.close()


def _extension_loop(bridge_module, port: int, adopt_result: dict, seen: list, stop: threading.Event) -> None:
    """Plays the real extension: polls /next with the pinned origin, answers
    license.adopt with `adopt_result` via POST /result."""
    origin = f"chrome-extension://{bridge_module._DEV_EXTENSION_ID}"
    while not stop.is_set():
        try:
            status, payload = _request(port, "GET", "/next", {"origin": origin})
        except OSError:
            return
        if payload.get("type") != "command":
            continue
        command = payload["command"]
        seen.append(command)
        body = json.dumps({"id": command["id"], "ok": True, "result": adopt_result}).encode()
        _request(port, "POST", "/result", {"origin": origin, "content-type": "application/json"}, body=body)


def _run_migration_against_extension(bridge, bridge_module, port, adopt_result):
    seen: list = []
    stop = threading.Event()
    ext = threading.Thread(
        target=_extension_loop, args=(bridge_module, port, adopt_result, seen, stop), daemon=True
    )
    ext.start()
    try:
        message = bridge.migrate_legacy_key(timeout_ms=5_000)
    finally:
        stop.set()
    return message, seen


def test_migration_hands_key_over_exactly_once_then_forgets(migration_env):
    bridge, port, bridge_module, licensing_module, tmp_path = migration_env
    write_legacy_state(tmp_path)
    assert licensing_module.legacy_license_key() == LEGACY_KEY

    message, seen = _run_migration_against_extension(bridge, bridge_module, port, {"ok": True, "tier": "PRO"})

    assert message is not None and "handed to the extension" in message
    assert len(seen) == 1, f"expected exactly one hand-over command, saw {len(seen)}"
    assert seen[0]["action"] == "license.adopt"
    assert seen[0]["params"] == {"key": LEGACY_KEY}
    # The local copy is gone - the extension is now the only key holder.
    assert licensing_module.legacy_license_key() is None
    assert not (tmp_path / "license.json").exists()

    # Second run (the "next session start"): nothing to migrate, no command.
    message2, seen2 = _run_migration_against_extension(bridge, bridge_module, port, {"ok": True})
    assert message2 is None
    assert seen2 == []


def test_migration_keeps_key_when_extension_declines(migration_env):
    bridge, port, bridge_module, licensing_module, tmp_path = migration_env
    write_legacy_state(tmp_path)

    message, seen = _run_migration_against_extension(
        bridge, bridge_module, port, {"ok": False, "error": "Rejected (HTTP 404)"}
    )

    assert message is not None and "declined" in message
    assert len(seen) == 1
    # Keep the key: a failed hand-over must be retryable next session.
    assert licensing_module.legacy_license_key() == LEGACY_KEY


def test_migration_keeps_key_when_extension_never_polls(migration_env):
    bridge, _port, _bridge_module, licensing_module, tmp_path = migration_env
    write_legacy_state(tmp_path)

    message = bridge.migrate_legacy_key(timeout_ms=200)  # nobody polling

    assert message is not None and "hand-over failed" in message
    assert licensing_module.legacy_license_key() == LEGACY_KEY


def test_migration_deletes_redundant_key_when_already_licensed(migration_env):
    """The extension already has a licence (asserted on its polls): the local
    copy is dead weight and must go WITHOUT a hand-over command."""
    bridge, _port, _bridge_module, licensing_module, tmp_path = migration_env
    write_legacy_state(tmp_path)
    bridge.note_license_assertion(ed25519_sign.valid_assert())

    message = bridge.migrate_legacy_key(timeout_ms=200)

    assert message is not None and "already licensed" in message
    assert licensing_module.legacy_license_key() is None
    assert bridge._queue == []


def test_migration_noop_without_legacy_key(migration_env):
    bridge, _port, _bridge_module, _licensing_module, _tmp_path = migration_env
    assert bridge.migrate_legacy_key(timeout_ms=200) is None
    assert bridge._queue == []


def test_migration_noop_in_client_mode(migration_env, tmp_path):
    """A client session must leave migration to the port owner - two sessions
    both handing the key over would race the delete."""
    bridge, _port, bridge_module, _licensing_module, state_dir = migration_env
    write_legacy_state(state_dir)
    client = bridge_module.ChromeProfileBridge(host="127.0.0.1", port=bridge.port)
    client._mode = "client"
    assert client.migrate_legacy_key(timeout_ms=200) is None
