"""Keeps the test suite out of the developer's real LucidPilot state.

auth.py and licensing.py both persist to ``~/.hermes/lucidpilot`` (overridable
via LUCIDPILOT_LICENSE_DIR) and both read that env var at IMPORT time, so the
redirect has to happen here, at conftest import, before any test module pulls
them in.

This exists because of a real incident: auth.py gained persistence, and
test_bridge_authorize_endpoint.py - which posts {"minutes": "indefinite"} to a
real ChromeAuth - promptly wrote an indefinite Chrome-control grant into the
developer's actual home directory. A test run must never change what the
product is allowed to do on the machine running it.
"""

from __future__ import annotations

import os
import tempfile

# Leaked deliberately (never cleaned up): the OS reaps its own temp dir, and
# tearing it down at session end would race modules that captured the path at
# import time.
_TEST_STATE_DIR = tempfile.mkdtemp(prefix="lucidpilot-test-state-")
os.environ["LUCIDPILOT_LICENSE_DIR"] = _TEST_STATE_DIR

# Same reasoning for the bridge port: an accidental bind to the real 16329
# would fight a live session on the developer's machine.
os.environ.setdefault("LUCIDPILOT_BRIDGE_PORT", "16399")

# A developer's standing auto-authorize grant (LUCIDPILOT_AUTO_AUTHORIZE in
# their shell) would silently pre-authorize every ChromeAuth the tests build,
# turning locked-by-default assertions into false failures. Tests that want
# the auto-grant set the var themselves via monkeypatch.
os.environ.pop("LUCIDPILOT_AUTO_AUTHORIZE", None)

# Session-wide test signing keypair for licence session tokens. Set here so
# every in-process bridge AND every mcp_server subprocess (which inherits a
# copy of os.environ) verifies against the same test key instead of the baked
# prod pin. ed25519_sign owns the keypair (module-level, one instance per
# run); importing it before setting the env keeps the two in lockstep.
from ed25519_sign import SESSION_PUBKEY_B64  # noqa: E402

os.environ["LUCIDPILOT_LICENSE_PUBKEY"] = SESSION_PUBKEY_B64
