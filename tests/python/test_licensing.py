"""Pytest coverage for licensing.py's licence gate, post key-storage removal:
the Python side never stores or verifies a key anymore - it reads the
extension's assertion out of bridge state (in-process in server mode, GET
/status with a short memo in client mode) and fails closed otherwise. See
loader note in test_bridge_conflict_detection.py - same by-path importlib
approach here (licensing.py has no unconditional relative imports, so this is
safe).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_licensing_module():
    for name in list(sys.modules):
        if name == "licensing_under_test":
            sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("licensing_under_test", REPO_ROOT / "licensing.py")
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["licensing_under_test"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeServerBridge:
    """Duck-types the two members licensing._server_bridge cares about plus
    license_fields(), mirroring bridge.ChromeProfileBridge's contract."""

    def __init__(self, fields):
        self._mode = "server"
        self._fields = fields

    def license_fields(self):
        return dict(self._fields)


@pytest.fixture
def lic(tmp_path):
    """Fresh module instance per test, legacy state file redirected to a tmp
    dir (never touches ~/.hermes/lucidpilot/license.json), memo cleared."""
    module = load_licensing_module()
    module._STATE_DIR = str(tmp_path)
    module._STATE_FILE = str(tmp_path / "license.json")
    module.invalidate_status_cache()
    return module


# 1. Server mode, fresh valid assertion -> licensed.
def test_server_mode_fresh_valid_assertion_is_licensed(lic):
    fields = {"licensed": True, "tier": "PRO", "licenseAssertedAt": time.time(),
              "licenseTokenState": "ok", "licenseAssertedValid": True}
    with mock.patch.object(lic, "_server_bridge", return_value=FakeServerBridge(fields)):
        assert lic.is_pro_licensed() is True
        assert "PRO" in lic.license_status_summary()
        assert "server-signed token verified" in lic.license_status_summary()
        lic.require_pro_licensed()  # must not raise


# 1b. Licensed by an OWNER process that predates signed tokens (client mode,
# /status has no licenseTokenState). Still licensed - the owner decided - but
# the summary must not claim a verification this process never performed.
def test_summary_does_not_claim_verification_it_did_not_do(lic):
    stale_owner = {"licensed": True, "tier": "PRO", "licenseAssertedAt": time.time()}
    with mock.patch.object(lic, "_server_bridge", return_value=None), \
         mock.patch.object(lic, "_fetch_owner_status", return_value=stale_owner):
        lic.invalidate_status_cache()
        assert lic.is_pro_licensed() is True
        summary = lic.license_status_summary()
        assert "server-signed token verified" not in summary
        assert "owns the bridge" in summary


# 2. Server mode, extension asserted invalid -> not licensed, message points
# at the popup (a present-but-unlicensed extension is a missing KEY, not a
# missing extension).
def test_server_mode_invalid_assertion_points_at_popup(lic):
    fields = {"licensed": False, "tier": None, "licenseAssertedAt": time.time()}
    with mock.patch.object(lic, "_server_bridge", return_value=FakeServerBridge(fields)):
        assert lic.is_pro_licensed() is False
        with pytest.raises(lic.LicenseRequiredError) as err:
            lic.require_pro_licensed()
        assert "popup" in str(err.value)
        assert lic.PURCHASE_URL in str(err.value)


# 3. No assertion at all (bridge running, extension silent) -> not licensed,
# and the message names THAT cause, not a missing key.
def test_no_assertion_names_the_silent_extension(lic):
    fields = {"licensed": False, "tier": None, "licenseAssertedAt": None}
    with mock.patch.object(lic, "_server_bridge", return_value=FakeServerBridge(fields)):
        assert lic.is_pro_licensed() is False
        with pytest.raises(lic.LicenseRequiredError) as err:
            lic.require_pro_licensed()
        assert "not reported a licence recently" in str(err.value)
        assert "not reported" in lic.license_status_summary()


# 3b. Extension claims a licence it cannot prove (valid:true, token not ok -
# a pre-token extension build, a tampered one, or one offline past the token
# life). The message must say update/reconnect, not "buy a key".
def test_unproven_assertion_points_at_extension_update(lic):
    for token_state in ("missing", "invalid", "expired"):
        fields = {
            "licensed": False,
            "tier": "PRO",
            "licenseAssertedAt": time.time(),
            "licenseTokenState": token_state,
            "licenseAssertedValid": True,
        }
        with mock.patch.object(lic, "_server_bridge", return_value=FakeServerBridge(fields)):
            assert lic.is_pro_licensed() is False
            with pytest.raises(lic.LicenseRequiredError) as err:
                lic.require_pro_licensed()
            assert "could not prove" in str(err.value)
            assert "refresh icon" in str(err.value)
            assert lic.PURCHASE_URL not in str(err.value)
            assert token_state in lic.license_status_summary()


# 3c. A pre-token OWNER process (client mode, /status has no token fields):
# the generic messaging applies - never the update-extension branch, which
# would mislead (the extension may be fine; the owning plugin is old).
def test_old_owner_status_without_token_fields_stays_generic(lic):
    stale_owner = {"licensed": False, "tier": None, "licenseAssertedAt": time.time()}
    with mock.patch.object(lic, "_server_bridge", return_value=None), \
         mock.patch.object(lic, "_fetch_owner_status", return_value=stale_owner):
        lic.invalidate_status_cache()
        with pytest.raises(lic.LicenseRequiredError) as err:
            lic.require_pro_licensed()
        assert "popup" in str(err.value)


# 4. Client mode (no in-process server): verdict comes from the owner's GET
# /status, fail closed when it is unreachable.
def test_client_mode_reads_owner_status_and_fails_closed(lic):
    with mock.patch.object(lic, "_server_bridge", return_value=None):
        with mock.patch.object(lic, "_fetch_owner_status", return_value=None):
            lic.invalidate_status_cache()
            assert lic.is_pro_licensed() is False

        fresh = {"licensed": True, "tier": "PRO", "licenseAssertedAt": time.time()}
        with mock.patch.object(lic, "_fetch_owner_status", return_value=fresh):
            lic.invalidate_status_cache()
            assert lic.is_pro_licensed() is True


# 5. Client-mode memo: repeated checks within the memo TTL hit the owner
# exactly once; invalidate_status_cache() forces a refetch (this is what the
# licence-change push relies on to make a flip visible immediately).
def test_client_mode_memoizes_and_invalidate_forces_refetch(lic):
    fresh = {"licensed": True, "tier": "PRO", "licenseAssertedAt": time.time()}
    with mock.patch.object(lic, "_server_bridge", return_value=None), \
         mock.patch.object(lic, "_fetch_owner_status", return_value=fresh) as fetch:
        lic.invalidate_status_cache()
        for _ in range(10):
            assert lic.is_pro_licensed() is True
        assert fetch.call_count == 1

        lic.invalidate_status_cache()
        assert lic.is_pro_licensed() is True
        assert fetch.call_count == 2


# 6. Legacy key helpers: read exactly what the old activate_license stored,
# forget deletes the file, both tolerate absence.
def test_legacy_key_read_and_forget(lic, tmp_path):
    assert lic.legacy_license_key() is None

    (tmp_path / "license.json").write_text(
        json.dumps({"license_key": "LUCIDPILOT-PR-payload.sig", "machine_id": "m1", "locked": False}),
        encoding="utf-8",
    )
    assert lic.legacy_license_key() == "LUCIDPILOT-PR-payload.sig"

    lic.forget_legacy_license_key()
    assert lic.legacy_license_key() is None
    assert not (tmp_path / "license.json").exists()
    lic.forget_legacy_license_key()  # idempotent

    # Garbage on disk reads as "no key", never raises.
    (tmp_path / "license.json").write_text("{not json", encoding="utf-8")
    assert lic.legacy_license_key() is None


# 7. The module never talks to the licence API and never stores a key: the
# whole point of the inversion. Source-level guard so a rebuilt key path
# can't sneak back in quietly.
def test_licensing_module_holds_no_key_machinery():
    src = (REPO_ROOT / "licensing.py").read_text(encoding="utf-8")
    for gone in (
        "def activate_license",
        "def verify_license_signature",
        "from cryptography",
        "import cryptography",
        "api/licenses/verify",
    ):
        assert gone not in src, f"key machinery came back: {gone}"


# 8. indicator_* is licence-gated too - LucidPilot has no free tier. The
# overlay goes through the same gate as everything else, at both layers -
# check_fn for visibility, require_pro_licensed() at runtime.
def test_indicator_tools_is_license_gated_at_both_layers():
    src = (REPO_ROOT / "indicator_tools.py").read_text(encoding="utf-8")
    assert "from .licensing import is_pro_licensed, require_pro_licensed" in src
    assert "require_pro_licensed()" in src, "runtime gate missing"
    assert "check_fn=_licensed" in src, "visibility gate missing"
