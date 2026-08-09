"""TEST-ONLY Ed25519 signing + session-token minting.

Builds on the vendored ed25519_verify module's curve internals (RFC 8032
section 6 reference signing). Lives in tests/ on purpose: the shipped plugin
must never contain signing code - it only verifies.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import secrets
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location("_ed25519_verify_for_tests", _REPO_ROOT / "ed25519_verify.py")
assert _spec is not None and _spec.loader is not None
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


def _secret_expand(secret: bytes) -> tuple[int, bytes]:
    h = ev._sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def generate_keypair() -> tuple[bytes, bytes]:
    """(secret 32 bytes, public 32 bytes)."""
    secret = secrets.token_bytes(32)
    a, _ = _secret_expand(secret)
    public = ev._point_compress(ev._point_mult(a, ev._G))
    return secret, public


def sign(secret: bytes, message: bytes) -> bytes:
    a, prefix = _secret_expand(secret)
    public = ev._point_compress(ev._point_mult(a, ev._G))
    r = int.from_bytes(ev._sha512(prefix + message), "little") % ev._L
    r_bytes = ev._point_compress(ev._point_mult(r, ev._G))
    h = int.from_bytes(ev._sha512(r_bytes + public + message), "little") % ev._L
    s = (r + h * a) % ev._L
    return r_bytes + int.to_bytes(s, 32, "little")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_token(secret: bytes, **overrides) -> str:
    """A session token in the exact shape the licensing server mints
    (entitlement blob: b64url(payload).b64url(sig))."""
    now = int(time.time())
    payload = {
        "v": 1,
        "kid": "ent-test-1",
        "machineId": "test-machine",
        "productId": "lucidpilot",
        "state": "ACTIVE",
        "tier": "PRO",
        "tierDisplay": "PRO",
        "email": None,
        "maxNodes": 1,
        "maxWorkers": 1,
        "features": {},
        "issuedAt": now,
        "expiresAt": now + 8 * 24 * 3600,
        "revalidateAfter": now + 24 * 3600,
    }
    payload.update(overrides)
    payload_bytes = json.dumps(payload).encode()
    return f"{_b64url(payload_bytes)}.{_b64url(sign(secret, payload_bytes))}"


def pubkey_b64(public: bytes) -> str:
    """The base64 form LUCIDPILOT_LICENSE_PUBKEY expects (raw 32 bytes)."""
    return base64.b64encode(public).decode()


# One keypair per pytest run. conftest.py exports the public half as
# LUCIDPILOT_LICENSE_PUBKEY before any test runs; tests mint matching tokens
# with SESSION_SECRET (directly or via valid_assert below).
SESSION_SECRET, SESSION_PUBKEY = generate_keypair()
SESSION_PUBKEY_B64 = pubkey_b64(SESSION_PUBKEY)


def session_token(**overrides) -> str:
    """A token the suite's pinned test key verifies."""
    return mint_token(SESSION_SECRET, **overrides)


def valid_assert(**assert_overrides) -> str:
    """A complete, provable /assert-license body (JSON string)."""
    body = {"valid": True, "tier": "PRO", "lastCheckAt": 0, "token": session_token()}
    body.update(assert_overrides)
    return json.dumps(body)
