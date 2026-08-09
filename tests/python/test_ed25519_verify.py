"""ed25519_verify.py against RFC 8032 section 7.1 test vectors, plus the
malformed-input contract (return False, never raise) bridge.py relies on."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location("ed25519_verify_under_test", REPO_ROOT / "ed25519_verify.py")
assert _spec is not None and _spec.loader is not None
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


# RFC 8032 section 7.1: (secret is irrelevant here), public key, message, signature.
VECTORS = [
    (  # TEST 1 (empty message)
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (  # TEST 2 (one byte)
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (  # TEST 3 (two bytes)
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


def test_rfc8032_vectors_verify():
    for pk_hex, msg_hex, sig_hex in VECTORS:
        assert ev.verify(bytes.fromhex(pk_hex), bytes.fromhex(msg_hex), bytes.fromhex(sig_hex))


def test_bit_flips_fail():
    pk_hex, msg_hex, sig_hex = VECTORS[2]
    pk, msg, sig = bytes.fromhex(pk_hex), bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
    assert not ev.verify(pk, msg + b"x", sig)
    flipped_sig = bytes([sig[0] ^ 1]) + sig[1:]
    assert not ev.verify(pk, msg, flipped_sig)
    flipped_pk = bytes([pk[0] ^ 1]) + pk[1:]
    assert not ev.verify(flipped_pk, msg, sig)


def test_malformed_inputs_return_false_never_raise():
    pk_hex, msg_hex, sig_hex = VECTORS[2]
    pk, msg, sig = bytes.fromhex(pk_hex), bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
    assert not ev.verify(b"", msg, sig)
    assert not ev.verify(pk[:31], msg, sig)
    assert not ev.verify(pk, msg, b"")
    assert not ev.verify(pk, msg, sig[:63])
    assert not ev.verify(pk, msg, b"\xff" * 64)  # s >= L territory / non-point R
    assert not ev.verify(b"\xff" * 32, msg, sig)  # non-canonical / non-point A
