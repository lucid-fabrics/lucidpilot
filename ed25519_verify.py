"""Vendored pure-Python Ed25519 signature VERIFICATION (RFC 8032).

Exists so bridge.py can check the licensing server's signed session tokens
without reintroducing the `cryptography` pip dependency the plugin
deliberately shed (see licensing.py's module docstring) - install stays
stdlib-only. Verify-only on purpose: the plugin never signs anything; the
test suite has its own signing helper built on this module's internals.

Adapted from the RFC 8032 section 6 reference implementation (public
domain). Deliberately NOT constant-time: that matters for signing with a
secret, not for verifying a public signature.

# ponytail: ~20ms per verify vs microseconds for libsodium - fine at one
# verify per /assert-license push (<=1/min), revisit only if that changes.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
# Group order, RFC 8032 section 5.1.
_L = 2**252 + 27742317777372353535851937790883648493


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


# Points are extended homogeneous coordinates (X, Y, Z, T): x = X/Z, y = Y/Z,
# x*y = T/Z - the representation the RFC reference code uses.
_Point = tuple[int, int, int, int]

_NEUTRAL: _Point = (0, 1, 1, 0)


def _point_add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mult(s: int, p: _Point) -> _Point:
    q = _NEUTRAL
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p: _Point, q: _Point) -> bool:
    # Cross-multiply to compare without dividing by Z.
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    if (p[1] * q[2] - q[1] * p[2]) % _P != 0:
        return False
    return True


def _point_compress(p: _Point) -> bytes:
    zinv = _inv(p[2])
    x = p[0] * zinv % _P
    y = p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes) -> _Point | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_G_Y = 4 * _inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None
_G: _Point = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature of `message` under
    the raw 32-byte `public_key`. Never raises on malformed input."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        a = _point_decompress(public_key)
        if a is None:
            return False
        r_bytes = signature[:32]
        r = _point_decompress(r_bytes)
        if r is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        h = int.from_bytes(_sha512(r_bytes + public_key + message), "little") % _L
        return _point_equal(_point_mult(s, _G), _point_add(r, _point_mult(h, a)))
    except Exception:
        return False
