"""Ed25519 (RFC 8032), standard library only.

vibecheck has no dependencies, and verifying a report must work anywhere
the CLI runs. This is the reference algorithm from RFC 8032 §6, checked
against the RFC's test vectors in tests/test_badges.py.

Signing with it is not constant-time. The hosted signer uses the
`cryptography` package when it's installed (it is, on the server: see
requirements.txt) and only falls back to this; verification has no secret
to leak.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

Point = Tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _add(a: Point, b: Point) -> Point:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s: int, point: Point) -> Point:
    q: Point = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            q = _add(q, point)
        point = _add(point, point)
        s >>= 1
    return q


def _equal(a: Point, b: Point) -> bool:
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G: Point = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(point: Point) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, _P - 2, _P)
    x, y = x * zinv % _P, y * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data: bytes) -> Optional[Point]:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _expand(seed: bytes) -> Tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("an Ed25519 secret key is 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _compress(_mul(a, _G))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    A = _compress(_mul(a, _G))
    r = _sha512_int(prefix + message) % _L
    R = _compress(_mul(r, _G))
    h = _sha512_int(R + A + message) % _L
    s = (r + h * a) % _L
    return R + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = _sha512_int(signature[:32] + public + message) % _L
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))
