"""Signed claims: what makes a report or a badge checkable.

A claim is canonical JSON (sorted keys, no spaces, ASCII), signed with
Ed25519 under a short prefix that says what kind of claim it is, so a
report signature can never pass as a badge signature or the reverse.

An envelope is ``{"p": <the canonical JSON string>, "sig": <base64url or
null>, "kid": <key id or null>}``. Verifiers check the signature over the
exact bytes of ``p`` and only then parse it, so no re-serialisation can
make two sides disagree.

The server's key comes from VIBECHECK_SIGNING_KEY (a base64url 32-byte
seed; scripts/make_signing_key.py makes one). Retired public keys stay
verifiable through VIBECHECK_OLD_PUBLIC_KEYS (comma-separated base64url).
Without a key nothing is signed and every claim says so.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Dict, List, Optional

from . import ed25519

REPORT = b"vibecheck/report/1\n"
BADGE = b"vibecheck/badge/1\n"

VERIFIED, TAMPERED, UNKNOWN_KEY, UNSIGNED = "verified", "tampered", "unknown-key", "unsigned"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def key_id(public: bytes) -> str:
    return b64url(hashlib.sha256(public).digest())[:16]


def digest(text: str) -> str:
    """How a badge names the report it was issued for."""
    return b64url(hashlib.sha256(text.encode("utf-8")).digest())


class Signer:
    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("VIBECHECK_SIGNING_KEY must be 32 bytes, base64url")
        self._seed = seed
        self.public = ed25519.public_key(seed)
        self.kid = key_id(self.public)
        self._fast = None
        try:  # constant-time and audited, when it's installed (it is on the server)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            self._fast = Ed25519PrivateKey.from_private_bytes(seed)
        except Exception:
            pass

    def sign(self, prefix: bytes, text: str) -> str:
        message = prefix + text.encode("utf-8")
        sig = self._fast.sign(message) if self._fast is not None else ed25519.sign(self._seed, message)
        return b64url(sig)

    def envelope(self, prefix: bytes, claim: dict) -> dict:
        text = canonical(claim)
        return {"p": text, "sig": self.sign(prefix, text), "kid": self.kid}


def unsigned_envelope(claim: dict) -> dict:
    return {"p": canonical(claim), "sig": None, "kid": None}


def load_signer(env=None) -> Optional[Signer]:
    env = os.environ if env is None else env
    raw = (env.get("VIBECHECK_SIGNING_KEY") or "").strip()
    if not raw:
        return None
    return Signer(unb64url(raw))


def public_keys(env=None, signer: Optional[Signer] = None) -> List[Dict[str, str]]:
    """The keys published at /.well-known/vibecheck-key, current first."""
    env = os.environ if env is None else env
    signer = signer if signer is not None else load_signer(env)
    keys = []
    if signer is not None:
        keys.append({"kid": signer.kid, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
                     "use": "sig", "x": b64url(signer.public), "status": "current"})
    for raw in (env.get("VIBECHECK_OLD_PUBLIC_KEYS") or "").split(","):
        raw = raw.strip()
        if raw:
            pub = unb64url(raw)
            keys.append({"kid": key_id(pub), "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
                         "use": "sig", "x": raw, "status": "retired"})
    return keys


def verify_envelope(envelope: dict, prefix: bytes, keys: List[Dict[str, str]]) -> str:
    """verified / tampered / unknown-key / unsigned. Never raises on bad input."""
    try:
        text, sig, kid = envelope.get("p"), envelope.get("sig"), envelope.get("kid")
        if not isinstance(text, str):
            return TAMPERED
        if not sig:
            return UNSIGNED
        key = next((k for k in keys if k.get("kid") == kid), None)
        if key is None:
            return UNKNOWN_KEY
        ok = ed25519.verify(unb64url(key["x"]), prefix + text.encode("utf-8"), unb64url(sig))
        return VERIFIED if ok else TAMPERED
    except Exception:
        return TAMPERED
