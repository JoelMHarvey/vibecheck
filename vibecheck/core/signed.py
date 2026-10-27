"""What the hosted endpoints add to a result: its badge level and the signed
report and badge (unsigned, and marked so, when no key is configured)."""

from __future__ import annotations

from typing import Optional

from . import badge, signing
from .models import CheckResult
from .report import level


def with_signatures(result: CheckResult, signer: Optional[signing.Signer] = None,
                    sign_badge: bool = True) -> dict:
    payload = result.to_dict()
    payload["level"] = level(result)
    signer = signer if signer is not None else signing.load_signer()
    signed = badge.sign_result(result, signer, badge.provenance("server"))
    if not sign_badge:
        # An upload has nothing to pin a badge to (no URL, no commit), so it
        # gets a signed report and no badge.
        signed.pop("badge")
    payload["signed"] = signed
    return payload
