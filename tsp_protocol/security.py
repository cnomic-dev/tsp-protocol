"""
tsp_protocol.security
======================
HMAC-SHA256 integrity/signature layer for TSP v0.1 (SPEC.md §5.1).

Signs and verifies over the Canonical JSON representation of a fixed set
of payload fields, excluding `sig` itself. Verification is fail-open for
v0.1, per SECURITY.md "Known Security Characteristics -> Fail-Open Behavior":
an unsigned packet ("sig": "none") or an unrecognized signature scheme is
accepted (with a reason string saying so), not rejected — only a *wrong*
hmac-sha256 signature fails. This is a documented, deliberate v0.1 design
choice ("to avoid blocking legitimate traffic during early adoption"), not
a placeholder — SECURITY.md itself calls out the corresponding risk and
mitigations (app-layer trust scoring/rate limiting; log fail-open events;
a future fail-secure mode).

TSPSecurity.verify_signature previously rejected "none"/unknown signatures
outright, which contradicted this policy. It now delegates to verify_hmac
so both entry points agree; see its docstring for the resulting behavior
change.
"""
import copy
import hashlib
import hmac
from typing import Any, Dict, Tuple

from .core import canonical_json

# Fields covered by the HMAC (payload only — 'sig' and 'origin' excluded so
# attribution/signature can be layered on independently).
_HMAC_FIELDS = ["act", "control", "id", "s", "t", "vec", "lang"]


def _hmac_payload(pkt: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the canonical payload fields covered by the signature."""
    return {k: pkt[k] for k in _HMAC_FIELDS if k in pkt}


def compute_hmac(pkt: Dict[str, Any], secret: str) -> str:
    """Compute HMAC-SHA256 over the canonical payload. Returns 'hmac-sha256:<hex>'."""
    msg = canonical_json(_hmac_payload(pkt))
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def sign_packet(pkt: Dict[str, Any], secret: str) -> Dict[str, Any]:
    """Return a copy of pkt with the HMAC-SHA256 `sig` field populated."""
    signed = copy.deepcopy(pkt)
    signed["sig"] = compute_hmac(pkt, secret)
    return signed


def verify_hmac(pkt: Dict[str, Any], secret: str, sig: str) -> Tuple[bool, str]:
    """
    Verify an HMAC-SHA256 signature (fail-open, see module docstring).
    Returns (ok, reason).
    """
    if sig == "none":
        return True, "no signature (fail-open)"
    if not sig.startswith("hmac-sha256:"):
        return True, f"unknown sig format — fail-open: {sig[:30]}"
    expected = compute_hmac(pkt, secret)
    if sig == expected:
        return True, "signature valid"
    return False, "signature mismatch"


# ── Backward-compatible OOP wrapper ──────────────────────────────────────────

class TSPSecurity:
    """
    Backward-compatible wrapper around the module-level functions above.
    Prefer sign_packet / verify_hmac directly in new code.

    BEHAVIOR CHANGE: verify_signature now delegates to verify_hmac and is
    therefore fail-open for "none" or an unrecognized sig scheme, matching
    SECURITY.md's documented v0.1 policy. The prior draft returned False
    for both cases instead — fail-closed — which no other part of the spec,
    tests, or SECURITY.md agreed with. If any caller relied on that
    fail-closed behavior (e.g. gating on "has a valid signature"), check
    `packet.get("sig", "none").startswith("hmac-sha256:")` explicitly rather
    than this method.
    """

    to_canonical_json = staticmethod(canonical_json)
    sign_packet = staticmethod(sign_packet)

    @staticmethod
    def verify_signature(packet: Dict[str, Any], secret_key: str) -> bool:
        ok, _ = verify_hmac(packet, secret_key, packet.get("sig", "none"))
        return ok
