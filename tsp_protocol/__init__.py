# tsp_protocol/__init__.py
from .core import (
    make_packet,
    verify_packet,
    verify_integrity,
    phi_canonical,
    vec_to_s,
    verify_vec,
    chordal_distance,
    canonical_json,
    SemanticCache,
    TSPCore,
    VALID_ACT,
    EPS_CACHE_DEFAULT,
    EPS_VERIFY_DEFAULT,
)
from .security import (
    sign_packet,
    verify_hmac,
    compute_hmac,
    TSPSecurity,
)

__all__ = [
    "make_packet", "verify_packet", "verify_integrity",
    "phi_canonical", "vec_to_s", "verify_vec", "chordal_distance", "canonical_json",
    "SemanticCache", "TSPCore",
    "sign_packet", "verify_hmac", "compute_hmac", "TSPSecurity",
    "VALID_ACT", "EPS_CACHE_DEFAULT", "EPS_VERIFY_DEFAULT",
]

__version__ = "0.1.0"
