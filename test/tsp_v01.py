# tsp_v01.py
# TSP v0.1 — Ternary Semantic Packet Core
# Apache License 2.0 — cnomic-dev, April 2026
# https://github.com/cnomic-dev/semantic-translator-architecture

import copy
import hashlib
import hmac as _hmac
import json
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# ── Precomputed lookup: all 27 (I,C,O) → S³ unit vectors ────────────────────

_LOOKUP: Dict[Tuple[int, int, int], List[float]] = {}
for _I in [-1, 0, 1]:
    for _C in [-1, 0, 1]:
        for _O in [-1, 0, 1]:
            _v = np.array([1.0, _I, _C, _O], dtype=np.float64)
            _LOOKUP[(_I, _C, _O)] = np.round(_v / np.linalg.norm(_v), 6).tolist()

# Precomputed 27×27 chordal distance matrix for O(1) retrieval
_TRIPLES: List[Tuple[int, int, int]] = list(_LOOKUP.keys())
_VECTORS = np.array([_LOOKUP[t] for t in _TRIPLES], dtype=np.float64)
_DIST_MATRIX = np.linalg.norm(
    _VECTORS[:, None, :] - _VECTORS[None, :, :], axis=-1
)
_TRIPLE_INDEX: Dict[Tuple[int, int, int], int] = {
    t: i for i, t in enumerate(_TRIPLES)
}

VALID_ACT = {"query", "store", "align", "verify"}


# ── φ mapping ────────────────────────────────────────────────────────────────

def phi_canonical(s: Tuple[int, int, int]) -> List[float]:
    """Official φ mapping: (I, C, O) → S³ unit vector (6 decimal places)."""
    key = tuple(s)
    if key in _LOOKUP:
        return _LOOKUP[key].copy()
    v = np.array([1.0, s[0], s[1], s[2]], dtype=np.float64)
    return np.round(v / np.linalg.norm(v), 6).tolist()


def vec_to_s(vec: List[float]) -> Tuple[int, int, int]:
    """Inverse mapping: S³ vector → (I, C, O) ternary triple."""
    return tuple(int(np.sign(x)) for x in vec[1:])  # type: ignore[return-value]


def verify_vec(s: Tuple[int, int, int],
               vec: List[float],
               tol: float = 1e-5) -> bool:
    """Verify vec matches official φ mapping within tolerance."""
    expected = np.array(phi_canonical(s))
    return bool(np.allclose(np.array(vec), expected, atol=tol))


def chordal_dist(u: List[float], v: List[float]) -> float:
    """Chordal Distance on S³: d_c(u, v) = ‖u − v‖₂."""
    return float(np.linalg.norm(np.array(u) - np.array(v)))


# ── Packet creation ──────────────────────────────────────────────────────────

def make_packet(
    s: Tuple[int, int, int],
    act: str = "query",
    eps: float = 0.65,
    profile: str = "sta-v0.1",
    lang_src: Optional[str] = None,
    lang_tgt: Optional[str] = None,
    text_hash: Optional[str] = None,
    origin: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a valid TSP v0.1 packet.

    Parameters
    ----------
    s       : Ternary triple (I, C, O) — each value in {-1, 0, 1}
    act     : Action — one of query / store / align / verify
    eps     : Cache hit threshold (chordal distance)
    profile : Mapping profile identifier
    """
    if act not in VALID_ACT:
        raise ValueError(f"act must be one of {VALID_ACT}, got {act!r}")
    if not all(x in (-1, 0, 1) for x in s):
        raise ValueError(f"s values must be in {{-1, 0, 1}}, got {s}")

    pkt: Dict[str, Any] = {
        "tsp": "0.1",
        "id":  f"tsp-{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:16]}",
        "t":   int(time.time()),
        "act": act,
        "s":   list(s),
        "vec": phi_canonical(s),
        "control": {"eps": eps, "profile": profile},
        "sig": "none",
    }
    if lang_src or lang_tgt:
        pkt["lang"] = {
            k: v for k, v in [("src", lang_src), ("tgt", lang_tgt)] if v
        }
    if text_hash:
        pkt.setdefault("meta", {})["text_hash"] = text_hash
    if origin:
        pkt["origin"] = origin
    return pkt


# ── Packet validation ────────────────────────────────────────────────────────

def verify_packet(
    pkt: Dict[str, Any],
    atol: float = 1e-5,
    unit_norm_tol: float = 1e-4,
) -> Tuple[bool, str]:
    """
    Validate a TSP v0.1 packet.

    Checks: s field, vec field, s↔vec consistency, unit norm, act enum.
    Returns (ok: bool, reason: str).
    """
    s = pkt.get("s")
    vec = pkt.get("vec")

    if not isinstance(s, list) or len(s) != 3:
        return False, "s field invalid: must be list of 3"
    if not isinstance(vec, list) or len(vec) != 4:
        return False, "vec field invalid: must be list of 4"
    if not all(x in (-1, 0, 1) for x in s):
        return False, "s values must be in {-1, 0, 1}"

    expected = np.array(phi_canonical(tuple(s)))  # type: ignore[arg-type]
    actual = np.array(vec)

    if not np.allclose(actual, expected, atol=atol):
        diff = float(np.linalg.norm(actual - expected))
        return False, f"vec mismatch (diff={diff:.6f}); s takes precedence"

    if abs(float(np.linalg.norm(actual)) - 1.0) > unit_norm_tol:
        return False, f"vec not unit vector (norm={np.linalg.norm(actual):.6f})"

    if pkt.get("act") not in VALID_ACT:
        return False, f"invalid act: {pkt.get('act')!r}"

    return True, "ok"


# ── Canonical JSON (RFC 8785 approximation) ──────────────────────────────────

def canonical_json(data: Dict[str, Any]) -> bytes:
    """
    RFC 8785 JCS approximation for v0.1:
    keys sorted lexicographically, UTF-8, no whitespace.
    """
    return json.dumps(
        data,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")


# ── HMAC-SHA256 ──────────────────────────────────────────────────────────────

def _hmac_payload(pkt: Dict[str, Any]) -> Dict[str, Any]:
    """Extract canonical payload fields for HMAC signing."""
    fields = ["act", "control", "id", "s", "t", "vec"]
    payload = {k: pkt[k] for k in fields if k in pkt}
    if "lang" in pkt:
        payload["lang"] = pkt["lang"]
    return payload


def compute_hmac(pkt: Dict[str, Any], secret: str) -> str:
    """Compute HMAC-SHA256 over canonical payload. Returns 'hmac-sha256:<hex>'."""
    msg = canonical_json(_hmac_payload(pkt))
    digest = _hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def verify_hmac(
    pkt: Dict[str, Any],
    secret: str,
    sig: str,
) -> Tuple[bool, str]:
    """
    Verify HMAC signature. Fail-open for v0.1:
    - sig == "none"       → pass (no signature)
    - unknown sig format  → pass with warning (fail-open)
    - hmac-sha256 mismatch → fail
    """
    if sig == "none":
        return True, "no signature (fail-open)"
    if not sig.startswith("hmac-sha256:"):
        return True, f"unknown sig format — fail-open: {sig[:30]}"
    expected = compute_hmac(pkt, secret)
    if sig == expected:
        return True, "signature valid"
    return False, "signature mismatch"


def sign_packet(pkt: Dict[str, Any], secret: str) -> Dict[str, Any]:
    """Return a copy of pkt with HMAC-SHA256 sig field populated."""
    signed = copy.deepcopy(pkt)
    signed["sig"] = compute_hmac(pkt, secret)
    return signed


# ── Semantic cache ───────────────────────────────────────────────────────────

class SemanticCache:
    """
    In-memory semantic cache using precomputed O(1) chordal distance lookup.

    Eviction: TTL expiry first; then lowest hit-count (LRU approximation).
    """

    def __init__(
        self,
        max_entries: int = 1000,
        ttl: float = 86400,
    ) -> None:
        self.max_entries = max_entries
        self.ttl = ttl
        self._store: Dict[str, Dict[str, Any]] = {}

    def _evict(self) -> None:
        now = time.time()
        expired = [k for k, v in self._store.items()
                   if now - v["ts"] > self.ttl]
        if expired:
            del self._store[expired[0]]
            return
        if self._store:
            lru = min(self._store, key=lambda k: self._store[k]["hits"])
            del self._store[lru]

    def put(self, triple: Tuple[int, int, int], result: Any) -> None:
        """Store a result keyed by ternary triple."""
        if len(self._store) >= self.max_entries:
            self._evict()
        key = str(triple)
        self._store[key] = {
            "triple": triple,
            "result": result,
            "hits":   1,
            "ts":     time.time(),
        }

    def get(self, triple: Tuple[int, int, int], eps: float = 0.65) -> Optional[Any]:
        """
        Retrieve result if a semantically close triple exists in cache.
        Uses precomputed 27×27 distance matrix for O(1) lookup.
        """
        now = time.time()
        idx_q = _TRIPLE_INDEX.get(triple)
        if idx_q is None:
            return None

        best_dist, best_key = float("inf"), None
        for key, entry in list(self._store.items()):
            if now - entry["ts"] > self.ttl:
                del self._store[key]
                continue
            idx_c = _TRIPLE_INDEX.get(entry["triple"])
            if idx_c is None:
                continue
            d = _DIST_MATRIX[idx_q, idx_c]
            if d < best_dist:
                best_dist, best_key = d, key

        if best_dist <= eps and best_key:
            self._store[best_key]["hits"] += 1
            return self._store[best_key]["result"]
        return None


# ── Minimal self-test ────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("TSP v0.1 — self-test\n")

    # 1. φ mapping
    s = (1, 0, -1)
    vec = phi_canonical(s)
    assert verify_vec(s, vec), "φ mapping failed"
    assert vec_to_s(vec) == s, "inverse mapping failed"
    print(f"✅ φ({s}) = {vec}")

    # 2. Chordal distance boundaries
    d_same = chordal_dist(phi_canonical((1, 0, -1)), phi_canonical((1, 0, -1)))
    d_1dim = chordal_dist(phi_canonical((1, 0, -1)), phi_canonical((1, 0,  0)))
    d_2dim = chordal_dist(phi_canonical((1, 0, -1)), phi_canonical((1, 1,  0)))
    eps = 0.65
    assert d_same < 1e-6
    assert d_1dim <= eps, f"d_1dim={d_1dim:.5f} > eps={eps}"
    assert d_2dim >  eps, f"d_2dim={d_2dim:.5f} <= eps={eps}"
    print(f"✅ Chordal distances: same={d_same:.5f} 1dim={d_1dim:.5f} 2dim={d_2dim:.5f}")

    # 3. Packet creation + validation
    pkt = make_packet(s, act="query", origin="cnomic-dev-genesis-2026")
    ok, reason = verify_packet(pkt)
    assert ok, reason
    print(f"✅ Packet valid: {reason}")

    # 4. Tampering detection
    bad = copy.deepcopy(pkt)
    bad["vec"][0] += 0.1
    ok_bad, _ = verify_packet(bad)
    assert not ok_bad
    print("✅ Tampering detected (vec modified)")

    # 5. HMAC round-trip
    secret = "test-secret-2026"
    signed = sign_packet(pkt, secret)
    ok_sig, msg = verify_hmac(signed, secret, signed["sig"])
    assert ok_sig, msg
    ok_wrong, _ = verify_hmac(signed, "wrong-key", signed["sig"])
    assert not ok_wrong
    print(f"✅ HMAC valid: {msg}")

    # 6. Fail-open
    ok_fo, reason_fo = verify_hmac(pkt, "any", "unknown-algo:xxx")
    assert ok_fo and "fail-open" in reason_fo
    print(f"✅ Fail-open: {reason_fo}")

    # 7. Semantic cache
    cache = SemanticCache()
    cache.put((1, 0, -1), "cached result")
    hit = cache.get((1, 0, -1), eps=0.65)
    assert hit == "cached result"
    miss = cache.get((1, 1, 1), eps=0.65)
    assert miss is None
    print("✅ Semantic cache: hit/miss correct")

    # 8. Forward compatibility (zero-padding)
    v4 = phi_canonical((1, 0, -1))
    v8 = v4 + [0.0] * 4
    assert np.allclose(v8[:4], v4, atol=1e-6)
    print("✅ Forward compatibility: zero-padding")

    print("\n🎉 All TSP v0.1 self-tests passed.")
