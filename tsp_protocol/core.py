"""
tsp_protocol.core
==================
Core geometric and semantic logic for TSP v0.1 (Ternary Semantic Packet).
Implements the phi mapping onto S^3, the chordal distance metric, packet
creation/validation, canonical JSON serialization, and an in-memory
semantic cache with O(1) triple lookup (SPEC.md §2-4).

`TSPCore` is kept as a thin backward-compatible wrapper around the
module-level functions for code written against the earlier class-based
API (see README.md "Quickstart"). New code should prefer the top-level
functions directly (see README.md "Citation" / __init__.py exports).
"""
import copy
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

VALID_ACT = {"query", "store", "align", "verify"}

# SECURITY.md "Best Practices" names two distinct thresholds — a looser one
# for cache-hit matching and a tighter one for semantic verification — but no
# prior version of this module defined either as code. Values match
# SECURITY.md verbatim. NOTE: EPS_VERIFY_DEFAULT is not yet consumed by any
# verify-path function below; verify_packet() only checks vec<->s structural
# integrity, not semantic closeness to a reference. Wiring "verify"/"align"
# acts to an actual eps-based semantic check is an open design question.
EPS_CACHE_DEFAULT = 0.65
EPS_VERIFY_DEFAULT = 0.30

# ── Precomputed lookup: all 27 (I, C, O) -> S3 unit vectors ─────────────────
# SPEC.md §2: no runtime floating-point computation is required for mapping.
_LOOKUP: Dict[Tuple[int, int, int], List[float]] = {}
for _I in (-1, 0, 1):
    for _C in (-1, 0, 1):
        for _O in (-1, 0, 1):
            _v = np.array([1.0, _I, _C, _O], dtype=np.float64)
            _LOOKUP[(_I, _C, _O)] = np.round(_v / np.linalg.norm(_v), 6).tolist()

_TRIPLES: List[Tuple[int, int, int]] = list(_LOOKUP.keys())
_VECTORS = np.array([_LOOKUP[t] for t in _TRIPLES], dtype=np.float64)
_DIST_MATRIX = np.linalg.norm(_VECTORS[:, None, :] - _VECTORS[None, :, :], axis=-1)
_TRIPLE_INDEX: Dict[Tuple[int, int, int], int] = {t: i for i, t in enumerate(_TRIPLES)}


# ── phi mapping (SPEC.md §2) ─────────────────────────────────────────────────

def phi_canonical(s) -> List[float]:
    """
    Official phi mapping: (I, C, O) -> S3 unit vector.
    v = (1, I, C, O) / ||(1, I, C, O)||, rounded to 6 decimal places (SPEC §2.2).
    """
    key = tuple(int(x) for x in s)
    if key in _LOOKUP:
        return _LOOKUP[key].copy()
    v = np.array([1.0, s[0], s[1], s[2]], dtype=np.float64)
    return np.round(v / np.linalg.norm(v), 6).tolist()


def vec_to_s(vec: List[float]) -> Tuple[int, int, int]:
    """Inverse mapping: S3 vector -> (I, C, O) ternary triple."""
    return tuple(int(np.sign(x)) for x in vec[1:])


def verify_vec(s, vec: List[float], tol: float = 1e-5) -> bool:
    """Verify that vec matches the official phi mapping of s within tolerance."""
    expected = np.array(phi_canonical(s))
    return bool(np.allclose(np.array(vec), expected, atol=tol))


def chordal_distance(u: List[float], v: List[float]) -> float:
    """Chordal Distance on S3 (SPEC §3.1): d_c(u, v) = ||u - v||_2."""
    return float(np.linalg.norm(np.array(u) - np.array(v)))


# alias kept for compatibility with earlier drafts that used this name
chordal_dist = chordal_distance


# ── Canonical JSON (SPEC.md §5.1, RFC 8785 approximation) ───────────────────

def canonical_json(data: Dict[str, Any]) -> bytes:
    """Sorted-key, whitespace-free, UTF-8 JSON — used as the HMAC signing input."""
    return json.dumps(
        data, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


# ── Packet creation / validation (SPEC.md §4) ────────────────────────────────

def make_packet(
    s,
    act: str = "query",
    eps: float = EPS_CACHE_DEFAULT,
    profile: str = "sta-v0.1",
    lang_src: Optional[str] = None,
    lang_tgt: Optional[str] = None,
    origin: Optional[str] = "none",
    text_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a compliant TSP v0.1 packet.

    s   : ternary triple (I, C, O), each value in {-1, 0, 1}
    act : one of "query" / "store" / "align" / "verify"
    lang_src / lang_tgt : optional source/target language codes; if either is
                          given, the packet gets an optional `lang` object
                          (present in README's example packet but previously
                          unsupported here).
    text_hash : optional content key, stored as meta.text_hash. The triple
                encodes *how* a request is phrased (intent/register/operation),
                not *what* it is about, so a cache needs this to tell two
                different requests with the same triple apart. (Present in the
                original tests/tsp_v01.py implementation; restored here after
                being dropped in the earlier consolidation.)
    """
    if act not in VALID_ACT:
        raise ValueError(f"act must be one of {VALID_ACT}, got {act!r}")
    if not all(x in (-1, 0, 1) for x in s):
        raise ValueError(f"s values must be in {{-1, 0, 1}}, got {s}")

    pkt: Dict[str, Any] = {
        "tsp": "0.1",
        "id": str(uuid.uuid4()),
        "t": int(time.time()),
        "act": act,
        "s": list(s),
        "vec": phi_canonical(s),
        "control": {"eps": eps, "profile": profile},
        "origin": origin,
        "sig": "none",
    }
    if lang_src or lang_tgt:
        pkt["lang"] = {k: v for k, v in [("src", lang_src), ("tgt", lang_tgt)] if v}
    if text_hash:
        pkt.setdefault("meta", {})["text_hash"] = text_hash
    return pkt


def verify_packet(
    pkt: Dict[str, Any],
    atol: float = 1e-5,
    unit_norm_tol: float = 1e-4,
) -> Tuple[bool, str]:
    """
    Validate a TSP v0.1 packet: s field, vec field, s<->vec consistency
    (s is canonical per SPEC §2.2), unit norm, and act enum.
    Returns (ok, reason).
    """
    s = pkt.get("s")
    vec = pkt.get("vec")

    if not isinstance(s, list) or len(s) != 3:
        return False, "s field invalid: must be list of 3"
    if not isinstance(vec, list) or len(vec) != 4:
        return False, "vec field invalid: must be list of 4"
    if not all(x in (-1, 0, 1) for x in s):
        return False, "s values must be in {-1, 0, 1}"

    expected = np.array(phi_canonical(tuple(s)))
    actual = np.array(vec)

    if not np.allclose(actual, expected, atol=atol):
        diff = float(np.linalg.norm(actual - expected))
        return False, f"vec mismatch (diff={diff:.6f}); s takes precedence"

    if abs(float(np.linalg.norm(actual)) - 1.0) > unit_norm_tol:
        return False, f"vec not unit vector (norm={np.linalg.norm(actual):.6f})"

    if pkt.get("act") not in VALID_ACT:
        return False, f"invalid act: {pkt.get('act')!r}"

    return True, "ok"


def verify_integrity(packet: Dict[str, Any]) -> bool:
    """Boolean-only integrity check, kept for TSPCore backward compatibility."""
    ok, _ = verify_packet(packet)
    return ok


# ── Semantic cache (O(1) chordal-distance lookup) ────────────────────────────

class SemanticCache:
    """
    In-memory semantic cache over the 27-point ternary lattice.

    Entries are keyed by (content_key, triple). A lookup only ever compares
    against entries with the *same* content_key, so it inspects at most 27
    candidates — genuinely O(1), unlike the previous version, which scanned
    every stored entry.

    content_key=None reproduces the old behavior (triple-only key). That mode
    is kept for backward compatibility but is semantically unsafe: every
    request with triple (1, 0, -1) — "summarize this, technical register" —
    would share a single cached answer regardless of what is being
    summarized. See tsp_protocol.semantics for the analysis.

    Matching: by default a chordal-distance threshold `eps` (SPEC §3.2). A
    `matcher(query_triple, cached_triple) -> bool` may be passed instead, e.g.
    a policy selected by tsp_protocol.dream from replayed logs.
    Eviction: TTL expiry first, then lowest hit-count (LRU approximation).
    """

    def __init__(self, max_entries: int = 1000, ttl: float = 86400,
                 matcher=None) -> None:
        self.max_entries = max_entries
        self.ttl = ttl
        self.matcher = matcher
        # content_key -> {triple -> entry}
        self._store: Dict[Any, Dict[Tuple[int, int, int], Dict[str, Any]]] = {}
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def _evict(self) -> None:
        now = time.time()
        victim, victim_hits = None, None
        for ck, bucket in self._store.items():
            for t, e in bucket.items():
                if now - e["ts"] > self.ttl:
                    victim = (ck, t)
                    break
                if victim_hits is None or e["hits"] < victim_hits:
                    victim, victim_hits = (ck, t), e["hits"]
            else:
                continue
            break
        if victim is not None:
            self._remove(*victim)

    def _remove(self, ck, t) -> None:
        bucket = self._store.get(ck)
        if bucket and t in bucket:
            del bucket[t]
            self._size -= 1
            if not bucket:
                del self._store[ck]

    def put(self, triple: Tuple[int, int, int], result: Any,
            content_key: Any = None) -> None:
        """Store a result under (content_key, triple)."""
        t = tuple(int(x) for x in triple)
        bucket = self._store.get(content_key)
        if not (bucket and t in bucket) and self._size >= self.max_entries:
            self._evict()
            bucket = self._store.get(content_key)
        if bucket is None:
            bucket = self._store[content_key] = {}
        if t not in bucket:
            self._size += 1
        bucket[t] = {"triple": t, "result": result, "hits": 1, "ts": time.time()}

    def get(self, triple: Tuple[int, int, int], eps: float = EPS_CACHE_DEFAULT,
            content_key: Any = None) -> Optional[Any]:
        """Return the closest matching cached result for this content, or None."""
        q = tuple(int(x) for x in triple)
        idx_q = _TRIPLE_INDEX.get(q)
        bucket = self._store.get(content_key)
        if idx_q is None or not bucket:
            return None

        now = time.time()
        best_dist, best_t = float("inf"), None
        for t, entry in list(bucket.items()):
            if now - entry["ts"] > self.ttl:
                self._remove(content_key, t)
                continue
            d = _DIST_MATRIX[idx_q, _TRIPLE_INDEX[t]]
            ok = self.matcher(q, t) if self.matcher is not None else d <= eps
            if ok and d < best_dist:
                best_dist, best_t = d, t

        if best_t is None:
            return None
        entry = self._store[content_key][best_t]
        entry["hits"] += 1
        return entry["result"]


# ── Backward-compatible OOP wrapper ──────────────────────────────────────────

class TSPCore:
    """
    Backward-compatible wrapper around the module-level functions above.
    Prefer make_packet / verify_packet / phi_canonical directly in new code.
    """

    phi_map = staticmethod(phi_canonical)
    chordal_distance = staticmethod(chordal_distance)

    @staticmethod
    def create_packet(s: list, act: str = "query", origin: str = "none", eps: float = EPS_CACHE_DEFAULT) -> dict:
        return make_packet(s, act=act, eps=eps, origin=origin)

    @staticmethod
    def verify_integrity(packet: dict) -> bool:
        return verify_integrity(packet)
