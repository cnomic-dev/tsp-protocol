"""
tsp_protocol.semantics
=======================
The ternary semantic layer of TSP v0.1: what the three coordinates mean,
what the chordal-distance threshold actually does on the 27-point lattice,
and dimension-aware match policies that can say what `eps` cannot.

Three facts about the geometry (all checked by lattice_report(), and by
the tests):

1. `eps` is not a continuous knob. The 27 points have only 13 distinct
   non-zero pairwise distances, so eps behaves as a step function; every eps
   in [0.6058, 0.7654) — including the default 0.65 — gives the same hits.

2. Under the default eps = 0.65 the hit relation is exactly:
       the two triples differ in ONE dimension, by a 0 <-> ±1 step,
       and the sparser triple already has at least one non-zero coordinate.
   Sign flips (-1 <-> +1) never hit; (0,0,0) has no neighbours at all.
   Derivation: going from k to k+1 non-zero coordinates, d^2 = 2 - 2*sqrt((1+k)/(2+k)),
   i.e. d = 0.765 (k=0), 0.606 (k=1), 0.518 (k=2).

3. The metric is blind to *which* dimension changed. Under eps = 0.65,
   (1,0,-1) "instruction / technical / summarize" hits (1,0,0) "instruction /
   technical / translate": a summary would be served for a translation request.
   Whether a change of Context (register) is acceptable while a change of
   Operation is not is a semantic decision the S3 embedding cannot encode.
   DimensionPolicy encodes it explicitly; tsp_protocol.dream chooses between
   such policies from logged traffic.

And one consequence for verification: EPS_VERIFY_DEFAULT = 0.30 is below
the smallest non-zero distance (0.5176), so "verify within eps_verify"
is exactly "s must match exactly". verify_semantic() says so directly.
"""
from dataclasses import dataclass, field
from itertools import combinations, product
from typing import Dict, FrozenSet, List, Tuple

import numpy as np

from .core import _DIST_MATRIX, _TRIPLE_INDEX, _TRIPLES, EPS_VERIFY_DEFAULT

Triple = Tuple[int, int, int]

# ── Locked v0.1 dimension definition (README "Dimension Definition") ───────
DIMENSIONS = ("I", "C", "O")
LABELS: Dict[str, Dict[int, str]] = {
    "I": {-1: "Exploration / Question", 0: "Neutral / Verification", 1: "Instruction / Assertion"},
    "C": {-1: "Casual / Conversational", 0: "Technical / Standard", 1: "Formal / Academic"},
    "O": {-1: "Compression / Summarization", 0: "Translation / Conversion", 1: "Expansion / Generation"},
}


def describe(s) -> Dict[str, str]:
    """Human-readable meaning of a triple, per the locked v0.1 table."""
    t = tuple(int(x) for x in s)
    if len(t) != 3 or any(x not in (-1, 0, 1) for x in t):
        raise ValueError(f"not a ternary triple: {s}")
    return {d: LABELS[d][v] for d, v in zip(DIMENSIONS, t)}


def diff_dims(a, b) -> Tuple[str, ...]:
    """Names of the dimensions in which two triples differ."""
    return tuple(d for d, x, y in zip(DIMENSIONS, a, b) if x != y)


def distance(a, b) -> float:
    """Chordal distance between two lattice triples (precomputed table)."""
    return float(_DIST_MATRIX[_TRIPLE_INDEX[tuple(a)], _TRIPLE_INDEX[tuple(b)]])


# ── Geometry of the eps threshold ─────────────────────────────────────────

def distinct_distances() -> List[float]:
    """The 13 distinct non-zero chordal distances on the lattice, ascending."""
    d = _DIST_MATRIX
    # rounded to 4 dp: vec is stored at 6 dp, so equal exact distances can
    # differ in the 6th place (e.g. 1.414213 vs 1.414214)
    return sorted({round(float(x), 4) for x in d[d > 1e-9]})


def eps_equivalence_classes() -> List[Tuple[float, float]]:
    """
    Half-open eps intervals [lo, hi) inside which the hit relation is constant.
    Any two eps values in the same interval are behaviourally identical.
    """
    edges = [0.0] + distinct_distances() + [float("inf")]
    return list(zip(edges[:-1], edges[1:]))


def neighbours(s, eps: float) -> List[Triple]:
    """Triples (other than s) within chordal distance eps of s."""
    i = _TRIPLE_INDEX[tuple(s)]
    return [t for j, t in enumerate(_TRIPLES) if j != i and _DIST_MATRIX[i, j] <= eps]


def default_eps_rule(a, b) -> bool:
    """
    Closed-form equivalent of `chordal distance <= eps` for any eps in
    [0.6058, 0.7654), including the default 0.65 (fact 2 above).
    """
    if tuple(a) == tuple(b):
        return True
    dims = [k for k in range(3) if a[k] != b[k]]
    if len(dims) != 1:
        return False
    k = dims[0]
    if a[k] != 0 and b[k] != 0:          # sign flip
        return False
    sparser = a if a[k] == 0 else b
    return any(x != 0 for x in sparser)


def lattice_report(eps: float = 0.65) -> Dict[str, object]:
    """Summary of what a given eps does on the 27-point lattice."""
    degree = {t: len(neighbours(t, eps)) for t in _TRIPLES}
    pairs = [(a, b) for a, b in combinations(_TRIPLES, 2) if distance(a, b) <= eps]
    by_dims: Dict[Tuple[str, ...], int] = {}
    for a, b in pairs:
        key = diff_dims(a, b)
        by_dims[key] = by_dims.get(key, 0) + 1
    lo, hi = next((lo, hi) for lo, hi in eps_equivalence_classes() if lo <= eps < hi)
    return {
        "eps": eps,
        "equivalent_eps_interval": (lo, hi),
        "hit_pairs": len(pairs),
        "hit_pairs_by_changed_dimension": by_dims,
        "isolated_triples": [t for t, k in degree.items() if k == 0],
        "max_degree": max(degree.values()),
    }


# ── Verification act semantics ─────────────────────────────────────────────

def verify_semantic(s, reference, eps: float = EPS_VERIFY_DEFAULT) -> Tuple[bool, str]:
    """
    Semantic check for act="verify": is packet triple `s` within eps of
    `reference`? With the SECURITY.md default 0.30 this is exact equality,
    and the reason string says so rather than implying tolerance.
    """
    d = distance(s, reference)
    exact_only = eps < distinct_distances()[0]
    if d <= eps:
        return True, "exact match" if d < 1e-9 else f"within eps (d={d:.4f})"
    note = " (eps below lattice spacing: only exact matches can pass)" if exact_only else ""
    return False, f"d={d:.4f} > eps={eps}{note}"


# ── Dimension-aware match policies ─────────────────────────────────────────

@dataclass(frozen=True)
class DimensionPolicy:
    """
    Explicit ternary match rule: a cached triple may serve a query triple iff
    they differ only in dimensions listed in `may_differ`, in at most
    `max_changes` of them, and (unless `allow_sign_flip`) never by a
    -1 <-> +1 flip. Callable as matcher(query, cached) for SemanticCache.
    """
    may_differ: FrozenSet[str] = field(default_factory=frozenset)
    max_changes: int = 1
    allow_sign_flip: bool = False

    def __call__(self, query, cached) -> bool:
        changed = [k for k in range(3) if query[k] != cached[k]]
        if len(changed) > self.max_changes:
            return False
        for k in changed:
            if DIMENSIONS[k] not in self.may_differ:
                return False
            if not self.allow_sign_flip and query[k] != 0 and cached[k] != 0:
                return False
        return True

    @property
    def name(self) -> str:
        if not self.may_differ:
            return "exact"
        dims = "".join(d for d in DIMENSIONS if d in self.may_differ)
        flip = "+flip" if self.allow_sign_flip else ""
        return f"dims[{dims}]<= {self.max_changes}{flip}"


@dataclass(frozen=True)
class EpsPolicy:
    """The SPEC §3.2 rule, as a matcher: chordal distance <= eps."""
    eps: float

    def __call__(self, query, cached) -> bool:
        return distance(query, cached) <= self.eps

    @property
    def name(self) -> str:
        return f"eps<={self.eps:.4f}"


def candidate_policies() -> List[object]:
    """
    The complete, finite space of ternary match policies considered by
    tsp_protocol.dream: one EpsPolicy per behaviourally distinct eps
    interval (plus eps=0, i.e. exact), and every DimensionPolicy over
    subsets of {I, C, O}. Small enough to enumerate exhaustively.
    """
    pols: List[object] = [EpsPolicy(0.0)]
    # one representative per interval, taken from its interior: the interval
    # edges are rounded, so an edge value itself can fall on the wrong side
    pols += [EpsPolicy(round((lo + hi) / 2, 4) if hi != float("inf") else lo + 0.05)
             for lo, hi in eps_equivalence_classes()[1:]]
    seen = set()
    for r in range(1, 4):
        for dims in combinations(DIMENSIONS, r):
            for m, flip in product(range(1, r + 1), (False, True)):
                p = DimensionPolicy(frozenset(dims), m, flip)
                if p not in seen:
                    seen.add(p)
                    pols.append(p)
    return pols
