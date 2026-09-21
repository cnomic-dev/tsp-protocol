# -*- coding: utf-8 -*-
# Tests for tsp_protocol.semantics and tsp_protocol.dream.
# Run: python tests/test_semantics_dream.py   (or pytest)
import random
from itertools import product

from tsp_protocol import SemanticCache, make_packet
from tsp_protocol.dream import LogEntry, dream, replay
from tsp_protocol.semantics import (
    DimensionPolicy, EpsPolicy, candidate_policies, default_eps_rule, describe,
    distance, distinct_distances, lattice_report, neighbours, verify_semantic,
)

TRIPLES = list(product((-1, 0, 1), repeat=3))


def test_eps_is_a_step_function():
    dd = distinct_distances()
    assert len(dd) == 13
    rep = lattice_report(0.65)
    lo, hi = rep["equivalent_eps_interval"]
    assert abs(lo - 0.6058) < 1e-4 and abs(hi - 0.7654) < 1e-4
    # every eps in the interval gives the same neighbourhoods
    for t in TRIPLES:
        assert neighbours(t, 0.61) == neighbours(t, 0.65) == neighbours(t, 0.76)


def test_default_eps_closed_form_matches_geometry():
    for a in TRIPLES:
        for b in TRIPLES:
            assert default_eps_rule(a, b) == (distance(a, b) <= 0.65), (a, b)


def test_default_eps_is_dimension_blind():
    # summarize -> translate is a hit under eps = 0.65
    assert distance((1, 0, -1), (1, 0, 0)) <= 0.65
    assert neighbours((0, 0, 0), 0.65) == []
    assert (0, 0, 0) in lattice_report(0.65)["isolated_triples"]


def test_verify_eps_is_exact_equality():
    assert distinct_distances()[0] > 0.30
    ok, why = verify_semantic((1, 0, -1), (1, 0, -1))
    assert ok and why == "exact match"
    ok, why = verify_semantic((1, 1, -1), (1, 0, -1))
    assert not ok and "only exact" in why


def test_describe():
    assert describe((1, 0, -1)) == {
        "I": "Instruction / Assertion", "C": "Technical / Standard",
        "O": "Compression / Summarization"}


def test_packet_text_hash_restored():
    pkt = make_packet((1, 0, -1), text_hash="abc")
    assert pkt["meta"]["text_hash"] == "abc"


def test_cache_content_isolation_and_matcher():
    c = SemanticCache()
    c.put((1, 0, -1), "summary of doc A", content_key="A")
    assert c.get((1, 0, -1), content_key="B") is None          # different content
    assert c.get((1, 0, -1), content_key="A") == "summary of doc A"
    assert c.get((1, 0, 0), content_key="A") == "summary of doc A"   # eps is O-blind
    c.matcher = DimensionPolicy(frozenset({"C"}))
    assert c.get((1, 0, 0), content_key="A") is None            # O change refused
    assert c.get((1, 1, -1), content_key="A") == "summary of doc A"  # C change ok
    assert len(c) == 1


def _synthetic_worlds(seed=0, n_worlds=4, n=400, n_docs=40):
    """Ground truth: the answer depends on content, Intent and Operation, not
    on register (C). A good policy may reuse across C, never across I or O."""
    rng = random.Random(seed)
    worlds = []
    for _ in range(n_worlds):
        log = []
        for _ in range(n):
            doc = rng.randrange(n_docs)
            t = (rng.choice((-1, 0, 1)), rng.choice((-1, 0, 1)), rng.choice((-1, 0, 1)))
            log.append(LogEntry(doc, t, (doc, t[0], t[2])))
        worlds.append(log)
    return worlds


def test_replay_refuses_logs_without_ground_truth():
    try:
        replay(EpsPolicy(0.65), [LogEntry("A", (1, 0, -1), None)])
    except ValueError as e:
        assert "shadow-mode" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_dream_selects_semantically_correct_policy():
    worlds = _synthetic_worlds()
    out = dream(worlds, lam=5.0)
    inc, sel = out["incumbent"], out["selected"]
    assert sel["score"] >= inc["score"]                    # the paper's guarantee
    assert inc["false_hit_rate"] > 0                        # eps=0.65 serves wrong answers
    assert sel["false_hit_rate"] == 0.0
    assert sel["policy"].may_differ == frozenset({"C"})
    assert sel["hit_rate"] > inc["hit_rate"] - inc["hit_rate"] * inc["false_hit_rate"]


def test_dream_keeps_incumbent_on_ties():
    worlds = _synthetic_worlds(n_worlds=1, n=50)
    exact = EpsPolicy(0.0)
    out = dream(worlds, incumbent=exact, candidates=[exact, DimensionPolicy()], lam=5.0)
    assert out["selected"]["policy"] is exact


def test_candidate_space_is_small_and_finite():
    pols = candidate_policies()
    assert 20 < len(pols) < 60
    assert len({p.name for p in pols}) == len(pols)


if __name__ == "__main__":
    fns = [v for k, v in dict(globals()).items() if k.startswith("test_")]
    for f in fns:
        f()
        print(f"✅ {f.__name__}")
    print(f"\n🎉 {len(fns)} semantics/dream tests passed.")
    out = dream(_synthetic_worlds(), lam=5.0)
    print("\nDemo on synthetic shadow logs (answer depends on content, I, O):")
    for r in out["ranking"][:5] + [out["incumbent"]]:
        print(f"  {r['name']:<22} score={r['score']:+.3f} hit={r['hit_rate']:.3f} "
              f"false_hit={r['false_hit_rate']:.3f}")
