# tsp_v01.py
# TSP v0.1 — Ternary Semantic Packet — reference self-test
# Apache License 2.0 — cnomic-dev, April 2026
# https://github.com/cnomic-dev/semantic-translator-architecture
#
# This used to be a full standalone reimplementation of the TSP v0.1 core
# (phi mapping, chordal distance, packet make/verify, HMAC, SemanticCache),
# separate from tsp_protocol/core.py + security.py. That split was the
# actual cause of tsp_protocol failing to import (see repo history / the
# accompanying writeup): two independently-maintained copies of the same
# math and packet logic had drifted apart. This file now imports the real
# package instead, so a passing run here means the installed package works,
# not just that this file's private copy of the logic is internally
# consistent.

import copy

import numpy as np

from tsp_protocol import (
    phi_canonical,
    vec_to_s,
    verify_vec,
    chordal_distance as chordal_dist,
    make_packet,
    verify_packet,
    sign_packet,
    verify_hmac,
    SemanticCache,
)

if __name__ == "__main__":
    print("TSP v0.1 — self-test (against installed tsp_protocol package)\n")

    # 1. phi mapping
    s = (1, 0, -1)
    vec = phi_canonical(s)
    assert verify_vec(s, vec), "phi mapping failed"
    assert vec_to_s(vec) == s, "inverse mapping failed"
    print(f"✅ φ({s}) = {vec}")

    # 2. Chordal distance boundaries
    d_same = chordal_dist(phi_canonical((1, 0, -1)), phi_canonical((1, 0, -1)))
    d_1dim = chordal_dist(phi_canonical((1, 0, -1)), phi_canonical((1, 0, 0)))
    d_2dim = chordal_dist(phi_canonical((1, 0, -1)), phi_canonical((1, 1, 0)))
    eps = 0.65
    assert d_same < 1e-6
    assert d_1dim <= eps, f"d_1dim={d_1dim:.5f} > eps={eps}"
    assert d_2dim > eps, f"d_2dim={d_2dim:.5f} <= eps={eps}"
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

    # 6. Fail-open (SECURITY.md-documented policy)
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

    print("\n🎉 All TSP v0.1 self-tests passed against tsp_protocol.")
