# Ternary Semantic Packet — TSP v0.1

**A Minimal Open Protocol for Semantic Packet Transmission**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-0.1-green.svg)]()
[![Status](https://img.shields.io/badge/status-open--draft-orange.svg)]()
[![Open Source](https://img.shields.io/badge/open--source-yes-brightgreen.svg)]()

> **TSP v0.1 is not a format — it's a semantic contract.**  
> It locks mathematical boundaries for cross-platform compatibility, while preserving engineering flexibility for future evolution.

**Author:** cnomic-dev  
**Date:** April 2026  
**Companion spec:** [Semantic Translator Architecture (STA v0.1)](https://github.com/cnomic-dev/semantic-translator-architecture)  
**Philosophy:** This protocol is fully open. Any platform, researcher, or developer may implement, extend, or fork without restriction.

---

## Overview

TSP v0.1 defines the standard transmission packet for the Semantic Translator Architecture (STA). It encodes a ternary semantic triple `(I, C, O)` alongside its S³ projection, enabling cross-platform semantic cache lookups with a mathematically auditable, lightweight structure.

```
✅ Core: 4 required fields, 27 precomputed S³ points, locked distance metric
⚙️ Optional: HMAC integrity, origin fingerprint, TCE-SU2 encryption (experimental)
🔗 Forward compatible: Zero-padding rule ensures v0.2+ never breaks v0.1 clients
```

---

## ⚠️ Security Parameters (Read First)

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `query_max_len` | `2000` | Input length guard |
| `vec` tolerance | `1e-5` | s↔vec consistency check |
| `unit_norm_tol` | `1e-4` | Unit vector validation |
| `sig` unknown format | fail-open | Log warning, continue processing |

---

## Packet Structure

### Minimal Valid Packet

```json
{
  "tsp": "0.1",
  "id":  "uuid-or-sha256-hash",
  "t":   1743750000,
  "act": "query",

  "s":   [1, 0, -1],
  "vec": [0.57735, 0.57735, 0.00000, -0.57735],

  "control": {
    "eps":     0.65,
    "profile": "sta-v0.1"
  },

  "lang": {
    "src": "zh-tw",
    "tgt": "en"
  },

  "meta": {
    "text_hash": "sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "length": 42
  },

  "sig": "none"
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tsp` | string | ✅ | Protocol version (`"0.1"`) |
| `id` | string | ✅ | UUID or SHA-256 hash — unique packet identifier |
| `t` | integer | ✅ | Unix timestamp (seconds) |
| `act` | enum | ✅ | Action: `query` / `store` / `align` / `verify` |
| `s` | int[3] | ✅ | **Canonical** ternary triple `(I, C, O) ∈ {-1, 0, 1}³` |
| `vec` | float[4] | ✅ | **Derived** S³ unit vector — MUST match `φ(s)` |
| `control.eps` | float | ✅ | Cache hit threshold (chordal distance) |
| `control.profile` | string | ✅ | Mapping version (`"sta-v0.1"`) |
| `lang` | object | optional | Source/target language codes |
| `meta.text_hash` | string | optional | Input integrity only — NOT for semantic matching |
| `sig` | string | optional | Signature (default: `"none"`) |
| `origin` | string | optional | Provenance fingerprint |

---

## Dimension Definition (Locked for v0.1)

| Dimension | Value | Meaning |
|-----------|-------|---------|
| **I — Intent** | `-1` | Exploration / Question |
| | `0` | Neutral / Verification |
| | `1` | Instruction / Assertion |
| **C — Context** | `-1` | Casual / Conversational |
| | `0` | Neutral / Domain-agnostic |
| | `1` | Formal / Academic |
| **O — Operation** | `-1` | Compression / Summarization |
| | `0` | Translation / Conversion |
| | `1` | Expansion / Generation |

---

## Specification Rules

### Rule 1 — Canonical Representation

`s` is the **authoritative** semantic representation.  
`vec` MUST be strictly derived from `s` using the official `φ` mapping defined by `control.profile`.  
On any inconsistency, `s` MUST take precedence. Receivers SHOULD re-compute `vec` from `s` during validation.

Consistency tolerance: `‖vec_computed − vec_provided‖₂ ≤ 1e-5`

### Rule 2 — Distance Metric (Locked)

Semantic distance is defined **exclusively** as Chordal Distance on S³:

$$d_c(\mathbf{u}, \mathbf{v}) = \|\mathbf{u} - \mathbf{v}\|_2$$

Cache hit condition: $d_c \leq \texttt{control.eps}$

**Prohibited:** cosine similarity, geodesic distance, or any other metric.

**Default thresholds:**
- `ε_cache = 0.65` — one ternary dimension of difference under the fixed S³ embedding. **This is not a universal constant** — it is calibrated to this specific embedding.
- `ε_verify = 0.30` — strict semantic verification

> Why `0.65`? Empirically: `d_1dim = 0.468 ≤ 0.65 ✅` (1-dim diff hits), `d_2dim = 0.680 > 0.65 ✅` (2-dim diff misses). Both `0.55` and `0.65` are mathematically valid; `0.65` provides more margin for cross-language floating-point variance.

### Rule 3 — Profile Isolation

`control.profile` identifies the exact version of `T` and `φ`.  
Packets with different profiles MUST NOT be directly compared for semantic matching.  
Default for v0.1: `"sta-v0.1"`.

### Rule 4 — Action Semantics

| `act` | Behavior |
|-------|----------|
| `query` | Standard semantic cache lookup (most common) |
| `store` | Force write to cache (bypass hit check) |
| `align` | Request cross-language or cross-profile alignment |
| `verify` | Semantic consistency check only (no cache read/write) |

### Rule 5 — Integrity vs Semantics

`meta.text_hash` is for input integrity only.  
It MUST NOT be used for semantic matching or cache decisions.  
Recommended format: `"sha256:<64-hex-chars>"`

---

## Official φ Mapping (sta-v0.1 profile)

$$\phi(I, C, O) = \frac{(1,\ I,\ C,\ O)}{\|(1,\ I,\ C,\ O)\|_2} \in S^3 \subset \mathbb{R}^4$$

All 27 discrete points are unique. Note: angular distances between points are not uniform — this is a known property of the fixed embedding, not a defect.

```python
import numpy as np

def phi_canonical(s: tuple) -> list:
    """Official φ mapping: (I, C, O) → S³ unit vector (6 decimal places)"""
    vec = np.array([1.0, s[0], s[1], s[2]], dtype=np.float64)
    return np.round(vec / np.linalg.norm(vec), decimals=6).tolist()

def vec_to_s(vec: list) -> tuple:
    """Inverse mapping: S³ vector → (I, C, O) ternary triple"""
    return tuple(int(np.sign(x)) for x in vec[1:])

def verify_vec(s: tuple, vec: list, tol: float = 1e-5) -> bool:
    """Verify vec matches official φ mapping"""
    expected = np.array(phi_canonical(s))
    return np.allclose(np.array(vec), expected, atol=tol)

# Example
# s = (1, 0, -1) → vec = [0.57735, 0.57735, 0.0, -0.57735]
```

**Bidirectional conversion:**

| Direction | Formula | Notes |
|-----------|---------|-------|
| `s → vec` | `φ(1, I, C, O) / ‖·‖` | Sender computes, receiver validates |
| `vec → s` | `sign(vec[1:])` | Exact recovery for all 27 points |

If both `s` and `vec` are present, receiver MUST validate consistency. On mismatch, use `s` and recompute `vec`.

---

## Forward Compatibility

v0.2+ may extend the triple with additional dimensions (e.g. `Certainty`, `Emotion`, `Temporal`).

**Zero-Padding Rule:**
- New dimensions default to `0`
- Distance calculations ignore `0`-valued dimensions
- v0.1 parsers truncate to first 3 dimensions — no breaking changes

```python
# v0.1 vector (4D)
v0 = phi_canonical((1, 0, -1))          # [0.57735, 0.57735, 0.0, -0.57735]

# v0.2 extended (8D) — backward compatible
v1 = v0 + [0.0] * 4
# d_c(v0, v1[:4]) == 0 ✅
```

---

## Security Layer (Optional)

Security extensions are **optional and orthogonal** to core semantics.  
Receivers MUST gracefully handle unknown `sig` formats (fail-open for v0.1).

### A.1 HMAC-SHA256 — Recommended Default

```json
"sig": "hmac-sha256:<64-hex-chars>"
```

**Canonical payload** (RFC 8785 JCS — keys in lexicographical order, UTF-8, no whitespace):

Fields signed: `act`, `control`, `id`, `s`, `t`, `vec`  
(include `lang` if present; document deviation in `config.yaml`)

On mismatch: log warning, continue processing (fail-open). Implementations MAY apply trust scoring or rate limiting.

### A.2 Origin Fingerprint

```json
"origin": "cnomic-dev-genesis-2026"
```

Lightweight provenance for open-source governance. Separate from `sig` by design.

### A.3 TCE-SU2 — Experimental

Privacy-preserving semantic matching via S³ ≅ SU(2) rotation:

$$\mathbf{vec}' = R \cdot \mathbf{vec} \cdot R^\dagger, \quad R \in \mathrm{SU}(2)$$

**Key properties:** Preserves unit norm. Chordal distance is rotation-invariant.

⚠️ Vectors under different rotation parameters MUST NOT be compared directly. Exchange rotation parameters via Diffie-Hellman or pre-shared keys.

**Status:** Experimental. Not required for basic interoperability.

| Topic | Recommendation |
|-------|---------------|
| Quaternion convention | `[w, x, y, z]` (scalar-first) |
| Reference implementation | `utils/security.py` — `so4_from_quat()` |
| Canonical JSON | Always RFC 8785 JCS for HMAC payload |

---

## Repository Structure

```
tsp/
├── README.md                  # This file
├── SPEC.md                    # Full formal specification
├── pyproject.toml             # dependencies: numpy>=1.24
├── profiles/
│   └── sta-v0.1.json          # Default profile registration
├── core/
│   ├── __init__.py
│   ├── phi.py                 # phi_canonical(), verify_vec(), vec_to_s()
│   ├── packet.py              # TSP encode / decode / validate
│   ├── cache.py               # Chordal distance retrieval
│   └── translator.py          # Main flow: T → φ → Cache → Fallback
├── tests/
│   ├── test_phi.py            # φ mapping: 27 combinations + tolerance
│   ├── test_packet.py         # TSP round-trip encode/decode + tampering
│   └── test_cache.py          # Chordal distance boundary tests
├── examples/
│   └── quickstart.py          # 5-minute onboarding
└── LICENSE                    # Apache 2.0
```

---

## Quickstart

```bash
git clone https://github.com/cnomic-dev/semantic-translator-architecture
cd semantic-translator-architecture
pip install numpy
python precompute_27_points.py
python examples/quickstart.py
```

```python
from core.phi import phi_canonical, verify_vec

s = (1, 0, -1)
vec = phi_canonical(s)
print(vec)           # [0.57735, 0.57735, 0.0, -0.57735]
print(verify_vec(s, vec))   # True
```

```bash
python -m pytest tests/ -v
```

---

## What v0.1 Does NOT Promise

- No persistent disk cache (dict only; planned v0.2)
- No dynamic threshold adjustment at runtime
- No guaranteed absolute cross-platform semantic consistency
- No SU(2) quaternion aligner (planned v0.2)
- No long context support (> 2000 tokens)
- Eviction strategy is implementation-defined

---

## Relationship to STA v0.1

| Layer | Spec | Role |
|-------|------|------|
| Inference efficiency | STA v0.1 | Semantic cache + cross-language alignment |
| **Packet transmission** | **TSP v0.1** | **Standard packet format for STA output** |
| KV cache compression | TurboQuant | Memory reduction during inference |
| Local deployment | Lemonade | Hardware routing + OpenAI-compatible endpoint |

---

## Dependencies

```toml
[project]
dependencies = ["numpy>=1.24"]

[project.optional-dependencies]
alignment = ["scipy>=1.10"]
testing   = ["pytest>=7.0"]
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add language adapters, encoding rules, or cache strategies. All contributions must preserve the v0.1 locked dimension definitions and distance metric.

---

## Related Work

- [STA v0.1 — Semantic Translator Architecture](https://github.com/cnomic-dev/semantic-translator-architecture)
- [ΨSEP — Human Basic Evolution Equation](https://github.com/cnomic-dev/human-basic-evolution-equation)
- SEP — Symbiotic Evolution Protocol
- ESP — Evolutionary Singularity Protocol

---

## License

```
Apache License 2.0
Copyright 2026 cnomic-dev

This protocol is fully open. Any platform, researcher, or developer
may implement, extend, or fork without restriction.

http://www.apache.org/licenses/LICENSE-2.0
```

---

*TSP v0.1 — April 2026 — github.com/cnomic-dev*
