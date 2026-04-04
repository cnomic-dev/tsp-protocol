# Ternary Semantic Packet — TSP v0.1

A minimal open protocol for semantic packet transmission & AI-human symbiosis.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-0.1-green.svg)]()
[![Status](https://img.shields.io/badge/status-stable--draft-orange.svg)]()
[![Open Source](https://img.shields.io/badge/open--source-yes-brightgreen.svg)]()

> **TSP v0.1 is not a format — it's a semantic contract.** It locks mathematical boundaries for cross-platform compatibility, ensures geometric honesty, and protects creator attribution through cryptographic verification.

**Author:** cnomic-dev (Architecture & Protocol Design)  
**Date:** April 2026  
**Repository:** [github.com/cnomic-dev/tsp-protocol](https://github.com/cnomic-dev/tsp-protocol)

## Philosophy

This protocol is fully open. Any platform, researcher, or developer may implement, extend, or fork it without restriction.

---

## Overview

Current LLM inference pipelines process every request from raw token sequences, reconstructing the full KV cache on each turn regardless of semantic overlap.

**TSP v0.1** introduces a lightweight, platform-agnostic standard to transmit and verify semantic intents. By mapping intent into a hyperspherical ($S^3$) coordinate system using ternary logic, TSP enables extremely low-latency semantic matching ($O(1)$ complexity) while ensuring data attribution and honesty.

**Core insight:** Reduce *how often* full inference occurs, while guaranteeing the *integrity* of the semantic data being reused.

---

## Dimension Definition (Locked for v0.1)

The three components of the semantic triple are defined as follows. **This definition is fixed for v0.1 and must not vary across implementations.**

| Dimension | Value | Meaning |
|-----------|-------|---------|
| **I — Intent** | `-1` | Exploration / Question |
| | `0` | Neutral / Verification |
| | `+1` | Instruction / Assertion |
| **C — Context** | `-1` | Casual / Conversational |
| | `0` | Technical / Standard |
| | `+1` | Formal / Academic |
| **O — Operation** | `-1` | Compression / Summarization |
| | `0` | Translation / Conversion |
| | `+1` | Expansion / Generation |

---

## TSP Packet Structure (JSON)

As a communication protocol, TSP standardizes how semantic data is formatted and transmitted. Below is the canonical JSON structure for a v0.1 packet.

```json
{
  "tsp": "0.1",
  "id": "uuid-or-sha256-hash",
  "t": 1743750000,
  "act": "query",
  "s": [1, 0, -1],
  "vec": [0.57735, 0.57735, 0.00000, -0.57735],
  "control": {
    "eps": 0.65,
    "profile": "sta-v0.1"
  },
  "lang": {
    "src": "zh-tw",
    "tgt": "en"
  },
  "origin": "cnomic-dev-genesis-2026",
  "sig": "hmac-sha256:xxxxxxxxxxxxxxx"
}
```

---

## Mathematical Foundation

### 1. Ternary Decomposition

$$\mathcal{T}: q \mapsto (I, C, O) \in \{-1, 0, 1\}^3$$

The translator maps an input query $q$ to a semantic triple.

### 2. S³ Projection (φ Mapping)

The triple is embedded onto the unit 3-sphere. The normalized 4D vector $\vec{v}$ is calculated as:

$$\vec{v} = \phi(I, C, O) = \frac{(1,\ I,\ C,\ O)}{\sqrt{1 + I^2 + C^2 + O^2}}$$

**Note:** All 27 discrete points map to unique unit vectors. The lookup table is precomputed — no runtime floating-point computation is required for mapping.

### 3. Cache Retrieval (Chordal Distance)

To minimize computational overhead, TSP adopts chordal distance for semantic similarity:

$$d_c(\mathbf{u}, \mathbf{v}) = \|\mathbf{u} - \mathbf{v}\|_2$$

**Cache hit condition:** $d_c \leq \epsilon$

**Default Epsilon ($\epsilon$):** 0.65 (recommended for cross-language tolerance and standard caching)

---

## Security & Attribution (Geometric Honesty)

Unlike standard caching algorithms, TSP v0.1 enforces strict data integrity and creator attribution, preventing "semantic hallucinations" and unauthorized tampering.

### 1. Canonical Representation (The Truth Layer)

The field `s` is the canonical and authoritative semantic representation. The field `vec` **must** be strictly derived from `s`. If a conflict occurs, the system must drop the packet or recalculate `vec`.

### 2. HMAC-SHA256 Integrity

When `sig` is not `"none"`, the packet **must** be signed using HMAC-SHA256 over the canonical JSON representation of the packet (excluding the `sig` field itself). This ensures the origin and data payload cannot be altered during transmission.

---

## Installation

Ensure your environment has `numpy>=1.24.0` installed.

```bash
# Clone the repository
git clone https://github.com/cnomic-dev/tsp-protocol.git
cd tsp-protocol

# Install in editable mode
pip install -e .
```

---

## Quickstart

### Basic Usage

```python
from tsp_protocol.core import TSPCore
from tsp_protocol.security import TSPSecurity

# 1. Create a semantic packet
packet = TSPCore.create_packet(
    s=[1, 0, -1],
    act="query",
    origin="node-alpha"
)

# 2. Verify Geometric Honesty (O(1) execution)
is_honest = TSPCore.verify_integrity(packet)
print(f"Geometric verification passed: {is_honest}")

# 3. Calculate Semantic Distance
v1 = TSPCore.phi_map([1, 0, -1])
v2 = TSPCore.phi_map([1, 1, -1])
distance = TSPCore.chordal_distance(v1, v2)
print(f"Chordal Distance: {distance:.5f}")
```

---

## Ecosystem & Relationships

| Component | Version | Role |
|-----------|---------|------|
| **STA** | v0.1 | Semantic cache architecture + cross-language alignment |
| **TSP** | v0.1 | Standard packet format & geometric verification (this repo) |
| **ΨSEP** | v0.45+ | Mathematical foundation for AI-human symbiosis |

---

## License

Apache License 2.0

Copyright 2026 cnomic-dev

This protocol is fully open. Any platform, researcher, or developer may implement, extend, or fork without restriction.

---

## Contributing

Contributions, forks, and extensions are welcome. Please submit issues and pull requests to the [main repository](https://github.com/cnomic-dev/tsp-protocol).

## Citation

If you use TSP v0.1 in your work, please cite:

```bibtex
@protocol{cnomic2026tsp,
  title={Ternary Semantic Packet: TSP v0.1},
  author={cnomic-dev},
  year={2026},
  url={https://github.com/cnomic-dev/tsp-protocol}
}
```
