# TSP v0.1 Technical Specification
## Ternary Semantic Packet Protocol

**Version:** 0.1.0  
**Status:** Experimental / Draft  
**Author:** cnomic-dev  
**Framework:** SEP v1.9 (Symbiotic Evolution Protocol)

---

## 1. Abstract
The Ternary Semantic Packet (TSP) protocol is a minimalist communication standard designed to facilitate AI-Human symbiosis. By mapping intent into a hyperspherical ($S^3$) coordinate system using ternary logic, TSP enables extremely low-latency semantic matching (O(1) complexity) while ensuring data attribution and honesty.

## 2. The $\phi$ Mapping (Ternary to Geometry)
The core of TSP is the $\phi$ function, which maps a ternary vector $s \in \{-1, 0, 1\}^3$ to a unit vector on the 3-sphere ($S^3$).

### 2.1 Formula
Given $s = (I, C, O)$, the normalized 4D vector $\vec{v}$ is calculated as:

$$\vec{v} = \phi(s) = \frac{(1, I, C, O)}{\sqrt{1 + I^2 + C^2 + O^2}}$$

### 2.2 Constraints
* **Precision:** The `vec` field MUST be rounded to **6 decimal places**.
* **Canonicality:** The field `s` is the **Canonical** representation. If a conflict occurs between `s` and `vec`, the receiver MUST recalculate `vec` from `s`.

## 3. Distance Metric: Chordal Distance
To minimize computational overhead on edge devices, TSP adopts **Chordal Distance** as the primary metric for semantic similarity.

### 3.1 Definition
For two vectors $u, v \in S^3$, the distance $d_c$ is defined as the Euclidean norm of their difference:

$$d_c(u, v) = \|u - v\|_2$$

### 3.2 Cache Matching
A semantic match (Cache Hit) is determined by the threshold $\epsilon$ (epsilon):
* **Default Epsilon:** $0.65$
* **Logic:** If $d_c \leq \epsilon$, the intent is considered semantically equivalent.

### 3.3 Ternary Semantics of the Threshold (informative)
On the 27-point lattice, $d_c$ takes only 13 distinct non-zero values, so
$\epsilon$ acts as a step function. For every $\epsilon \in [0.6058, 0.7654)$ —
including the default $0.65$ — a hit occurs iff the two triples differ in
exactly one dimension by a $0 \leftrightarrow \pm1$ step and the sparser triple
has at least one non-zero coordinate. Sign flips never hit; $(0,0,0)$ has no
neighbours. The metric does not distinguish *which* dimension changed (e.g.
Summarization vs. Translation along $O$). Implementations MAY use an explicit
per-dimension match rule instead (`tsp_protocol.semantics.DimensionPolicy`).

The triple encodes how a request is phrased, not what it is about. A cache
SHOULD key entries on a content identifier (`meta.text_hash`) together with
`s`, and MUST NOT serve an entry across different content identifiers.

The verification threshold $\epsilon_{verify} = 0.30$ (SECURITY.md) is below the
lattice spacing ($0.5176$) and is therefore equivalent to exact equality of `s`.

### 3.4 Offline Policy Selection (informative)
A match rule can be selected from shadow-mode logs (every request inferred,
with a ground-truth answer key) by replaying each candidate rule and scoring
$V = (\text{correct hits} - \lambda \cdot \text{false hits})/N$, following the
replay-simulator approach of Dream-RSI (arXiv:2609.14858). See
`tsp_protocol.dream`.

## 4. Packet Structure (JSON)
| Field | Type | Description |
| :--- | :--- | :--- |
| `tsp` | String | Protocol version (Fixed: "0.1") |
| `id` | String | Unique UUID for the packet |
| `t` | Integer | Unix timestamp |
| `act` | Enum | Action: `query`, `store`, `align`, `verify` |
| `s` | Array | Canonical ternary values [I, C, O] |
| `vec` | Array | Derived 4D S³ unit vector |
| `control` | Object | Contains `eps` and `profile` (e.g., "sta-v0.1") |
| `lang` | Object | *Optional.* Source/target language codes for cross-lingual matching: `{"src": ..., "tgt": ...}` |
| `meta` | Object | *Optional.* `text_hash`: content identifier used as the cache key alongside `s` (§3.3) |
| `origin` | String | Attribution seed for the creator |
| `sig` | String | Signature (Default: "none" or "hmac-sha256:<hex>") |

## 5. Security Layer
### 5.1 Integrity (HMAC-SHA256)
When `sig` is not "none", the packet MUST be signed using HMAC-SHA256 over the **Canonical JSON** (RFC 8785) representation of the packet (excluding the `sig` field).

### 5.2 Privacy (TCE-SU2) - *Experimental*
TSP reserves the $SU(2)$ rotation mechanism for blind matching. Encrypted matching is performed via rotation matrices in $SO(4)$ that preserve Chordal distance.

---
© 2026 cnomic-dev. Licensed under Apache License 2.0.
