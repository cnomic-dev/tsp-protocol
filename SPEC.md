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
| `origin` | String | Attribution seed for the creator |
| `sig` | String | Signature (Default: "none" or "hmac-sha256:<hex>") |

## 5. Security Layer
### 5.1 Integrity (HMAC-SHA256)
When `sig` is not "none", the packet MUST be signed using HMAC-SHA256 over the **Canonical JSON** (RFC 8785) representation of the packet (excluding the `sig` field).

### 5.2 Privacy (TCE-SU2) - *Experimental*
TSP reserves the $SU(2)$ rotation mechanism for blind matching. Encrypted matching is performed via rotation matrices in $SO(4)$ that preserve Chordal distance.

---
© 2026 cnomic-dev. Licensed under Apache License 2.0.
