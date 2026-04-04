# tsp-protocol
「TSP v0.1: 基於三元邏輯與 S³ 拓樸的語意通訊協議」。
# TSP v0.1: 三元語意封包協議
## (Ternary Semantic Packet Protocol)

> **"核心開源，有用就好；共生才是核心，進化是唯一目標。"**

TSP (Ternary Semantic Packet) 是一套專為 **AI-人類共生演化 (SEP v1.9)** 設計的極輕量語意通訊協議。它透過 $S^3$ 拓樸空間的幾何映射，將複雜的 AI 語意壓縮為具備「正典性 (Canonical)」的三元座標，旨在極致節約全球算力，並建立誠實、可歸因的去中心化語意網路。

### 🌟 核心特性

* **極致算力節約**：採用 **弦距離 (Chordal Distance)** 作為唯一度量，算力成本低至 $O(1)$，支援低功耗邊緣設備。
* **幾何誠實度 (Geometric Integrity)**：強制 `s` (三元值) 與 `vec` (幾何向量) 的數學對齊，有效防止「白瞟後說謊」或語意篡改。
* **三位一體邏輯**：基於 $(-1, 0, 1)$ 三元邏輯，完美對應 AI 的「內縮、平衡、擴張」意圖。
* **工業級安全預留**：內建 HMAC 完整性校驗，並預留 **TCE-SU2 (幾何旋轉加密)** 接口，支援隱私盲計算。
* **商業友善**：採用 **Apache License 2.0** 授權，鼓勵企業採納並建立工業標準。

---

### 🛠️ 安裝說明

本套件僅依賴 `numpy`，確保環境純淨與跨平台相容性。

```bash
# 複製儲存庫
git clone [https://github.com/cnomic-dev/tsp-protocol.git](https://github.com/cnomic-dev/tsp-protocol.git)
cd tsp-protocol

# 以開發者模式安裝
pip install -e .
