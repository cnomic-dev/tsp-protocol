# -*- coding: utf-8 -*-
# tspv01_test_final_py.py
# TSP v0.1 完整驗證套件（對照 tsp_protocol 實際套件執行）
#
# 原始版本是從 Colab notebook 匯出的 TSPv01 class，內含第三份獨立的
# phi mapping / HMAC 實作，且檔尾殘留了未依原始 cell 順序排列的示範
#程式碼（會在執行到一半時對尚未賦值的 test_packet 丟出 NameError），
# 以及一行 Colab 專用的 `!cat` shell magic（在純 Python 直譯器下是
# SyntaxError）。這個版本移除了那些殘留內容，並把驗證套件改成直接
# 呼叫 tsp_protocol 套件本身，而不是再維護一份平行實作。
#
# 附註：tests/tspv01_test_final.py 是同一份 notebook 的 .ipynb JSON
# 原始匯出檔，卻被存成 .py 副檔名；用 `python tests/tspv01_test_final.py`
# 執行時，因為 JSON 物件語法剛好也是合法的 Python dict 字面值，會被當成
# 一個「什麼都不做的運算式」直接跑完、回傳 exit code 0 ——不會報錯，
# 但也完全沒有執行任何測試。這份檔案已從交付內容中移除，避免誤以為
# 它是一份會失敗的測試（它其實是一份『永遠假裝通過』的空測試）。

import copy
from typing import Dict, Tuple

import numpy as np

from tsp_protocol import (
    phi_canonical,
    chordal_distance,
    canonical_json,
    make_packet,
    verify_packet,
    compute_hmac,
    verify_hmac,
)


def generate_test_packet(triple: Tuple[int, int, int], act: str = "query",
                          eps: float = 0.65, origin: str = None) -> Dict:
    """薄包裝：透過套件的 make_packet 產生測試封包，維持舊有呼叫介面。"""
    return make_packet(triple, act=act, eps=eps, origin=origin)


class TestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def _report(self, name: str, passed: bool, msg: str = ""):
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} | {name}")
        if msg and not passed:
            print(f"       └─ {msg}")
        self.results.append((name, passed, msg))
        if passed:
            self.passed += 1
        else:
            self.failed += 1

    def run_all(self):
        print("🔬 TSP v0.1 完整驗證套件（對照 tsp_protocol 套件）\n")
        self.test_phi_lookup_27_combinations()
        self.test_chordal_distance_boundaries()
        self.test_packet_integrity()
        self.test_hmac_functionality()
        self.test_fail_open_behavior()
        self.test_forward_compatibility()
        self.test_canonical_json_determinism()
        self._print_summary()

    def test_phi_lookup_27_combinations(self):
        all_ok = True
        for I in (-1, 0, 1):
            for C in (-1, 0, 1):
                for O in (-1, 0, 1):
                    vec = phi_canonical((I, C, O))
                    if len(vec) != 4 or abs(np.linalg.norm(vec) - 1.0) > 1e-6:
                        all_ok = False
                        break
        self._report("φ 映射: 27 種組合正確性", all_ok)

    def test_chordal_distance_boundaries(self):
        base = phi_canonical((1, 0, -1))
        eps = 0.65
        d_same = chordal_distance(base, base)
        d_1dim = chordal_distance(base, phi_canonical((1, 0, 0)))
        d_2dim = chordal_distance(base, phi_canonical((1, 1, 0)))
        all_ok = (d_same < 1e-6) and (d_1dim <= eps) and (d_2dim > eps)
        self._report(f"Chordal Distance 邊界測試 (eps={eps})", all_ok,
                      f"d_same={d_same:.5f}, d_1dim={d_1dim:.5f}, d_2dim={d_2dim:.5f}")

    def test_packet_integrity(self):
        pkt = generate_test_packet((1, 0, -1), origin="cnomic-dev-genesis-2026")
        valid, reason = verify_packet(pkt)
        self._report("封包完整性: 有效封包", valid, reason)

        bad_pkt = copy.deepcopy(pkt)
        bad_pkt["vec"][0] += 0.1
        valid_bad, _ = verify_packet(bad_pkt)
        self._report("封包完整性: 檢測篡改", not valid_bad)

    def test_hmac_functionality(self):
        pkt = generate_test_packet((1, 0, -1))
        secret = "test-secret-2026"
        sig = compute_hmac(pkt, secret)
        valid, _ = verify_hmac(pkt, secret, sig)
        self._report("HMAC: 往返驗證", valid and sig.startswith("hmac-sha256:"))

        wrong_sig = compute_hmac(pkt, "wrong-key")
        self._report("HMAC: 錯誤金鑰檢測", sig != wrong_sig)

    def test_fail_open_behavior(self):
        pkt = generate_test_packet((1, 0, -1))
        valid, reason = verify_hmac(pkt, "any", "unknown-algo:xxx")
        self._report("安全層: fail-open 未知格式", valid and "fail-open" in reason)

    def test_forward_compatibility(self):
        v4 = phi_canonical((1, 0, -1))
        v12 = v4 + [0.0] * 8
        compatible = np.allclose(v12[:4], v4, atol=1e-6)
        self._report("向前相容: Zero-Padding", compatible)

    def test_canonical_json_determinism(self):
        data = {"z": 1, "a": [2, 3], "m": "測試中文", "k": None}
        outputs = [canonical_json(data) for _ in range(5)]
        self._report("Canonical JSON: 確定性", all(o == outputs[0] for o in outputs))

    def _print_summary(self):
        print(f"\n📊 測試總結: {self.passed} passed, {self.failed} failed")
        if self.failed == 0:
            print("🎉 所有 TSP v0.1 核心驗證通過！可安全納入專案。")
        else:
            print("⚠️  部分測試失敗，請檢查上述輸出。")


if __name__ == "__main__":
    suite = TestSuite()
    suite.run_all()
