import numpy as np
import uuid
import time

class TSPCore:
    """
    Core geometric and semantic logic for TSP v0.1.
    Implements S3 manifold mapping and Chordal distance metrics.
    """

    @staticmethod
    def phi_map(s: list) -> list:
        """
        Official φ Mapping: Maps ternary values (I, C, O) to S3 unit vector.
        Formula: v = (1, I, C, O) / ||(1, I, C, O)||
        
        Args:
            s (list): Ternary list of 3 integers from {-1, 0, 1}.
        Returns:
            list: A normalized 4D vector rounded to 6 decimal places.
        """
        # Append constant 1 for the hypersphere projection
        v = np.array([1.0, s[0], s[1], s[2]], dtype=np.float64)
        normalized_v = v / np.linalg.norm(v)
        return list(np.round(normalized_v, 6))

    @staticmethod
    def chordal_distance(v1: list, v2: list) -> float:
        """
        Calculates the Chordal Distance between two vectors on the S3 manifold.
        Metric: dc = ||v1 - v2||_2
        """
        return float(np.linalg.norm(np.array(v1) - np.array(v2)))

    @staticmethod
    def create_packet(s: list, act: str = "query", origin: str = "none", eps: float = 0.65) -> dict:
        """
        Factory method to create a compliant TSP v0.1 JSON packet.
        """
        return {
            "tsp": "0.1",
            "id": str(uuid.uuid4()),
            "t": int(time.time()),
            "act": act,
            "s": s,
            "vec": TSPCore.phi_map(s),
            "control": {
                "eps": eps,
                "profile": "sta-v0.1"
            },
            "origin": origin,
            "sig": "none"
        }

    @staticmethod
    def verify_integrity(packet: dict) -> bool:
        """
        Verifies that the 'vec' field matches the canonical mapping of 's'.
        This is the primary defense against 'Semantic Hallucination' or tampering.
        """
        s = packet.get("s")
        vec = packet.get("vec")
        if s is None or vec is None:
            return False
        
        expected_vec = TSPCore.phi_map(s)
        return np.allclose(vec, expected_vec, atol=1e-5)
