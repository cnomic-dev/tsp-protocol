import hmac
import hashlib
import json

class TSPSecurity:
    """
    Security and Integrity layer for TSP v0.1.
    Implements HMAC-SHA256 with Canonical JSON representation.
    """

    @staticmethod
    def to_canonical_json(data: dict) -> bytes:
        """
        Converts a dictionary to a Canonical JSON string (RFC 8785 style).
        Ensures consistent hashing across different platforms.
        """
        # Sort keys and remove whitespace for deterministic output
        canonical_str = json.dumps(
            data, 
            sort_keys=True, 
            separators=(',', ':'), 
            ensure_ascii=False
        )
        return canonical_str.encode('utf-8')

    @staticmethod
    def sign_packet(packet: dict, secret_key: str) -> dict:
        """
        Signs a packet using HMAC-SHA256.
        Excludes the 'sig' field itself from the signature calculation.
        """
        # Prepare data for signing (exclude sig)
        sign_data = packet.copy()
        if "sig" in sign_data:
            del sign_data["sig"]
        
        message = TSPSecurity.to_canonical_json(sign_data)
        signature = hmac.new(
            secret_key.encode('utf-8'), 
            message, 
            hashlib.sha256
        ).hexdigest()
        
        packet["sig"] = f"hmac-sha256:{signature}"
        return packet

    @staticmethod
    def verify_signature(packet: dict, secret_key: str) -> bool:
        """
        Verifies the HMAC signature of a packet.
        Returns True if the signature is valid, False otherwise.
        """
        sig_field = packet.get("sig", "none")
        if sig_field == "none" or not sig_field.startswith("hmac-sha256:"):
            return False
        
        provided_sig = sig_field.split(":")[1]
        
        # Prepare data for verification
        check_data = packet.copy()
        del check_data["sig"]
        
        message = TSPSecurity.to_canonical_json(check_data)
        expected_sig = hmac.new(
            secret_key.encode('utf-8'), 
            message, 
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(provided_sig, expected_sig)
