"""Pure Python crypto implementation (fallback when Rust isn't available)."""

import hashlib
import hmac
from typing import Optional

def compute_pmk(passphrase: str, ssid: str) -> str:
    """
    Compute PMK using PBKDF2-HMAC-SHA1.
    This is the pure Python version (slower but works everywhere).
    """
    # Use hashlib's PBKDF2 (available in Python 3.6+)
    pmk = hashlib.pbkdf2_hmac(
        'sha1',
        passphrase.encode('utf-8'),
        ssid.encode('utf-8'),
        4096,  # WPA2 iterations
        32     # 32 bytes = 256 bits
    )
    return pmk.hex()


def verify_passphrase(passphrase: str, ssid: str, target_pmk_hex: str) -> bool:
    """Verify if a passphrase matches the target PMK."""
    computed = compute_pmk(passphrase, ssid)
    return computed == target_pmk_hex


def crack_batch(passphrases: list, ssid: str, target_pmk_hex: str) -> Optional[str]:
    """Batch crack passwords."""
    for pwd in passphrases:
        if verify_passphrase(pwd, ssid, target_pmk_hex):
            return pwd
    return None
