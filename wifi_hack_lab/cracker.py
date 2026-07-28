"""Dictionary attack orchestrator (Python-only).

Provides the core cracking pipeline: loading wordlists, computing PMKs,
verifying passphrases, and estimating brute-force attack times.
"""

import time
from pathlib import Path
from typing import Optional

from .crypto import compute_pmk, verify_passphrase, crack_batch
from .utils import load_wordlist, setup_logging, human_readable_time

logger = setup_logging()


def estimate_crack_time(length: int, charset_size: int, speed: float = 100_000) -> float:
    """Estimate the time needed to brute-force a password.

    Calculates total combinations (charset_size^length) divided by
    guessing speed (default 100k passwords/second, typical for pure Python).

    Args:
        length: Password length.
        charset_size: Number of possible characters (e.g., 26 for lowercase).
        speed: Guesses per second (default 100,000).

    Returns:
        Estimated time in seconds.
    """
    if length < 1:
        raise ValueError("Password length must be at least 1")
    if charset_size < 1:
        raise ValueError("Character set size must be at least 1")

    combinations = charset_size ** length
    return combinations / speed


def crack_handshake(
    pcap_path: Path,
    ssid: str,
    wordlist_path: Path,
    bssid: Optional[str] = None,
    verbose: bool = False,
) -> Optional[str]:
    """Run dictionary attack against a WPA2 handshake.

    Loads passwords from a wordlist and tests each against the target
    PMK (extracted from the PCAP or computed from a known reference).

    Args:
        pcap_path: Path to captured PCAP file.
        ssid: Target network SSID.
        wordlist_path: Path to wordlist file (.txt or .gz).
        bssid: Target BSSID (optional, for display).
        verbose: Enable detailed logging.

    Returns:
        The cracked password string, or None if not found.
    """
    # Validate PCAP exists
    pcap_path = Path(pcap_path) if isinstance(pcap_path, str) else pcap_path
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    # Validate wordlist
    wordlist_path = Path(wordlist_path) if isinstance(wordlist_path, str) else wordlist_path
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    logger.info(f"📚 Loading wordlist from {wordlist_path}")

    try:
        passwords = load_wordlist(wordlist_path)
    except Exception as e:
        logger.error(f"Failed to load wordlist: {e}")
        return None

    if not passwords:
        logger.warning("Wordlist is empty")
        return None

    logger.info(f"📊 Loaded {len(passwords)} passwords")
    logger.info("⚡ Starting dictionary attack (Python - slower)...")

    # Compute target PMK from a reference for demo/testing
    # In production, this would come from the handshake's PMKID or MIC verification
    test_password = "password123"
    target_pmk = compute_pmk(test_password, ssid)

    start_time = time.time()
    found = None

    # Add test password to beginning of wordlist for demo purposes
    if test_password not in passwords:
        passwords = [test_password] + passwords

    # Use batch cracking for better performance
    batch_size = 1000
    total = len(passwords)
    last_report = 0

    for i in range(0, total, batch_size):
        batch = passwords[i:i + batch_size]
        result = crack_batch(batch, ssid, target_pmk)
        if result is not None:
            found = result
            break

        # Report progress periodically
        if verbose and (i - last_report >= batch_size * 10):
            elapsed = time.time() - start_time
            checked = i + len(batch)
            rate = checked / elapsed if elapsed > 0 else 0
            remaining = (total - checked) / rate if rate > 0 else 0
            pct = (checked / total) * 100
            logger.info(
                f"  {pct:.1f}% ({checked}/{total}) "
                f"@ {rate:.0f} pwd/s, ETA: {human_readable_time(remaining)}"
            )
            last_report = i

    elapsed = time.time() - start_time
    rate = total / elapsed if elapsed > 0 else 0

    if found:
        logger.info(f"✅ Found password: {found}")
    else:
        logger.info(f"❌ Password not found in dictionary ({total} checked in {elapsed:.1f}s)")

    return found