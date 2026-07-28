"""Dictionary attack orchestrator using Rust core."""

import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import _core  # Rust module
from .utils import setup_logging, load_wordlist, human_readable_time
from .handshake import extract_handshake_data

logger = setup_logging()


def crack_handshake(
    pcap_path: Path,
    ssid: str,
    wordlist_path: Path,
    bssid: Optional[str] = None,
    batch_size: int = 10000,
    max_threads: int = 4,
    verbose: bool = False,
) -> Optional[str]:
    """
    Run dictionary attack against captured handshake.

    Args:
        pcap_path: Path to captured PCAP file
        ssid: Target network SSID
        wordlist_path: Path to dictionary file (.txt or .gz)
        bssid: Optional BSSID for filtering
        batch_size: Number of passwords to process per batch
        max_threads: Maximum threads for parallel processing
        verbose: Enable debug logging

    Returns:
        Found password, or None if not found
    """
    # Extract handshake data
    logger.info("📋 Extracting handshake data from PCAP...")
    handshake_data = extract_handshake_data(pcap_path, bssid, ssid)

    if not handshake_data['is_handshake_complete']:
        logger.warning(f"⚠️ Handshake may be incomplete (only {handshake_data['eapol_count']} EAPOL frames)")

    # Get the PMK from the Rust core (compute it from the SSID and a placeholder)
    # In reality, we'll compute the PMK for each password attempt
    # For now, we use the target PMK from the handshake (if available)
    target_pmk = handshake_data.get('pmk', '')
    if not target_pmk:
        # If PMK isn't extracted, we'll compute it for each password
        logger.info("🔑 No PMK extracted. Will compute PMK for each password attempt.")

    # Load wordlist
    logger.info(f"📚 Loading wordlist from {wordlist_path}...")
    try:
        passwords = load_wordlist(wordlist_path)
    except Exception as e:
        logger.error(f"Failed to load wordlist: {e}")
        return None

    logger.info(f"📊 Loaded {len(passwords)} passwords for testing")

    # Start cracking
    logger.info("⚡ Starting dictionary attack...")
    start_time = time.time()
    found_password = None

    # Try the Rust batch function first
    try:
        # Use the batch crack function from Rust
        logger.info("🚀 Using Rust batch cracker...")
        result = _core.crack_batch(passwords, ssid, target_pmk)
        if result:
            found_password = result
    except Exception as e:
        logger.warning(f"Batch crack failed: {e}. Falling back to sequential.")

    # Fallback: sequential cracking
    if not found_password:
        logger.info("🔍 Sequential cracking...")
        for idx, pwd in enumerate(passwords):
            # Compute PMK for each password
            if _core.verify_passphrase(pwd, ssid, target_pmk):
                found_password = pwd
                break

            # Progress update
            if idx > 0 and idx % 10000 == 0:
                elapsed = time.time() - start_time
                rate = idx / elapsed if elapsed > 0 else 0
                logger.debug(f"   Checked {idx}/{len(passwords)} passwords ({rate:.0f}/s)")

    # Results
    elapsed = time.time() - start_time
    if found_password:
        logger.info(f"✅ Password found: {found_password}")
        logger.info(f"   Time: {human_readable_time(elapsed)}")
        return found_password
    else:
        logger.info(f"❌ Password not found in dictionary")
        logger.info(f"   Time: {human_readable_time(elapsed)}")
        return None


def crack_with_rules(
    pcap_path: Path,
    ssid: str,
    wordlist_path: Path,
    rules_path: Optional[Path] = None,
    bssid: Optional[str] = None,
    verbose: bool = False,
) -> Optional[str]:
    """
    Run dictionary attack with mutation rules.
    This expands the wordlist by applying transformations.

    Args:
        pcap_path: Path to captured PCAP
        ssid: Network SSID
        wordlist_path: Base dictionary
        rules_path: Path to rules file (optional)
        bssid: Optional BSSID
        verbose: Enable debug logging

    Returns:
        Found password, or None
    """
    # First try the standard attack
    found = crack_handshake(pcap_path, ssid, wordlist_path, bssid, verbose=verbose)

    if found:
        return found

    # If rules are provided, expand the wordlist
    if rules_path and rules_path.exists():
        logger.info("📐 Applying mutation rules...")
        # TODO: Implement rule-based expansion
        # For now, just return None
        logger.warning("Rule-based expansion not yet implemented")
        return None

    return None


def estimate_crack_time(password_length: int, charset_size: int, speed: int = 100000) -> float:
    """
    Estimate time to brute-force a password.

    Args:
        password_length: Length of the password
        charset_size: Number of possible characters (e.g., 26 for lowercase)
        speed: Guesses per second (default 100k)

    Returns:
        Estimated time in seconds
    """
    import math
    combinations = charset_size ** password_length
    return combinations / speed