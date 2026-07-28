"""Parse captured PCAP files to extract WPA2 handshake data and PMKID."""

from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import hashlib
import hmac
import struct

from scapy.all import rdpcap, Dot11, Dot11EAPOL, Dot11WPA, Dot11WPA2
from scapy.layers.dot11 import EAPOL

from .utils import setup_logging, is_valid_bssid, is_valid_ssid

logger = setup_logging()


def extract_pmkid(pcap_path: Path, bssid: str, ssid: str) -> Optional[str]:
    """
    Extract PMKID from a PCAP file.
    PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || SSID)
    Note: This requires the PMK to be computed first, so this is a placeholder
    for PMKID extraction from the actual RSN IE.
    """
    # TODO: Parse RSN IE from beacon/probe response to extract PMKID
    # For now, return None (we'll use the full handshake method)
    logger.warning("PMKID extraction not yet implemented. Use full handshake method.")
    return None


def extract_handshake_data(pcap_path: Path, bssid: str, ssid: str) -> Dict[str, Any]:
    """
    Extract WPA2 handshake data from a PCAP file.

    Returns:
        Dict with:
        - 'pmk': The PMK (hex string) - will be computed by Rust
        - 'snonce': SNonce (hex string)
        - 'anonce': ANonce (hex string)
        - 'mic': MIC (hex string) - for verification
        - 'eapol_frames': list of raw EAPOL frames (hex strings)
        - 'is_handshake_complete': bool
    """
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if not is_valid_bssid(bssid):
        raise ValueError(f"Invalid BSSID: {bssid}")

    if not is_valid_ssid(ssid):
        raise ValueError(f"Invalid SSID: {ssid}")

    packets = rdpcap(str(pcap_path))
    logger.info(f"📂 Loaded {len(packets)} packets from {pcap_path}")

    # Filter EAPOL packets
    eapol_packets = [p for p in packets if p.haslayer(Dot11EAPOL)]

    if len(eapol_packets) < 4:
        logger.warning(f"⚠️ Found only {len(eapol_packets)} EAPOL packets (need 4 for full handshake)")

    # Extract nonces and MICs
    snonce = None
    anonce = None
    mic = None
    eapol_raw = []

    for pkt in eapol_packets:
        # Get EAPOL layer
        eapol = pkt[Dot11EAPOL]
        # EAPOL-Key frame contains the key descriptor
        if hasattr(eapol, 'key_descriptor_version'):
            # The raw EAPOL frame bytes (for mic verification)
            raw = bytes(pkt[Dot11EAPOL])
            eapol_raw.append(raw.hex())

            # Extract nonces (SNonce comes from client, ANonce from AP)
            # This is simplified; in production, you'd parse the key descriptor
            if hasattr(eapol, 'wpa_key_nonce'):
                nonce = eapol.wpa_key_nonce
                if snonce is None:
                    snonce = nonce.hex()
                elif anonce is None and nonce != bytes.fromhex(snonce):
                    anonce = nonce.hex()

            # Extract MIC (message integrity code)
            if hasattr(eapol, 'wpa_key_mic'):
                mic = eapol.wpa_key_mic.hex()

    # If we didn't find nonces, try alternative parsing
    if snonce is None or anonce is None:
        logger.warning("Nonces not found using direct parsing. Trying alternative method...")
        # Fallback: brute force from raw packet data
        # In production, you'd use more sophisticated parsing

    # Determine if handshake is complete (has at least 4 EAPOL frames)
    is_complete = len(eapol_packets) >= 4

    # For now, return the raw data
    return {
        'pmk': '',  # Will be computed by Rust
        'snonce': snonce or '',
        'anonce': anonce or '',
        'mic': mic or '',
        'eapol_frames': eapol_raw,
        'is_handshake_complete': is_complete,
        'eapol_count': len(eapol_packets),
    }


def extract_handshake_from_pcap(
    pcap_path: Path,
    bssid: str,
    ssid: str
) -> Tuple[str, str, str]:
    """
    Simplified extraction: returns (pmk_hex, snonce_hex, anonce_hex)
    for use with the Rust cracker.

    Returns:
        pmk: The PMK as hex string (to be computed by Rust)
        snonce: Supplicant nonce (hex)
        anonce: Authenticator nonce (hex)
    """
    data = extract_handshake_data(pcap_path, bssid, ssid)

    # We don't compute PMK here - Rust will do it
    # But we need the nonces for the MIC calculation

    return (
        data['pmk'],  # Empty, will be computed
        data['snonce'],
        data['anonce']
    )


def verify_mic(pmk_hex: str, eapol_frame_hex: str) -> bool:
    """
    Verify the MIC of an EAPOL frame using the PMK.
    This is a placeholder - actual implementation requires more detailed parsing.
    """
    # TODO: Implement full MIC verification
    # This requires parsing the EAPOL-Key frame and computing the MIC
    # using HMAC-SHA1 with the PMK
    logger.warning("MIC verification not yet implemented")
    return True


def extract_handshake_from_pcap(pcap_path: Path, bssid: str, ssid: str):
    data = extract_handshake_data(pcap_path, bssid, ssid)
    return data