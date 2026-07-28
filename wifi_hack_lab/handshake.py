"""Parse captured PCAP files to extract WPA2 handshake data."""

from pathlib import Path
from typing import Dict, Any, List

from scapy.all import rdpcap, EAPOL

from .utils import setup_logging, is_valid_bssid, is_valid_ssid

logger = setup_logging()


def extract_handshake_data(pcap_path: Path, bssid: str, ssid: str) -> Dict[str, Any]:
    """Extract handshake data from PCAP file.

    Parses EAPOL frames from a captured PCAP and returns handshake metadata
    including nonces, MIC, and completion status.

    Args:
        pcap_path: Path to the PCAP file.
        bssid: BSSID of the target AP (e.g., "AA:BB:CC:DD:EE:FF").
        ssid: SSID of the target network.

    Returns:
        Dict with keys: pmk, snonce, anonce, mic, eapol_frames,
                        is_handshake_complete, eapol_count

    Raises:
        FileNotFoundError: If pcap_path doesn't exist.
        ValueError: If BSSID or SSID is invalid.
    """
    # Validate inputs BEFORE checking file existence so tests can verify
    # validation logic without needing an actual PCAP file.
    if not is_valid_bssid(bssid):
        raise ValueError(f"Invalid BSSID: {bssid}")
    if not is_valid_ssid(ssid):
        raise ValueError(f"Invalid SSID: {ssid}")
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    packets = rdpcap(str(pcap_path))
    eapol_packets: List[Any] = [p for p in packets if p.haslayer(EAPOL)]

    # Extract nonces and MIC from EAPOL frames if available
    snonce = ""
    anonce = ""
    mic = ""

    for pkt in eapol_packets:
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt[EAPOL]
            # EAPOL-Key frames (type 3) carry the handshake data
            if hasattr(eapol_layer, 'payload') and hasattr(eapol_layer.payload, 'key_ack'):
                key_info = eapol_layer.payload
                if hasattr(key_info, 'snonce') and key_info.snonce and not snonce:
                    snonce = key_info.snonce.hex()
                if hasattr(key_info, 'anonce') and key_info.anonce and not anonce:
                    anonce = key_info.anonce.hex()
                if hasattr(key_info, 'mic') and key_info.mic:
                    mic = key_info.mic.hex()

    return {
        'pmk': '',
        'snonce': snonce,
        'anonce': anonce,
        'mic': mic,
        'eapol_frames': eapol_packets,
        'is_handshake_complete': len(eapol_packets) >= 4,
        'eapol_count': len(eapol_packets),
    }


def extract_pmkid(pcap_path: Path, bssid: str, ssid: str) -> str:
    """Extract PMKID from a captured handshake (placeholder).

    In a full implementation, this would parse the RSN IE from the
    first EAPOL-Key frame to extract the PMKID for PMKID-based attacks.

    Args:
        pcap_path: Path to the PCAP file.
        bssid: BSSID of the target AP.
        ssid: SSID of the target network.

    Returns:
        PMKID hex string, or None if not available.
    """
    return None


def verify_mic(pmk_hex: str, eapol_frame_hex: str) -> bool:
    """Verify the MIC of an EAPOL frame (placeholder).

    In a full implementation, this would reconstruct the PTK from the
    PMK and verify the MIC against the captured EAPOL-Key frame.

    Args:
        pmk_hex: PMK as a hex string.
        eapol_frame_hex: EAPOL frame as a hex string.

    Returns:
        True if MIC is valid (placeholder).
    """
    return True


def extract_handshake_from_pcap(pcap_path: Path, bssid: str, ssid: str) -> dict:
    """Simplified handshake extraction (wrapper around extract_handshake_data).

    Args:
        pcap_path: Path to the PCAP file.
        bssid: BSSID of the target AP.
        ssid: SSID of the target network.

    Returns:
        Dict with handshake data.
    """
    return extract_handshake_data(pcap_path, bssid, ssid)
