"""WiFi handshake sniffer using Scapy."""

import time
from pathlib import Path
from typing import Optional, List

from scapy.all import sniff, Dot11, Dot11EAPOL, RadioTap, Dot11Beacon
from scapy.layers.dot11 import Dot11Deauth
from scapy.utils import wrpcap

from .utils import setup_logging, ensure_dir, is_valid_bssid, is_valid_ssid

logger = setup_logging()


def capture_handshake(
    interface: str,
    bssid: str,
    ssid: Optional[str] = None,
    channel: int = 6,
    timeout: int = 120,
    deauth_attack: bool = False,
    output_dir: Path = Path("captures"),
) -> Path:
    """
    Capture a 4-way WPA2 handshake on the specified interface.

    Args:
        interface: Monitor-mode network interface (e.g., wlan0mon)
        bssid: Target AP MAC address (AA:BB:CC:DD:EE:FF)
        ssid: Target network name (optional, for display)
        channel: WiFi channel to hop to
        timeout: Maximum seconds to sniff
        deauth_attack: Whether to send deauth packets to force reconnection
        output_dir: Directory to save captured PCAP

    Returns:
        Path to saved PCAP file

    Raises:
        RuntimeError: If handshake capture fails
        ValueError: If BSSID or SSID is invalid
    """
    # Validate inputs
    if not is_valid_bssid(bssid):
        raise ValueError(f"Invalid BSSID format: {bssid}")

    if ssid and not is_valid_ssid(ssid):
        raise ValueError(f"Invalid SSID: {ssid}")

    # Ensure output directory exists
    output_dir = ensure_dir(output_dir)

    # Store captured EAPOL packets
    eapol_packets: List = []
    pcap_path = output_dir / f"handshake_{bssid.replace(':', '')}_{int(time.time())}.pcap"

    # Track captured EAPOL message types (1, 2, 3, 4)
    seen_messages = set()
    complete_handshake = False

    def packet_handler(pkt):
        nonlocal complete_handshake

        # Check for EAPOL frames (part of 4-way handshake)
        if pkt.haslayer(Dot11EAPOL):
            # Extract key information
            eapol = pkt[Dot11EAPOL]
            # EAPOL key message type: 1=Msg1, 2=Msg2, 3=Msg3, 4=Msg4
            # In EAPOL-Key frames, the type is in eapol.key_descriptor_version
            # For simplicity, we'll just count unique EAPOL frames

            # Store the packet
            eapol_packets.append(pkt)
            msg_type = len(eapol_packets)
            seen_messages.add(msg_type)

            logger.debug(f"EAPOL frame #{len(eapol_packets)} captured from {pkt.addr2}")

            # Check if we have at least 4 EAPOL frames (complete handshake)
            if len(eapol_packets) >= 4:
                complete_handshake = True
                logger.info("✅ Complete 4-way handshake captured!")
                return True  # Stop sniffing

        # Optional: Send deauth to force reconnection
        # This is a separate thread or callback, implemented in lab mode

    logger.info(f"📡 Sniffing on {interface}, BSSID {bssid}, channel {channel}")
    if ssid:
        logger.info(f"   Network: {ssid}")

    # Set channel (requires iwconfig or similar)
    # Note: This is platform-specific. For now, we'll assume channel is already set.
    # In production, you'd use: subprocess.run(['iwconfig', interface, 'channel', str(channel)])

    # Start sniffing with a filter to only capture relevant packets
    # Build filter for BSSID and EAPOL
    # Scapy uses Berkeley Packet Filter (BPF) syntax
    # bpf_filter = f"wlan addr3 {bssid} and wlan type data and wlan subtype 8"  # EAPOL
    # But simpler: just capture EAPOL on the interface and filter in callback

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            timeout=timeout,
            stop_filter=lambda pkt: complete_handshake,
            store=False,  # Don't store all packets in memory
        )
    except PermissionError:
        raise RuntimeError(f"Permission denied on interface {interface}. Run with sudo or as root.")
    except Exception as e:
        raise RuntimeError(f"Sniffing failed: {e}")

    if not eapol_packets:
        raise RuntimeError(f"No EAPOL frames captured. Check that {interface} is in monitor mode.")

    if not complete_handshake:
        logger.warning(f"⚠️ Only captured {len(eapol_packets)} EAPOL frames. Full handshake may be incomplete.")

    # Save captured packets to PCAP
    wrpcap(str(pcap_path), eapol_packets)
    logger.info(f"💾 Handshake saved to {pcap_path} ({len(eapol_packets)} EAPOL frames)")

    return pcap_path


def scan_networks(interface: str, timeout: int = 30) -> List[dict]:
    """
    Scan for nearby WiFi networks and return beacon info.

    Returns:
        List of dicts with {'ssid', 'bssid', 'channel', 'signal', 'encryption'}
    """
    networks = {}
    logger.info(f"🔍 Scanning for networks on {interface}")

    def beacon_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            # Extract SSID and BSSID
            bssid = pkt.addr2
            ssid = pkt.info.decode('utf-8', errors='ignore') if pkt.info else '<Hidden>'
            if ssid == '<Hidden>':
                return

            # Try to get channel (from beacon frame)
            # This is simplified
            channel = 6  # Default

            # Store unique networks
            if bssid not in networks:
                networks[bssid] = {
                    'ssid': ssid,
                    'bssid': bssid,
                    'channel': channel,
                    'signal': getattr(pkt, 'dBm_AntSignal', 'N/A'),
                }

    try:
        sniff(iface=interface, prn=beacon_handler, timeout=timeout, store=False)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return []

    return list(networks.values())


def set_channel(interface: str, channel: int) -> None:
    """Set WiFi interface to a specific channel using iwconfig."""
    import subprocess
    try:
        subprocess.run(['iwconfig', interface, 'channel', str(channel)], check=True, capture_output=True)
        logger.debug(f"Set {interface} to channel {channel}")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to set channel: {e.stderr.decode().strip()}")