"""WiFi handshake sniffer using Scapy."""

import time
import subprocess
from pathlib import Path
from typing import Optional, List

from scapy.all import sniff, Dot11, RadioTap, Dot11Beacon, Dot11ProbeResp, Dot11Deauth, wrpcap
from scapy.all import Dot11WPA, Dot11WPA2, Dot11AssoReq, Dot11ReassoReq

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
    """Capture a 4-way WPA2 handshake."""
    if not is_valid_bssid(bssid):
        raise ValueError(f"Invalid BSSID: {bssid}")

    output_dir = ensure_dir(output_dir)
    eapol_packets = []
    pcap_path = output_dir / f"handshake_{bssid.replace(':', '')}_{int(time.time())}.pcap"
    complete = False

    def packet_handler(pkt):
        nonlocal complete
        if pkt.haslayer(Dot11) and pkt.type == 2:
            if hasattr(pkt, 'payload') and hasattr(pkt.payload, 'type'):
                if pkt.payload.type == 0x888e:
                    eapol_packets.append(pkt)
                    logger.info(f"📦 EAPOL-like frame #{len(eapol_packets)} captured")
                    if len(eapol_packets) >= 4:
                        complete = True
                        return True

    logger.info(f"📡 Capturing on {interface}, BSSID {bssid}, channel {channel}")
    
    try:
        sniff(iface=interface, prn=packet_handler, timeout=timeout, stop_filter=lambda pkt: complete, store=False)
    except PermissionError:
        raise RuntimeError(f"Permission denied. Run with sudo.")
    except Exception as e:
        raise RuntimeError(f"Sniffing failed: {e}")

    if not eapol_packets:
        logger.warning(f"No EAPOL frames captured. Interface may not be in monitor mode.")

    wrpcap(str(pcap_path), eapol_packets)
    logger.info(f"💾 Saved to {pcap_path} ({len(eapol_packets)} frames)")
    return pcap_path


def scan_networks(interface: str, timeout: int = 30) -> List[dict]:
    """Scan for nearby WiFi networks."""
    networks = {}
    logger.info(f"🔍 Scanning on {interface} (timeout: {timeout}s)")

    def packet_handler(pkt):
        if not pkt.haslayer(Dot11):
            return
        
        bssid = pkt.addr2
        if not bssid:
            return
        
        ssid = None
        encryption = "Unknown"
        
        if pkt.haslayer(Dot11Beacon):
            if hasattr(pkt, 'info') and pkt.info:
                try:
                    ssid = pkt.info.decode('utf-8', errors='ignore')
                except:
                    ssid = str(pkt.info)
            if pkt.haslayer(Dot11WPA2):
                encryption = "WPA2"
            elif pkt.haslayer(Dot11WPA):
                encryption = "WPA"
        
        elif pkt.haslayer(Dot11ProbeResp):
            if hasattr(pkt, 'info') and pkt.info:
                try:
                    ssid = pkt.info.decode('utf-8', errors='ignore')
                except:
                    ssid = str(pkt.info)
            if pkt.haslayer(Dot11WPA2):
                encryption = "WPA2"
            elif pkt.haslayer(Dot11WPA):
                encryption = "WPA"
        
        elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
            if hasattr(pkt, 'info') and pkt.info:
                try:
                    ssid = pkt.info.decode('utf-8', errors='ignore')
                except:
                    ssid = str(pkt.info)
        
        if not ssid and hasattr(pkt, 'info') and pkt.info:
            try:
                ssid = pkt.info.decode('utf-8', errors='ignore')
            except:
                ssid = str(pkt.info)
        
        if not ssid or ssid == '' or ssid == ' ':
            return
        
        ssid = ssid.strip()
        if not ssid:
            return
        
        signal = 'N/A'
        if pkt.haslayer(RadioTap):
            radio = pkt[RadioTap]
            if hasattr(radio, 'dBm_AntSignal'):
                signal = radio.dBm_AntSignal
            elif hasattr(radio, 'dBm_AntNoise'):
                signal = radio.dBm_AntNoise
        
        if bssid not in networks:
            networks[bssid] = {
                'ssid': ssid,
                'bssid': bssid,
                'channel': 6,
                'signal': signal,
                'encryption': encryption
            }
            logger.debug(f"Found: {ssid} ({bssid}) - {encryption}")

    try:
        sniff(iface=interface, prn=packet_handler, timeout=timeout, store=False)
    except PermissionError:
        raise RuntimeError(f"Permission denied on {interface}. Run with sudo.")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return []

    logger.info(f"Found {len(networks)} networks")
    return list(networks.values())


def set_channel(interface: str, channel: int) -> None:
    """Set WiFi interface to a specific channel."""
    try:
        subprocess.run(['iwconfig', interface, 'channel', str(channel)], check=True, capture_output=True)
    except Exception as e:
        logger.warning(f"Failed to set channel: {e}")


def set_monitor_mode(interface: str) -> bool:
    """Put interface in monitor mode."""
    try:
        subprocess.run(['sudo', 'systemctl', 'stop', 'NetworkManager'], check=False)
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
        subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'monitor'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
        logger.info(f"✅ {interface} is now in monitor mode")
        return True
    except Exception as e:
        logger.error(f"Failed to set monitor mode: {e}")
        return False


def restore_managed_mode(interface: str) -> bool:
    """Restore interface to managed mode."""
    try:
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
        subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'managed'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
        subprocess.run(['sudo', 'systemctl', 'start', 'NetworkManager'], check=False)
        logger.info(f"✅ {interface} is back in managed mode")
        return True
    except Exception as e:
        logger.error(f"Failed to restore managed mode: {e}")
        return False