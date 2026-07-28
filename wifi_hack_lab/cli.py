"""Command-line interface for WiFi Hack Lab."""

import sys
import time
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .utils import setup_logging, ensure_dir, is_valid_bssid, is_valid_ssid
from .sniffer import capture_handshake, scan_networks, set_channel
from .handshake import extract_handshake_data
from .cracker import crack_handshake, estimate_crack_time
from .visualizer import display_results, display_scan_results, display_cracking_progress


@click.group()
@click.version_option(version=__version__, prog_name="wifi-hack-lab")
def cli():
    """WiFi Hack Lab — Educational WiFi security tool.
    
    Learn how WPA2 handshakes work by attacking your own network.
    Use only on networks you own or have explicit permission to test.
    """
    pass


@cli.command()
@click.option("--interface", "-i", required=True, help="Monitor interface (e.g., wlan0mon)")
@click.option("--bssid", "-b", required=True, help="Target AP BSSID (e.g., AA:BB:CC:DD:EE:FF)")
@click.option("--ssid", "-s", required=True, help="Target AP SSID")
@click.option("--wordlist", "-w", default="dictionaries/rockyou.txt", help="Path to wordlist file")
@click.option("--channel", "-c", default=6, type=int, help="WiFi channel")
@click.option("--timeout", "-t", default=60, type=int, help="Sniff timeout in seconds")
@click.option("--deauth", is_flag=True, help="Send deauth packets to force reconnection")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--output", "-o", default="captures", help="Output directory for PCAP files")
def hack(
    interface: str,
    bssid: str,
    ssid: str,
    wordlist: str,
    channel: int,
    timeout: int,
    deauth: bool,
    verbose: bool,
    output: str,
):
    """Capture handshake and attempt to crack the WiFi password."""
    # Setup logging
    logger = setup_logging(verbose)
    logger.info(f"WiFi Hack Lab v{__version__}")
    logger.info(f"Target: {ssid} ({bssid}) on channel {channel}")
    
    # Validate inputs
    if not is_valid_bssid(bssid):
        click.echo(f"❌ Invalid BSSID format: {bssid}", err=True)
        sys.exit(1)
    
    if not is_valid_ssid(ssid):
        click.echo(f"❌ Invalid SSID: {ssid}", err=True)
        sys.exit(1)
    
    # Check wordlist
    wordlist_path = Path(wordlist)
    if not wordlist_path.exists():
        click.echo(f"❌ Wordlist not found: {wordlist_path}", err=True)
        sys.exit(1)
    
    # Ensure output directory
    output_dir = ensure_dir(Path(output))
    
    # Set channel
    try:
        set_channel(interface, channel)
    except Exception as e:
        logger.warning(f"Failed to set channel: {e}")
        click.echo("⚠️  Ensure your interface is in monitor mode and channel is set correctly.", err=True)
    
    # Step 1: Capture handshake
    click.echo("\n📡 Capturing handshake...")
    try:
        pcap_path = capture_handshake(
            interface=interface,
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            timeout=timeout,
            deauth_attack=deauth,
            output_dir=output_dir,
        )
    except Exception as e:
        click.echo(f"❌ Capture failed: {e}", err=True)
        sys.exit(1)
    
    # Step 2: Extract handshake data
    click.echo("\n📋 Extracting handshake data...")
    try:
        handshake_data = extract_handshake_data(pcap_path, bssid, ssid)
        click.echo(f"   EAPOL frames: {handshake_data['eapol_count']}")
        click.echo(f"   Complete: {'✅' if handshake_data['is_handshake_complete'] else '⚠️'}")
    except Exception as e:
        click.echo(f"❌ Extraction failed: {e}", err=True)
        sys.exit(1)
    
    # Step 3: Crack the password
    click.echo(f"\n🔓 Starting dictionary attack using {wordlist_path}...")
    start_time = time.time()
    
    try:
        password = crack_handshake(
            pcap_path=pcap_path,
            ssid=ssid,
            wordlist_path=wordlist_path,
            bssid=bssid,
            verbose=verbose,
        )
    except Exception as e:
        click.echo(f"❌ Cracking failed: {e}", err=True)
        sys.exit(1)
    
    # Step 4: Display results
    elapsed = time.time() - start_time
    
    if password:
        click.echo("\n" + "=" * 50)
        click.echo(f"🔓 Password recovered: {password}")
        click.echo("=" * 50)
        click.echo(f"⏱️  Time: {elapsed:.2f} seconds")
        click.echo(f"📄 PCAP saved: {pcap_path}")
        
        # Analyze password strength
        strength = "weak" if len(password) < 8 else "medium" if len(password) < 12 else "strong"
        click.echo(f"🔐 Password strength: {strength}")
    else:
        click.echo("\n" + "=" * 50)
        click.echo("❌ Password not found in dictionary.")
        click.echo("=" * 50)
        click.echo("💡 Suggestions:")
        click.echo("   - Use a larger wordlist (e.g., rockyou.txt)")
        click.echo("   - Enable rule-based mutations")
        click.echo("   - Try brute-force for short passwords (< 8 chars)")
        click.echo(f"📄 PCAP saved: {pcap_path}")


@cli.command()
@click.option("--interface", "-i", required=True, help="Monitor interface (e.g., wlan0mon)")
@click.option("--timeout", "-t", default=30, type=int, help="Scan duration in seconds")
def scan(interface: str, timeout: int):
    """Scan for nearby WiFi networks."""
    logger = setup_logging(True)
    click.echo(f"🔍 Scanning for networks on {interface}...")
    
    try:
        networks = scan_networks(interface, timeout)
    except Exception as e:
        click.echo(f"❌ Scan failed: {e}", err=True)
        sys.exit(1)
    
    if not networks:
        click.echo("No networks found. Ensure your interface is in monitor mode.")
        return
    
    # Display results
    display_scan_results(networks)


@cli.command()
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("--bssid", "-b", required=True, help="Target AP BSSID")
@click.option("--ssid", "-s", required=True, help="Target AP SSID")
def analyze(pcap_path: str, bssid: str, ssid: str):
    """Analyze a captured PCAP file."""
    logger = setup_logging(True)
    pcap = Path(pcap_path)
    
    click.echo(f"📂 Analyzing {pcap}...")
    
    try:
        data = extract_handshake_data(pcap, bssid, ssid)
    except Exception as e:
        click.echo(f"❌ Analysis failed: {e}", err=True)
        sys.exit(1)
    
    click.echo("\n📊 Handshake Analysis:")
    click.echo(f"   EAPOL frames: {data['eapol_count']}")
    click.echo(f"   Complete: {'✅' if data['is_handshake_complete'] else '⚠️'}")
    click.echo(f"   SNonce: {data['snonce'][:16]}...")
    click.echo(f"   ANonce: {data['anonce'][:16]}...")


@cli.command()
@click.argument("length", type=int, default=8)
@click.option("--charset", "-c", default="lower+upper+digits", help="Character set: lower, upper, digits, symbols")
def estimate(length: int, charset: str):
    """Estimate time to brute-force a password."""
    charset_size = 26  # Default: lowercase
    if "upper" in charset:
        charset_size += 26
    if "digits" in charset:
        charset_size += 10
    if "symbols" in charset:
        charset_size += 33
    
    time_seconds = estimate_crack_time(length, charset_size)
    
    click.echo(f"🔐 Password length: {length}")
    click.echo(f"📊 Character set size: {charset_size}")
    click.echo(f"⏱️  Estimated crack time: {time_seconds:.2f} seconds")
    click.echo(f"   ({time_seconds/3600:.2f} hours)")


def main():
    """Entry point for console_scripts."""
    cli()


if __name__ == "__main__":
    main()