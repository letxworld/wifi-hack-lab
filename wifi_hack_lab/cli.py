"""Command-line interface for WiFi Hack Lab.

Provides the CLI entry points for all tool commands including:
scan, hack, analyze, estimate, and lab.
"""

import sys
import time
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .utils import setup_logging, ensure_dir, is_valid_bssid, is_valid_ssid, human_readable_time
from .sniffer import capture_handshake, scan_networks, set_channel
from .handshake import extract_handshake_data
from .cracker import crack_handshake, estimate_crack_time
from .visualizer import (
    display_results,
    display_scan_results,
    display_cracking_progress,
    display_estimate,
    display_welcome,
    confirm_action,
)
from .lab import WiFiLab, create_weak_password


def _common_setup(verbose: bool = False):
    """Initialize logging and display welcome banner."""
    logger = setup_logging(verbose)
    return logger


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
    """Capture handshake and attempt to crack the WiFi password.

    Runs the full attack pipeline: channel set → handshake capture →
    EAPOL extraction → dictionary attack → result display.
    """
    # Setup
    logger = _common_setup(verbose)
    display_welcome()

    if not confirm_action("This will attempt to crack a WiFi network. Proceed?"):
        return

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

    # Step 4: Display results using visualizer
    elapsed = time.time() - start_time
    display_results(
        password=password,
        elapsed=elapsed,
        pcap_path=str(pcap_path),
    )

    # Analyze password strength
    if password:
        strength = "weak" if len(password) < 8 else "medium" if len(password) < 12 else "strong"
        suggestions = []
        if len(password) < 8:
            suggestions.append("Short passwords are vulnerable to brute-force")
        if not any(c.isupper() for c in password):
            suggestions.append("No uppercase letters — easier to guess")
        if not any(c.isdigit() for c in password):
            suggestions.append("No digits — reduces search space")
        if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?`~" for c in password):
            suggestions.append("No symbols — reduces search space")

        if suggestions:
            click.echo(f"\n🔐 Strength analysis ({strength}):")
            for s in suggestions:
                click.echo(f"   • {s}")


@cli.command()
@click.option("--interface", "-i", required=True, help="Monitor interface (e.g., wlan0mon)")
@click.option("--timeout", "-t", default=30, type=int, help="Scan duration in seconds")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def scan(interface: str, timeout: int, verbose: bool):
    """Scan for nearby WiFi networks.

    Captures beacon frames to discover networks and displays
    SSID, BSSID, channel, signal strength, and encryption type.
    """
    _common_setup(verbose)
    click.echo(f"🔍 Scanning for networks on {interface}...")

    try:
        networks = scan_networks(interface, timeout)
    except Exception as e:
        click.echo(f"❌ Scan failed: {e}", err=True)
        sys.exit(1)

    if not networks:
        click.echo("No networks found. Ensure your interface is in monitor mode.")
        return

    # Display results using visualizer
    display_scan_results(networks)


@cli.command()
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("--bssid", "-b", required=True, help="Target AP BSSID")
@click.option("--ssid", "-s", required=True, help="Target AP SSID")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def analyze(pcap_path: str, bssid: str, ssid: str, verbose: bool):
    """Analyze a captured PCAP file for WPA2 handshake data.

    Extracts and displays EAPOL frame count, completion status,
    SNonce, ANonce, and MIC from the captured handshake.
    """
    _common_setup(verbose)
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

    if data.get('snonce'):
        click.echo(f"   SNonce: {data['snonce'][:16]}...")
    else:
        click.echo("   SNonce: (not available)")

    if data.get('anonce'):
        click.echo(f"   ANonce: {data['anonce'][:16]}...")
    else:
        click.echo("   ANonce: (not available)")

    if data.get('mic'):
        click.echo(f"   MIC: {data['mic'][:16]}...")
    else:
        click.echo("   MIC: (not available)")


@cli.command()
@click.argument("length", type=int, default=8)
@click.option("--charset", "-c", default="lower+upper+digits", help="Character set: lower, upper, digits, symbols")
@click.option("--speed", "-s", default=100000, type=float, help="Guesses per second (default: 100k)")
def estimate(length: int, charset: str, speed: float):
    """Estimate time to brute-force a password.

    Calculates the time needed to crack a password of a given length
    and complexity, based on the standard 100k guesses/second rate
    for pure Python PBKDF2-SHA1.
    """
    charset_size = 0
    if "lower" in charset:
        charset_size += 26
    if "upper" in charset:
        charset_size += 26
    if "digits" in charset:
        charset_size += 10
    if "symbols" in charset:
        charset_size += 33

    if charset_size == 0:
        click.echo("❌ No character sets specified. Use e.g. -c lower+upper+digits", err=True)
        sys.exit(1)

    time_seconds = estimate_crack_time(length, charset_size, speed)
    display_estimate(length, charset_size, time_seconds)


@cli.command()
@click.option("--interface", "-i", required=True, help="Wireless interface for AP mode")
@click.option("--ssid", "-s", default="TestAP", help="Network SSID")
@click.option("--password", "-p", default=None, help="WiFi password (auto-generate if not set)")
@click.option("--channel", "-c", default=6, type=int, help="WiFi channel")
@click.option("--timeout", "-t", default=120, type=int, help="Auto-stop after N seconds (0 = manual)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def lab(interface: str, ssid: str, password: str, channel: int, timeout: int, verbose: bool):
    """Create a test access point for safe, educational demos.

    Uses hostapd + dnsmasq to create an isolated WiFi network
    with a configurable weak password. Ideal for practicing
    handshake capture and cracking in a safe environment.
    """
    _common_setup(verbose)
    display_welcome()

    if not confirm_action("Start a test AP? This will create a visible WiFi network."):
        return

    # Generate a weak password if not provided
    if not password:
        password = create_weak_password()
        click.echo(f"🔑 Generated weak password: {password}")

    lab_instance = WiFiLab(
        interface=interface,
        ssid=ssid,
        password=password,
        channel=channel,
    )

    if not lab_instance.start():
        click.echo("❌ Failed to start lab")
        sys.exit(1)

    bssid = lab_instance.get_bssid()
    if bssid:
        click.echo(f"\n📡 BSSID: {bssid}")

    click.echo("\n" + "=" * 50)
    click.echo("✅ LAB IS RUNNING")
    click.echo("=" * 50)
    click.echo(f"📡 SSID: {ssid}")
    click.echo(f"🔑 Password: {password}")
    click.echo(f"📡 BSSID: {bssid or 'Unknown'}")
    click.echo("\n💡 Now test with:")
    click.echo(f"   wifi-hack-lab hack --interface wlan0mon --bssid {bssid or '<BSSID>'} --ssid {ssid}")
    click.echo("\n⚠️  Press Ctrl+C to stop the lab")

    try:
        if timeout > 0:
            click.echo(f"⏱️  Lab will auto-stop in {timeout} seconds")
            time.sleep(timeout)
            click.echo("\n⏱️  Timeout reached. Stopping lab...")
        else:
            # Wait indefinitely
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\n⚠️  Stopping lab...")
    finally:
        lab_instance.stop()
        click.echo("✅ Lab stopped")


def main():
    """Entry point for console_scripts."""
    cli()


if __name__ == "__main__":
    main()