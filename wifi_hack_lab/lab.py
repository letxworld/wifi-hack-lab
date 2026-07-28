"""Lab mode — spin up a test AP for safe, isolated WiFi hacking demonstrations."""

import subprocess
import time
import tempfile
import os
import signal
import atexit
from pathlib import Path
from typing import Optional, Dict, Any
import random
import string

from .utils import setup_logging, ensure_dir

logger = setup_logging()


class WiFiLab:
    """
    Create an isolated test WiFi network for educational demonstrations.
    
    Uses hostapd + dnsmasq to create a fake AP with a configurable weak password.
    All traffic is contained within the test environment.
    """
    
    def __init__(
        self,
        interface: str,
        ssid: str = "TestAP",
        password: str = "password123",
        channel: int = 6,
        ip_range: str = "192.168.100.0/24",
    ):
        """
        Initialize the WiFi lab.
        
        Args:
            interface: Wireless interface (must support AP mode)
            ssid: Network name
            password: WiFi password (weak for demonstration)
            channel: WiFi channel
            ip_range: DHCP IP range
        """
        self.interface = interface
        self.ssid = ssid
        self.password = password
        self.channel = channel
        self.ip_range = ip_range
        
        # Check if interface supports AP mode
        self._check_interface()
        
        # Temporary config files
        self.temp_dir = tempfile.mkdtemp(prefix="wifi_lab_")
        self.hostapd_conf = Path(self.temp_dir) / "hostapd.conf"
        self.dnsmasq_conf = Path(self.temp_dir) / "dnsmasq.conf"
        self.hostapd_pid = None
        self.dnsmasq_pid = None
        
        # Register cleanup on exit
        atexit.register(self.stop)
    
    def _check_interface(self):
        """Check if interface is available and supports AP mode."""
        try:
            result = subprocess.run(
                ['iw', 'dev', self.interface, 'info'],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise RuntimeError(f"Interface {self.interface} not found or not wireless")
            
            # Check if interface supports AP mode
            result = subprocess.run(
                ['iw', 'list'],
                capture_output=True,
                text=True
            )
            if "AP" not in result.stdout:
                logger.warning(f"Interface {self.interface} may not support AP mode")
        except FileNotFoundError:
            logger.warning("iw not found. Ensure interface is set up for AP mode.")
    
    def _write_configs(self):
        """Write hostapd and dnsmasq configuration files."""
        # hostapd config
        hostapd_content = f"""interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
wpa=2
wpa_passphrase={self.password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
        self.hostapd_conf.write_text(hostapd_content)
        
        # dnsmasq config (DHCP server)
        dnsmasq_content = f"""interface={self.interface}
dhcp-range={self.ip_range.split('/')[0].replace('.0', '.10')},{self.ip_range.split('/')[0].replace('.0', '.100')},12h
dhcp-option=3,{self.ip_range.split('/')[0].replace('.0', '.1')}
dhcp-option=6,8.8.8.8,1.1.1.1
"""
        self.dnsmasq_conf.write_text(dnsmasq_content)
        
        logger.debug(f"Configs written to {self.temp_dir}")
    
    def start(self) -> bool:
        """Start the test AP."""
        if self.is_running():
            logger.warning("Lab is already running")
            return False
        
        logger.info(f"🚀 Starting WiFi Lab: {self.ssid} (password: {self.password})")
        logger.info(f"   Interface: {self.interface}, Channel: {self.channel}")
        
        # Write configs
        self._write_configs()
        
        # Set interface up
        subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=False)
        
        # Assign IP address
        subprocess.run([
            'ip', 'addr', 'add',
            f"{self.ip_range.split('/')[0].replace('.0', '.1')}/24",
            'dev', self.interface
        ], check=False)
        
        # Start dnsmasq (DHCP)
        try:
            self.dnsmasq_pid = subprocess.Popen([
                'dnsmasq',
                '--no-daemon',
                '--conf-file', str(self.dnsmasq_conf),
                '--pid-file', '/tmp/dnsmasq-wifi-lab.pid'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.debug("DHCP server started")
        except FileNotFoundError:
            logger.warning("dnsmasq not found. DHCP may not work.")
        
        # Start hostapd (AP)
        try:
            self.hostapd_pid = subprocess.Popen([
                'hostapd',
                '-B',  # Run in background
                str(self.hostapd_conf),
                '-P', '/tmp/hostapd-wifi-lab.pid'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info("✅ Access Point started")
        except FileNotFoundError:
            logger.error("❌ hostapd not found. Install: sudo apt install hostapd")
            self.stop()
            return False
        
        # Wait for AP to fully start
        time.sleep(2)
        
        logger.info(f"📡 SSID: {self.ssid}")
        logger.info(f"🔑 Password: {self.password}")
        logger.info("💡 Now run: wifi-hack-lab hack --interface wlan0mon --bssid <BSSID> --ssid TestAP")
        
        return True
    
    def stop(self):
        """Stop the test AP and clean up."""
        if not self.is_running():
            return
        
        logger.info("🛑 Stopping WiFi Lab...")
        
        # Kill hostapd
        if self.hostapd_pid:
            try:
                os.kill(self.hostapd_pid.pid, signal.SIGTERM)
                self.hostapd_pid.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        
        # Kill dnsmasq
        if self.dnsmasq_pid:
            try:
                os.kill(self.dnsmasq_pid.pid, signal.SIGTERM)
                self.dnsmasq_pid.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        
        # Remove IP address
        subprocess.run([
            'ip', 'addr', 'del',
            f"{self.ip_range.split('/')[0].replace('.0', '.1')}/24",
            'dev', self.interface
        ], check=False)
        
        # Clean up temp files
        subprocess.run(['rm', '-rf', self.temp_dir], check=False)
        
        logger.info("✅ Lab stopped")
    
    def is_running(self) -> bool:
        """Check if the lab is currently running."""
        if self.hostapd_pid:
            return self.hostapd_pid.poll() is None
        return False
    
    def get_bssid(self) -> Optional[str]:
        """Get the BSSID of the test AP."""
        try:
            result = subprocess.run(
                ['iw', 'dev', self.interface, 'info'],
                capture_output=True,
                text=True
            )
            for line in result.stdout.split('\n'):
                if 'addr' in line:
                    return line.split()[-1]
        except Exception:
            pass
        return None


def create_weak_password(length: int = 8) -> str:
    """Generate a weak, predictable password for demonstration."""
    # Common patterns: word + numbers + symbol
    words = ['password', 'admin', 'wifi', 'network', 'test', 'default', 'qwerty', 'letmein']
    word = random.choice(words)
    digits = ''.join(random.choices(string.digits, k=3))
    symbols = random.choice(['!', '@', '#', '$', '&'])
    return f"{word}{digits}{symbols}"


def lab_cli():
    """CLI command for setting up a test lab."""
    import click
    
    @click.command()
    @click.option("--interface", "-i", required=True, help="Wireless interface for AP mode")
    @click.option("--ssid", "-s", default="TestAP", help="Network SSID")
    @click.option("--password", "-p", default=None, help="WiFi password (auto-generate if not set)")
    @click.option("--channel", "-c", default=6, help="WiFi channel")
    @click.option("--timeout", "-t", default=120, help="Auto-stop after N seconds (0 = manual)")
    def start_lab(interface, ssid, password, channel, timeout):
        """Start a test AP for educational hacking demonstrations."""
        from .visualizer import display_welcome, confirm_action
        
        display_welcome()
        
        if not confirm_action("Start the test lab? This will create a fake WiFi network."):
            return
        
        # Generate a weak password if not provided
        if not password:
            password = create_weak_password()
            click.echo(f"🔑 Generated weak password: {password}")
        
        lab = WiFiLab(
            interface=interface,
            ssid=ssid,
            password=password,
            channel=channel
        )
        
        if not lab.start():
            click.echo("❌ Failed to start lab")
            return
        
        bssid = lab.get_bssid()
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
            lab.stop()
            click.echo("✅ Lab stopped")
    
    return start_lab


# Add lab command to CLI
if __name__ == "__main__":
    lab_cli()()