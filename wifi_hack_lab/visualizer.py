"""Rich terminal output for WiFi Hack Lab.

Provides formatted display functions for scan results, cracking progress,
brute-force estimates, welcome banners, and confirmation prompts.
"""

from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.align import Align
from rich.layout import Layout
from rich.live import Live
from rich.prompt import Confirm, Prompt
from rich import box

console = Console()


def display_welcome():
    """Display the ASCII art welcome banner with legal disclaimer."""
    banner = """
[bold cyan]
██╗    ██╗██╗███████╗██╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗
██║    ██║██║██╔════╝██║    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
██║ █╗ ██║██║█████╗  ██║    ███████║███████║██║     █████╔╝
██║███╗██║██║██╔══╝  ██║    ██╔══██║██╔══██║██║     ██╔═██╗
╚███╔███╔╝██║██║     ██║    ██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
[/bold cyan]
[bold yellow]⚠️  LEGAL DISCLAIMER[/bold yellow]
[italic]This tool is for EDUCATIONAL PURPOSES only.
Use only on networks you OWN or have EXPLICIT PERMISSION to test.
Unauthorized access to WiFi networks is ILLEGAL and unethical.
The authors assume NO LIABILITY for misuse of this software.[/italic]
"""
    console.print(banner)
    console.print()


def confirm_action(message: str, default: bool = False) -> bool:
    """Ask the user to confirm an action before proceeding.

    Args:
        message: The confirmation prompt text.
        default: Default response if user presses Enter.

    Returns:
        True if confirmed, False otherwise.
    """
    return Confirm.ask(f"\n[bold yellow]⚠️  {message}[/bold yellow]", default=default)


def display_cracking_progress(
    current: int,
    total: int,
    found: Optional[str] = None,
    speed: Optional[float] = None,
    eta: Optional[str] = None,
):
    """Display real-time cracking progress.

    Shows a progress bar with percentage, count, speed, and ETA.
    If a password is found, displays it in green.

    Args:
        current: Number of passwords checked.
        total: Total passwords in wordlist.
        found: Recovered password (if any).
        speed: Passwords per second (optional).
        eta: Estimated time remaining string (optional).
    """
    if found:
        console.print(f"\n[bold green]✅ Password found: {found}[/bold green]")
        return

    if total <= 0:
        return

    percent = (current / total * 100)
    bar_width = 30
    filled = int(bar_width * percent / 100)
    bar = f"[{'#' * filled}{'-' * (bar_width - filled)}]"

    info = f"   {bar} {percent:.1f}% ({current:,}/{total:,})"
    if speed is not None:
        info += f" @ {speed:.0f} pwd/s"
    if eta:
        info += f" ETA: {eta}"

    console.print(info, end="\r")


def display_results(
    password: Optional[str],
    elapsed: float,
    pcap_path: Optional[str] = None,
    speed: Optional[float] = None,
):
    """Display final cracking results in a formatted panel.

    Args:
        password: Recovered password (None if not found).
        elapsed: Time elapsed in seconds.
        pcap_path: Path to the PCAP file (optional).
        speed: Average cracking speed in pwd/s (optional).
    """
    if password:
        strength = (
            "Weak" if len(password) < 8
            else "Medium" if len(password) < 12
            else "Strong"
        )
        content = (
            f"[bold green]✅ Password recovered![/bold green]\n\n"
            f"[bold]Password:[/bold] {password}\n"
            f"[bold]Time:[/bold] {elapsed:.2f} seconds\n"
            f"[bold]Strength:[/bold] {strength}\n"
        )
        if speed:
            content += f"[bold]Speed:[/bold] {speed:.0f} pwd/s\n"
        if pcap_path:
            content += f"[bold]PCAP:[/bold] {pcap_path}\n"
        panel = Panel(content, title="🔓 Success", border_style="green")
    else:
        content = (
            f"[bold red]❌ Password not found.[/bold red]\n\n"
            f"[bold]Time:[/bold] {elapsed:.2f} seconds\n"
        )
        if speed:
            content += f"[bold]Speed:[/bold] {speed:.0f} pwd/s\n"
        if pcap_path:
            content += f"[bold]PCAP:[/bold] {pcap_path}\n"
        content += (
            f"\n[bold]Suggestions:[/bold]\n"
            f"  • Use a larger wordlist (e.g., rockyou.txt)\n"
            f"  • Enable rule-based mutations\n"
            f"  • Try brute-force for short passwords (< 8 chars)\n"
        )
        panel = Panel(content, title="❌ Failure", border_style="red")

    console.print(panel)


def display_scan_results(networks: List[Dict[str, Any]]):
    """Display scanned networks in a formatted table.

    Shows SSID, BSSID, channel, signal strength, and encryption type
    for each discovered network.

    Args:
        networks: List of network dicts with keys: ssid, bssid, channel,
                  signal, encryption.
    """
    if not networks:
        console.print("[yellow]No networks found.[/yellow]")
        return

    table = Table(
        title="📡 Nearby WiFi Networks",
        style="bright_blue",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("SSID", style="bold green", no_wrap=True)
    table.add_column("BSSID", style="dim", no_wrap=True)
    table.add_column("Ch", justify="center")
    table.add_column("Signal", justify="right")
    table.add_column("Encryption", style="yellow")

    for net in networks[:20]:
        ssid = net.get('ssid', '<Hidden>')
        bssid = net.get('bssid', 'Unknown')
        channel = net.get('channel', '?')
        signal = net.get('signal', 'N/A')
        encryption = net.get('encryption', 'Unknown')

        # Color signal strength
        signal_str = str(signal)
        if isinstance(signal, (int, float)):
            if signal > -50:
                signal_str = f"[green]{signal}[/green]"
            elif signal > -70:
                signal_str = f"[yellow]{signal}[/yellow]"
            else:
                signal_str = f"[red]{signal}[/red]"

        table.add_row(ssid, bssid, str(channel), signal_str, encryption)

    console.print(table)
    if len(networks) > 20:
        console.print(f"[dim]... and {len(networks) - 20} more networks[/dim]")


def display_estimate(length: int, charset_size: int, time_seconds: float):
    """Display brute-force time estimate in a formatted panel.

    Args:
        length: Password length.
        charset_size: Number of possible characters.
        time_seconds: Estimated time in seconds.
    """
    # Convert to human-readable format
    if time_seconds < 60:
        time_str = f"{time_seconds:.2f} seconds"
    elif time_seconds < 3600:
        time_str = f"{time_seconds/60:.2f} minutes"
    elif time_seconds < 86400:
        time_str = f"{time_seconds/3600:.2f} hours"
    elif time_seconds < 31536000:
        time_str = f"{time_seconds/86400:.2f} days"
    else:
        time_str = f"{time_seconds/31536000:.2f} years"

    combinations = charset_size ** length

    panel = Panel(
        f"[bold]Password length:[/bold] {length}\n"
        f"[bold]Character set:[/bold] {charset_size} characters\n"
        f"[bold]Combinations:[/bold] {combinations:,}\n"
        f"[bold]Estimated time:[/bold] {time_str}\n\n"
        f"[dim]Assuming {combinations:,} combinations at 100k guesses/sec[/dim]",
        title="⏱️ Brute-Force Estimate",
        border_style="yellow",
    )
    console.print(panel)