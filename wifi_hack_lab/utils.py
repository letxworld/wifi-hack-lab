"""Shared utilities for logging, file I/O, and validation."""

import logging
import sys
import gzip
from pathlib import Path
from typing import List, Optional

# --- Logging ---

def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> logging.Logger:
    """Configure logging with console and optional file output."""
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("wifi_hack_lab")
    logger.setLevel(level)

    # Clear any existing handlers
    logger.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console.setFormatter(formatter)
    logger.addHandler(console)

    # File handler (optional)
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# --- File I/O ---

def ensure_dir(path: Path) -> Path:
    """Create directory if it doesn't exist, return the path."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_wordlist(path: Path, allow_gz: bool = True) -> List[str]:
    """
    Load a wordlist from a text file or gzipped file.
    Returns a list of stripped lines (non-empty).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    lines = []
    open_func = gzip.open if (allow_gz and path.suffix == ".gz") else open

    with open_func(path, "rt", encoding="utf-8", errors="ignore") as f:
        for line in f:
            clean = line.strip()
            if clean and not clean.startswith("#"):
                lines.append(clean)

    return lines


def save_pcap(packets: list, output_path: Path) -> None:
    """Save a list of Scapy packets to a PCAP file."""
    from scapy.utils import wrpcap
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)


# --- Validation ---

def is_valid_bssid(bssid: str) -> bool:
    """Check if a string is a valid MAC address (e.g., AA:BB:CC:DD:EE:FF)."""
    import re
    pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    return bool(re.match(pattern, bssid))


def is_valid_ssid(ssid: str) -> bool:
    """Check if SSID is non-empty and under 32 bytes (WiFi limit)."""
    # Strip whitespace - a space-only SSID is not valid
    stripped = ssid.strip()
    return bool(stripped) and len(ssid.encode("utf-8")) <= 32


# --- Misc ---

def human_readable_time(seconds: float) -> str:
    """Convert seconds to human-readable string (e.g., '1m 23s')."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    mins, secs = divmod(seconds, 60)
    if mins < 60:
        return f"{int(mins)}m {int(secs)}s"
    hours, mins = divmod(mins, 60)
    return f"{int(hours)}h {int(mins)}m {int(secs)}s"