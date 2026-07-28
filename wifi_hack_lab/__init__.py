"""WiFi Hack Lab — Educational WiFi Security Tool

This package provides tools to capture WPA2 handshakes and perform
dictionary-based password cracking for educational purposes.
"""

__version__ = "0.1.0"
__author__ = "Your Name <you@example.com>"

# Optionally expose core functions at package level for cleaner imports
# from ._core import compute_pmk, verify_passphrase, crack_batch

# Import submodules so they're available when you import the package
from . import cli
from . import sniffer
from . import handshake
from . import cracker
from . import visualizer
from . import lab
from . import utils

__all__ = [
    "cli",
    "sniffer",
    "handshake",
    "cracker",
    "visualizer",
    "lab",
    "utils",
]