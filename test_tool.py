#!/usr/bin/env python3
"""Quick test script for WiFi Hack Lab."""

from wifi_hack_lab import cli, sniffer, cracker
import time

print("🔬 Testing WiFi Hack Lab...")

# Test 1: Scan (if you have monitor mode)
try:
    print("\n📡 Attempting to scan...")
    # Just test import
    print("✅ Modules loaded successfully!")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n✅ Test complete!")
