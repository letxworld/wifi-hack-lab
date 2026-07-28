#!/bin/bash
# Download the rockyou.txt wordlist for WiFi Hack Lab

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST_DIR="$SCRIPT_DIR/../dictionaries"
WORDLIST_FILE="$WORDLIST_DIR/rockyou.txt"
WORDLIST_GZ="$WORDLIST_DIR/rockyou.txt.gz"

echo "📚 Downloading rockyou.txt wordlist..."
echo "   This is the most common password dictionary for penetration testing."

# Create dictionaries directory if it doesn't exist
mkdir -p "$WORDLIST_DIR"

# Check if wordlist already exists
if [ -f "$WORDLIST_FILE" ]; then
    echo "✅ Wordlist already exists at $WORDLIST_FILE"
    exit 0
fi

# Download from the official source (brannondorsey's mirror)
echo "⬇️  Downloading from https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
curl -L -o "$WORDLIST_GZ" "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

# Unzip
echo "📦 Extracting..."
gunzip -f "$WORDLIST_GZ"

# Verify
if [ -f "$WORDLIST_FILE" ]; then
    LINES=$(wc -l < "$WORDLIST_FILE")
    echo "✅ Downloaded successfully! ($LINES passwords)"
else
    echo "❌ Download failed."
    exit 1
fi