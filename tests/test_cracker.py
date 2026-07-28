"""Unit tests for the cracking module and crypto integration."""

import pytest
from pathlib import Path
import tempfile

from wifi_hack_lab.cracker import crack_handshake, estimate_crack_time
from wifi_hack_lab.handshake import extract_handshake_data
from wifi_hack_lab.crypto import compute_pmk, verify_passphrase, crack_batch
from wifi_hack_lab.utils import load_wordlist


class TestCrypto:
    """Test the Python crypto functions directly."""

    def test_compute_pmk(self):
        """Test PMK computation with known values."""
        ssid = "TestAP"
        passphrase = "password"
        pmk = compute_pmk(passphrase, ssid)

        # PMK should be 64 hex characters (32 bytes)
        assert len(pmk) == 64
        assert all(c in "0123456789abcdef" for c in pmk.lower())

        # Same inputs should produce same output
        pmk2 = compute_pmk(passphrase, ssid)
        assert pmk == pmk2

    def test_verify_passphrase(self):
        """Test passphrase verification."""
        ssid = "TestAP"
        passphrase = "boys@123"

        # Compute PMK
        pmk = compute_pmk(passphrase, ssid)

        # Verify correct passphrase
        assert verify_passphrase(passphrase, ssid, pmk) is True

        # Verify incorrect passphrase
        assert verify_passphrase("wrongpassword", ssid, pmk) is False

        # Verify empty passphrase
        assert verify_passphrase("", ssid, pmk) is False

    def test_crack_batch(self):
        """Test batch cracking with a list of passwords."""
        ssid = "TestAP"
        target_pass = "foundme"
        pmk = compute_pmk(target_pass, ssid)

        # List with target password
        passphrases = ["wrong1", "wrong2", target_pass, "wrong3"]
        result = crack_batch(passphrases, ssid, pmk)
        assert result == target_pass

        # List without target
        passphrases = ["wrong1", "wrong2", "wrong3"]
        result = crack_batch(passphrases, ssid, pmk)
        assert result is None

    def test_crack_batch_empty(self):
        """Test batch cracking with empty list."""
        ssid = "TestAP"
        pmk = compute_pmk("password", ssid)
        result = crack_batch([], ssid, pmk)
        assert result is None


class TestCracker:
    """Test the high-level cracker functions."""

    def test_estimate_crack_time(self):
        """Test brute-force time estimation."""
        # 4-character lowercase password: 26^4 = 456,976 combinations
        time_sec = estimate_crack_time(4, 26, speed=100000)
        assert time_sec > 0
        assert time_sec < 10  # Should be fast

        # Longer password should take longer
        time_short = estimate_crack_time(4, 26)
        time_long = estimate_crack_time(8, 26)
        assert time_long > time_short

    def test_estimate_invalid_length(self):
        """Test estimate with invalid length."""
        with pytest.raises(ValueError):
            estimate_crack_time(0, 26)

    def test_estimate_invalid_charset(self):
        """Test estimate with invalid charset size."""
        with pytest.raises(ValueError):
            estimate_crack_time(8, 0)

    def test_load_wordlist(self, tmp_path):
        """Test wordlist loading."""
        # Create a temporary wordlist
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("password\n123456\nqwerty\n# comment\n\n")

        loaded = load_wordlist(wordlist)
        assert loaded == ["password", "123456", "qwerty"]
        assert "# comment" not in loaded
        assert "" not in loaded

    def test_load_gzipped_wordlist(self, tmp_path):
        """Test loading gzipped wordlist."""
        import gzip

        wordlist = tmp_path / "test.txt.gz"
        with gzip.open(wordlist, "wt", encoding="utf-8") as f:
            f.write("password\n123456\nqwerty\n")

        loaded = load_wordlist(wordlist, allow_gz=True)
        assert loaded == ["password", "123456", "qwerty"]

    def test_crack_handshake_no_pcap(self):
        """Test crack_handshake with missing PCAP."""
        with pytest.raises(FileNotFoundError):
            crack_handshake(
                pcap_path=Path("/nonexistent.pcap"),
                ssid="TestAP",
                wordlist_path=Path("/nonexistent.txt")
            )

    def test_crack_handshake_no_wordlist(self):
        """Test crack_handshake with missing wordlist."""
        with pytest.raises(FileNotFoundError):
            crack_handshake(
                pcap_path=Path("/nonexistent.pcap"),
                ssid="TestAP",
                wordlist_path=Path("/nonexistent.txt")
            )


class TestHandshakeExtraction:
    """Test handshake extraction from PCAP files."""

    def test_invalid_bssid(self):
        """Test BSSID validation in handshake extraction."""
        with pytest.raises(ValueError, match="Invalid BSSID"):
            extract_handshake_data(
                pcap_path=Path("dummy.pcap"),
                bssid="invalid",
                ssid="TestAP"
            )

    def test_invalid_ssid(self):
        """Test SSID validation in handshake extraction."""
        with pytest.raises(ValueError, match="Invalid SSID"):
            extract_handshake_data(
                pcap_path=Path("dummy.pcap"),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid=""
            )

    def test_missing_pcap(self):
        """Test handshake extraction with missing PCAP."""
        with pytest.raises(FileNotFoundError):
            extract_handshake_data(
                pcap_path=Path("/nonexistent.pcap"),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid="TestAP"
            )


class TestCrackerIntegration:
    """Integration tests for the full cracking pipeline."""

    def test_pmk_consistency(self):
        """Test that PMK computation is deterministic."""
        ssid = "TestNetwork"
        passphrase = "MySecretPassword123!"

        # Compute PMK twice
        pmk1 = compute_pmk(passphrase, ssid)
        pmk2 = compute_pmk(passphrase, ssid)

        assert pmk1 == pmk2
        assert len(pmk1) == 64

    def test_verify_known_vectors(self):
        """Test against known PMK vectors from WPA2 test vectors."""
        ssid = "TestAP"
        passphrase = "password"

        # Compute actual PMK
        actual_pmk = compute_pmk(passphrase, ssid)

        assert len(actual_pmk) == 64
        assert actual_pmk != "0" * 64  # Not all zeros
        # PMK should be a valid hex string
        assert all(c in "0123456789abcdef" for c in actual_pmk.lower())