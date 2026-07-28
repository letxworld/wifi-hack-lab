"""Unit tests for the sniffer module."""

import pytest
from pathlib import Path
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock

from wifi_hack_lab.sniffer import (
    capture_handshake,
    scan_networks,
    set_channel,
)
from wifi_hack_lab.utils import is_valid_bssid, is_valid_ssid


class MockElt:
    """Mock Dot11Elt element."""
    def __init__(self, eid: int, info: bytes):
        self.ID = eid
        self.info = info
        self.len = len(info)
        self.payload = None

    def haslayer(self, layer):
        return False


class MockRadiotap:
    """Mock RadioTap header."""
    def __init__(self, signal=-50):
        self.dBm_AntSignal = signal


class TestSniffer:
    """Test the sniffer functions."""

    def test_is_valid_bssid(self):
        """Test BSSID validation."""
        # Valid BSSIDs
        assert is_valid_bssid("AA:BB:CC:DD:EE:FF") is True
        assert is_valid_bssid("00:11:22:33:44:55") is True
        assert is_valid_bssid("aa:bb:cc:dd:ee:ff") is True
        assert is_valid_bssid("01:23:45:67:89:AB") is True

        # Invalid BSSIDs
        assert is_valid_bssid("") is False
        assert is_valid_bssid("AABBCCDDEEFF") is False  # Missing colons
        assert is_valid_bssid("AA:BB:CC:DD:EE") is False  # Too short
        assert is_valid_bssid("AA:BB:CC:DD:EE:FF:GG") is False  # Too long
        assert is_valid_bssid("AA:BB:CC:DD:EE:FF:") is False
        assert is_valid_bssid("XX:BB:CC:DD:EE:FF") is False  # Invalid hex

    def test_is_valid_ssid(self):
        """Test SSID validation."""
        # Valid SSIDs
        assert is_valid_ssid("MyWiFi") is True
        assert is_valid_ssid("Test") is True
        assert is_valid_ssid("A" * 32) is True  # Max length

        # Invalid SSIDs
        assert is_valid_ssid("") is False
        assert is_valid_ssid("A" * 33) is False  # Too long
        assert is_valid_ssid(" ") is False  # Space-only is not valid

    @patch('wifi_hack_lab.sniffer.sniff')
    def test_capture_handshake_timeout(self, mock_sniff):
        """Test handshake capture with timeout (no packets)."""
        # Mock sniff to do nothing (timeout)
        mock_sniff.side_effect = lambda **kwargs: None

        with tempfile.TemporaryDirectory() as tmpdir:
            result = capture_handshake(
                interface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                timeout=5,
                output_dir=Path(tmpdir)
            )
            # Should still save an empty PCAP
            assert result.exists()
            assert result.suffix == ".pcap"

    @patch('wifi_hack_lab.sniffer.sniff')
    def test_capture_handshake_incomplete(self, mock_sniff):
        """Test handshake capture with incomplete handshake."""
        from scapy.packet import Packet

        # Create a mock packet that matches BSSID
        class MockPacket(Packet):
            def __init__(self):
                super().__init__()
                self.addr2 = "AA:BB:CC:DD:EE:FF"
                self.addr1 = None
                self.addr3 = None

        mock_pkt = MockPacket()

        def sniff_side_effect(**kwargs):
            # Call prn with mock packet 3 times (incomplete)
            for _ in range(3):
                kwargs['prn'](mock_pkt)

        mock_sniff.side_effect = sniff_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            result = capture_handshake(
                interface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                timeout=10,
                output_dir=Path(tmpdir)
            )

            # Should still save the partial handshake
            assert result.exists()
            assert result.suffix == ".pcap"

    @patch('wifi_hack_lab.sniffer.sniff')
    def test_capture_handshake_complete(self, mock_sniff):
        """Test handshake capture with complete handshake."""
        from scapy.packet import Packet

        # Create mock packets
        class MockPacket(Packet):
            def __init__(self):
                super().__init__()
                self.addr2 = "AA:BB:CC:DD:EE:FF"
                self.addr1 = None
                self.addr3 = None

        def sniff_side_effect(**kwargs):
            # Call prn with mock packet 4 times (complete)
            for _ in range(4):
                kwargs['prn'](MockPacket())

        mock_sniff.side_effect = sniff_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            result = capture_handshake(
                interface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                timeout=10,
                output_dir=Path(tmpdir)
            )

            assert result.exists()
            assert result.suffix == ".pcap"

    def test_capture_handshake_invalid_bssid(self):
        """Test capture_handshake with invalid BSSID."""
        with pytest.raises(ValueError, match="Invalid BSSID"):
            capture_handshake(
                interface="wlan0mon",
                bssid="invalid",
                ssid="TestAP"
            )

    def test_capture_handshake_invalid_ssid(self):
        """Test capture_handshake with invalid SSID."""
        with pytest.raises(ValueError, match="Invalid SSID"):
            capture_handshake(
                interface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                ssid=""
            )

    class MockBeaconPacket:
        """Simulated beacon packet for testing scan_networks."""
        def __init__(self, ssid: str, bssid: str, channel: int = 6, signal: int = -50):
            self.addr2 = bssid
            self._ssid = ssid
            self._channel = channel
            self._signal = signal

        def haslayer(self, layer):
            from scapy.all import Dot11Beacon, RadioTap, Dot11Elt
            return layer in (Dot11Beacon, RadioTap, Dot11Elt)

        def __getitem__(self, layer):
            from scapy.all import Dot11Beacon, RadioTap, Dot11Elt
            if layer == Dot11Beacon:
                return self
            if layer == RadioTap:
                return MockRadiotap(self._signal)
            if layer == Dot11Elt:
                # Create SSID element
                ssid_elt = MockElt(0, self._ssid.encode())
                # Create channel element
                ch_elt = MockElt(3, bytes([self._channel]))
                # Chain them
                ssid_elt.payload = ch_elt
                return ssid_elt
            raise KeyError(layer)

        @property
        def cap(self):
            """Mock capabilities."""
            class Cap:
                privacy = False
            return Cap()

    @patch('wifi_hack_lab.sniffer.sniff')
    def test_scan_networks(self, mock_sniff):
        """Test network scanning."""
        def sniff_side_effect(**kwargs):
            networks = [
                ("Network1", "AA:BB:CC:DD:EE:11", 1, -45),
                ("Network2", "AA:BB:CC:DD:EE:22", 6, -60),
                ("Network3", "AA:BB:CC:DD:EE:33", 11, -75),
            ]
            for ssid, bssid, ch, sig in networks:
                beacon = self.MockBeaconPacket(ssid, bssid, ch, sig)
                kwargs['prn'](beacon)

        mock_sniff.side_effect = sniff_side_effect

        results = scan_networks("wlan0mon", timeout=5)
        assert len(results) >= 3
        assert any(net['ssid'] == "Network1" for net in results)

    @patch('subprocess.run')
    def test_set_channel(self, mock_subprocess):
        """Test setting WiFi channel."""
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        set_channel("wlan0mon", 6)
        mock_subprocess.assert_called_once_with(
            ['iwconfig', 'wlan0mon', 'channel', '6'],
            check=True,
            capture_output=True,
            text=True,
        )

    @patch('subprocess.run')
    def test_set_channel_failure(self, mock_subprocess, caplog):
        """Test channel setting failure."""
        import subprocess
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'iwconfig', stderr=b'Error')

        with pytest.raises(RuntimeError, match="Could not set channel"):
            set_channel("wlan0mon", 6)

    @patch('wifi_hack_lab.sniffer.sniff')
    def test_capture_handshake_permission_error(self, mock_sniff):
        """Test permission error when sniffing."""
        mock_sniff.side_effect = PermissionError("Permission denied")

        with pytest.raises(RuntimeError, match="Permission denied"):
            capture_handshake(
                interface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                timeout=5
            )

    @patch('wifi_hack_lab.sniffer.sniff')
    def test_capture_handshake_general_error(self, mock_sniff):
        """Test general error during sniffing."""
        mock_sniff.side_effect = Exception("Something went wrong")

        with pytest.raises(RuntimeError, match="Sniffing failed"):
            capture_handshake(
                interface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                timeout=5
            )

    def test_capture_output_directory_creation(self, tmp_path):
        """Test that output directory is created if it doesn't exist."""
        from wifi_hack_lab.utils import ensure_dir

        new_dir = tmp_path / "captures" / "subdir"
        ensure_dir(new_dir)
        assert new_dir.exists()
        assert new_dir.is_dir()