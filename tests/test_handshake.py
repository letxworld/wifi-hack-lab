"""Unit tests for the handshake parsing module."""

import pytest
from pathlib import Path
import tempfile
from unittest.mock import patch, MagicMock

from wifi_hack_lab.handshake import (
    extract_handshake_data,
    extract_pmkid,
    verify_mic,
    extract_handshake_from_pcap,
)
from wifi_hack_lab.utils import is_valid_bssid, is_valid_ssid


class TestHandshakeParsing:
    """Test handshake parsing functions."""

    def test_extract_handshake_data_missing_pcap(self):
        """Test extraction with missing PCAP file."""
        with pytest.raises(FileNotFoundError, match="PCAP not found"):
            extract_handshake_data(
                pcap_path=Path("/nonexistent.pcap"),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid="TestAP"
            )

    def test_extract_handshake_data_invalid_bssid(self):
        """Test extraction with invalid BSSID."""
        with pytest.raises(ValueError, match="Invalid BSSID"):
            extract_handshake_data(
                pcap_path=Path("dummy.pcap"),
                bssid="invalid",
                ssid="TestAP"
            )

    def test_extract_handshake_data_invalid_ssid(self):
        """Test extraction with invalid SSID."""
        with pytest.raises(ValueError, match="Invalid SSID"):
            extract_handshake_data(
                pcap_path=Path("dummy.pcap"),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid=""
            )

    @patch('wifi_hack_lab.handshake.rdpcap')
    def test_extract_handshake_data_no_eapol(self, mock_rdpcap):
        """Test extraction with PCAP containing no EAPOL packets."""
        # Mock an empty PCAP
        mock_rdpcap.return_value = []

        with tempfile.NamedTemporaryFile(suffix='.pcap') as tmp:
            result = extract_handshake_data(
                pcap_path=Path(tmp.name),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid="TestAP"
            )

        assert result['eapol_count'] == 0
        assert result['is_handshake_complete'] is False
        assert result['snonce'] == ''
        assert result['anonce'] == ''
        assert result['mic'] == ''
        assert result['eapol_frames'] == []

    @patch('wifi_hack_lab.handshake.rdpcap')
    def test_extract_handshake_data_with_eapol(self, mock_rdpcap):
        """Test extraction with PCAP containing EAPOL frames."""
        from scapy.all import EAPOL
        from scapy.packet import Packet

        # Create a mock packet that has EAPOL layer
        class MockKeyInfo:
            def __init__(self):
                self.key_ack = 1
                self.snonce = b'\x01' * 32
                self.anonce = b'\x02' * 32
                self.mic = b'\x03' * 16

        class MockEAPOLPayload:
            def __init__(self):
                self.key_ack = 1
                self.snonce = b'\x01' * 32
                self.anonce = b'\x02' * 32
                self.mic = b'\x03' * 16

        class MockEAPOL(Packet):
            name = "EAPOL"
            def __init__(self):
                super().__init__()
                self.payload = MockEAPOLPayload()

        class MockPacket(Packet):
            def __init__(self):
                super().__init__()
                self.addr2 = "AA:BB:CC:DD:EE:FF"
                self._eapol = MockEAPOL()

            def haslayer(self, layer):
                return layer == EAPOL

            def __getitem__(self, layer):
                if layer == EAPOL:
                    return self._eapol
                raise KeyError

        # Mock rdpcap to return 4 EAPOL packets
        mock_packets = [MockPacket() for _ in range(4)]
        mock_rdpcap.return_value = mock_packets

        with tempfile.NamedTemporaryFile(suffix='.pcap') as tmp:
            result = extract_handshake_data(
                pcap_path=Path(tmp.name),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid="TestAP"
            )

        assert result['eapol_count'] == 4
        assert result['is_handshake_complete'] is True
        assert result['snonce'] != ''
        assert result['anonce'] != ''
        assert result['mic'] != ''
        assert len(result['eapol_frames']) == 4

    @patch('wifi_hack_lab.handshake.rdpcap')
    def test_extract_handshake_data_partial(self, mock_rdpcap):
        """Test extraction with partial handshake (less than 4 EAPOL frames)."""
        from scapy.all import EAPOL
        from scapy.packet import Packet

        class MockEAPOLPayload:
            def __init__(self):
                self.key_ack = 1
                self.snonce = b'\x01' * 32
                self.anonce = b'\x02' * 32
                self.mic = b'\x03' * 16

        class MockEAPOL(Packet):
            name = "EAPOL"
            def __init__(self):
                super().__init__()
                self.payload = MockEAPOLPayload()

        class MockPacket(Packet):
            def __init__(self):
                super().__init__()
                self.addr2 = "AA:BB:CC:DD:EE:FF"
                self._eapol = MockEAPOL()

            def haslayer(self, layer):
                return layer == EAPOL

            def __getitem__(self, layer):
                if layer == EAPOL:
                    return self._eapol
                raise KeyError

        # Mock rdpcap to return only 2 EAPOL packets
        mock_packets = [MockPacket() for _ in range(2)]
        mock_rdpcap.return_value = mock_packets

        with tempfile.NamedTemporaryFile(suffix='.pcap') as tmp:
            result = extract_handshake_data(
                pcap_path=Path(tmp.name),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid="TestAP"
            )

        assert result['eapol_count'] == 2
        assert result['is_handshake_complete'] is False

    def test_extract_pmkid_placeholder(self):
        """Test PMKID extraction (placeholder)."""
        result = extract_pmkid(
            pcap_path=Path("dummy.pcap"),
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TestAP"
        )
        assert result is None

    def test_verify_mic_placeholder(self):
        """Test MIC verification (placeholder)."""
        result = verify_mic(
            pmk_hex="0123456789abcdef",
            eapol_frame_hex="abcdef0123456789"
        )
        assert result is True  # Placeholder

    @patch('wifi_hack_lab.handshake.extract_handshake_data')
    def test_extract_handshake_from_pcap(self, mock_extract):
        """Test the simplified handshake extraction."""
        mock_extract.return_value = {
            'pmk': '',
            'snonce': '01' * 16,
            'anonce': '02' * 16,
            'mic': '03' * 8,
            'eapol_frames': ['abc'],
            'is_handshake_complete': True,
            'eapol_count': 4,
        }

        with tempfile.NamedTemporaryFile(suffix='.pcap') as tmp:
            result = extract_handshake_from_pcap(
                pcap_path=Path(tmp.name),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid="TestAP"
            )

        assert result['snonce'] == '01' * 16
        assert result['anonce'] == '02' * 16
        assert result['is_handshake_complete'] is True

    @patch('wifi_hack_lab.handshake.rdpcap')
    def test_extract_handshake_data_non_hex_nonce(self, mock_rdpcap):
        """Test handshake extraction with non-hex nonce (should still work)."""
        from scapy.all import EAPOL
        from scapy.packet import Packet

        class MockEAPOLPayload:
            def __init__(self):
                self.key_ack = 1
                self.snonce = b'\xff' * 32  # Non-printable
                self.anonce = b'\xfe' * 32  # Non-printable
                self.mic = b'\x00' * 16

        class MockEAPOL(Packet):
            name = "EAPOL"
            def __init__(self):
                super().__init__()
                self.payload = MockEAPOLPayload()

        class MockPacket(Packet):
            def __init__(self):
                super().__init__()
                self.addr2 = "AA:BB:CC:DD:EE:FF"
                self._eapol = MockEAPOL()

            def haslayer(self, layer):
                return layer == EAPOL

            def __getitem__(self, layer):
                if layer == EAPOL:
                    return self._eapol
                raise KeyError

        mock_packets = [MockPacket() for _ in range(4)]
        mock_rdpcap.return_value = mock_packets

        with tempfile.NamedTemporaryFile(suffix='.pcap') as tmp:
            result = extract_handshake_data(
                pcap_path=Path(tmp.name),
                bssid="AA:BB:CC:DD:EE:FF",
                ssid="TestAP"
            )

        # Should still extract hex representation
        assert result['snonce'] != ''
        assert result['anonce'] != ''
        assert len(result['eapol_frames']) == 4