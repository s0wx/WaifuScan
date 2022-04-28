import logging

from pyshark import LiveCapture

from lib.PacketExtractor import PacketExtractor


class NetworkScan:
    def __init__(self, interface, extractor: PacketExtractor):
        """
        Used to scan network interfaces (e.g. en0 for Wi-Fi on macOS)

        :param interface: network interface to sniff
        """

        self.interface = interface
        self.capture_logger = logging.getLogger("[WaifuScan] (Network)")
        self.capture_logger.setLevel(level=logging.INFO)
        self.extractor = extractor

    def start_tls_cert_scan(self):
        """
        Start Network Scan for Certificates only considering "TLS Handshake Type Certificate".

        Extracted packets will be saved to Database if not tracked yet.

        :return:
        """

        capture = LiveCapture(interface=self.interface, display_filter="ssl.handshake.type==11")
        self.capture_logger.info(f" Starting LiveCapture on {self.interface}...")

        capture.apply_on_packets(self.extractor.extract_to_database, timeout=10000)
        capture.sniff(timeout=50)
