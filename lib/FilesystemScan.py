import logging

from pyshark import FileCapture

from lib.PacketExtractor import PacketExtractor


class FilesystemScan:
    def __init__(self, extractor: PacketExtractor):
        """
        Used to scan the local file system or specific files
        """

        self.capture_logger = logging.getLogger("[WaifuScan] (Network)")
        self.capture_logger.setLevel(level=logging.INFO)
        self.extractor = extractor

    def scan_tls_cert_packets_from_traffic_dump(self, file_path):
        """
        Extract certificates from network capture file (e.g. .pcapng)

        :param file_path: file path to capture file
        :return: all found relevant packages for further processing
        """

        capture = FileCapture(file_path, display_filter="ssl.handshake.type==11")
        return [(capture_packet, capture_packet.tls) for capture_packet in capture if hasattr(capture_packet, 'tls')]
