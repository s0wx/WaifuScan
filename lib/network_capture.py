import logging
import os

from pyshark import LiveCapture

from lib.data_utilities import calculate_sha256_from_bytes
from lib.file_processing import save_certificate
from lib.mongo_utilities import certificate_database
from lib.packet_utilities import get_packet_tracing, extract_tls_certificate_as_bytes


class NetworkScan:
    def __init__(self, interface):
        self.interface = interface
        self.capture_logger = logging.getLogger("[WaifuScan] (Network)")
        self.capture_logger.setLevel(level=logging.INFO)

    def start_tls_cert_scan(self):
        """
        Start Network Scan for Certificates only considering "TLS Handshake Type Certificate".

        Extracted packets will be saved to Database if not tracked yet.

        :return:
        """

        capture = LiveCapture(interface=self.interface, display_filter="ssl.handshake.type==11")
        self.capture_logger.info(f"Starting LiveCapture on {self.interface}...")

        capture.apply_on_packets(single_live_packet_extraction_database, timeout=10000)
        capture.sniff(timeout=50)


def single_live_packet_extraction_local(packet):
    capture_logger = logging.getLogger("[WaifuScan] (Network)")
    capture_logger.setLevel(level=logging.INFO)

    if hasattr(packet, 'tls'):
        packet_full, packet_tls = packet, packet.tls
        _ = get_packet_tracing(packet_full, capture_logger)
        cert_data = extract_tls_certificate_as_bytes(packet_tls)
        certificate_hash = calculate_sha256_from_bytes(cert_data)
        if not os.path.exists(f"extracted_certificates/livecapture_cert_{certificate_hash}.crt"):
            save_certificate(cert_data, f"extracted_certificates/livecapture_cert_{certificate_hash}.crt")
            capture_logger.info("Saved new certificate")
        else:
            capture_logger.info("Already saved certificate before")


def single_live_packet_extraction_database(packet):
    capture_logger = logging.getLogger("[WaifuScan] (Network)")
    capture_logger.setLevel(level=logging.INFO)

    if hasattr(packet, 'tls'):
        packet_full, packet_tls = packet, packet.tls
        _ = get_packet_tracing(packet_full, capture_logger)
        cert_data = extract_tls_certificate_as_bytes(packet_tls)
        certificate_hash = calculate_sha256_from_bytes(cert_data)
        certificate_database.add_certificate({
            "sha256": certificate_hash,
            "certificateBytes": cert_data
        }, capture_logger)
