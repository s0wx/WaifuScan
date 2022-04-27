import logging
import os

from pyshark import LiveCapture

from lib.data_utilities import calculate_sha256_from_bytes
from lib.file_processing import save_certificate
from network_scan import single_live_packet_extraction


def livecapture_tls_cert(interface="en0"):
    capture_logger = logging.getLogger("LiveCaptureCertificates")
    capture_logger.setLevel(level=logging.INFO)

    capture = LiveCapture(interface=interface, display_filter="ssl.handshake.type==11")
    capture.set_debug()
    capture_logger.info(f"Selecting {interface} for live capture...")

    capture.apply_on_packets(single_live_packet_extraction, timeout=10000)
    capture.sniff(timeout=50)


def single_live_packet_extraction(packet):
    capture_logger = logging.getLogger("LiveCaptureCertificates (Packet)")
    capture_logger.setLevel(level=logging.INFO)

    if hasattr(packet, 'tls'):
        capture_logger.info("Found matching TLS Packet")
        packet_full, packet_tls = packet, packet.tls
        _ = get_packet_tracing(packet_full, capture_logger)
        cert_data = extract_tls_certificate_as_bytes(packet_tls)
        certificate_hash = calculate_sha256_from_bytes(cert_data)
        if not os.path.exists(f"extracted_certificates/livecapture_cert_{certificate_hash}.crt"):
            save_certificate(cert_data, f"extracted_certificates/livecapture_cert_{certificate_hash}.crt")
            capture_logger.info(f"Saved certificate as livecapture_cert_{certificate_hash}.crt\n")
        else:
            capture_logger.info("Not saving found detected certificate because already saved")
