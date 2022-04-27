import os
import logging
import pyshark

from lib.data_utilities import calculate_sha256_from_bytes
from lib.file_processing import save_certificate
from lib.packet_utilities import get_packet_tracing


def extract_tls_certificate_as_bytes(captured_packet):
    """
    Extracts only the certificate byte content from the packet as bytes

    :param captured_packet:
    :return:
    """

    cert_hex = captured_packet._all_fields["tls.handshake.certificate"].split(":")
    return bytes.fromhex("".join(cert_hex))


def extract_tls_cert_packets_from_file(file_path):
    capture = pyshark.FileCapture(file_path, display_filter="ssl.handshake.type==11")
    return [(capture_packet, capture_packet.tls) for capture_packet in capture if hasattr(capture_packet, 'tls')]


def extract_tls_cert_packets_from_livecapture(interface="en0"):
    capture_logger = logging.getLogger("LiveCaptureCertificates")
    capture_logger.setLevel(level=logging.INFO)

    capture = pyshark.LiveCapture(interface=interface, display_filter="ssl.handshake.type==11")
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


if __name__ == '__main__':
    logging.basicConfig()
    capture_filepath = "captures/non_vpn_refresh.pcapng"
    # full_extract_from_file(capture_filepath)
    extract_tls_cert_packets_from_livecapture("en0")
