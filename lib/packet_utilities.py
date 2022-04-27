import logging
import os
from datetime import datetime
from pyshark import FileCapture, LiveCapture

from lib.data_utilities import calculate_sha256_from_bytes
from lib.file_processing import save_certificate


def get_packet_timestamp(sniffed_packet):
    """
    Returns the sniff_timestamp as readable date format

    :param sniffed_packet: packet to track
    :return: packet date as string
    """

    return str(datetime.fromtimestamp(float(sniffed_packet.sniff_timestamp)))


def get_packet_tracing(sniffed_packet, logger):
    """
    Get SRC and DST data from traced packet

    :param sniffed_packet: packet to check
    :param logger: logging instance
    :return: dictionary of of packet trace data
    """

    src_address_ipv4 = None
    src_address_ipv6 = None
    dst_address_ipv4 = None
    dst_address_ipv6 = None

    src_port = None
    dst_port = None

    # track src and dst ports of packet
    if hasattr(sniffed_packet, 'tcp'):
        tcp_data = sniffed_packet.tcp
        src_port = tcp_data.srcport
        dst_port = tcp_data.dstport

    if hasattr(sniffed_packet, 'ip'):
        # packet contains at least one IPv4 address
        ip_data = sniffed_packet.ip

        if hasattr(ip_data, 'src'):
            src_address_ipv4 = ip_data.src
        if hasattr(ip_data, 'dst'):
            dst_address_ipv4 = ip_data.dst

    if hasattr(sniffed_packet, 'ipv6'):
        # packet contains at least one IPv6 address
        ipv6_data = sniffed_packet.ipv6

        if hasattr(ipv6_data, 'src'):
            src_address_ipv6 = ipv6_data.src
        if hasattr(ipv6_data, 'dst'):
            dst_address_ipv6 = ipv6_data.dst

    traced_packet_ip_addresses = {}
    if src_address_ipv4:
        traced_packet_ip_addresses["src"] = {
            "addressType": "v4",
            "address": src_address_ipv4,
            "port": src_port,
            "time": get_packet_timestamp(sniffed_packet)
        }
    if src_address_ipv6:
        traced_packet_ip_addresses["src"] = {
            "addressType": "v6",
            "address": src_address_ipv6,
            "port": src_port,
            "time": get_packet_timestamp(sniffed_packet)
        }
    if dst_address_ipv4:
        traced_packet_ip_addresses["dst"] = {
            "addressType": "v4",
            "address": dst_address_ipv4,
            "port": dst_port,
            "time": get_packet_timestamp(sniffed_packet)
        }
    if dst_address_ipv6:
        traced_packet_ip_addresses["dst"] = {
            "addressType": "v6",
            "address": dst_address_ipv6,
            "port": dst_port,
            "time": get_packet_timestamp(sniffed_packet)
        }

    logger.info \
        (f"Detected certificate coming from [IP{traced_packet_ip_addresses['src']['addressType']} {traced_packet_ip_addresses['src']['address']}:{traced_packet_ip_addresses['src']['port']}] ---> "
                f"[IP{traced_packet_ip_addresses['dst']['addressType']} {traced_packet_ip_addresses['dst']['address']}:{traced_packet_ip_addresses['dst']['port']}]")
    return traced_packet_ip_addresses


def extract_tls_cert_packets_from_file(file_path):
    capture = FileCapture(file_path, display_filter="ssl.handshake.type==11")
    return [(capture_packet, capture_packet.tls) for capture_packet in capture if hasattr(capture_packet, 'tls')]


def extract_tls_cert_packets_from_livecapture(interface="en0"):
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


def extract_tls_certificate_as_bytes(captured_packet):
    """
    Extracts only the certificate byte content from the packet as bytes

    :param captured_packet:
    :return:
    """

    cert_hex = captured_packet._all_fields["tls.handshake.certificate"].split(":")
    return bytes.fromhex("".join(cert_hex))
