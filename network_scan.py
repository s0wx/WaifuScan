import os
import logging
import pyshark
import hashlib
import json
from datetime import datetime
from collections import defaultdict




def extract_tls_certificate_as_bytes(captured_packet):
    cert_hex = captured_packet._all_fields["tls.handshake.certificate"].split(":")
    return bytes.fromhex("".join(cert_hex))


def save_certificate(certificate_data: bytes, file_path: str):
    with open(f"{file_path}", "wb") as cert_file:
        cert_file.write(certificate_data)


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
        packet_tracing = get_packet_tracing(packet_full, capture_logger)
        cert_data = extract_tls_certificate_as_bytes(packet_tls)
        current_time = datetime.now()
        save_certificate(cert_data, f"extracted_certificates/livecapture_cert_{current_time}.crt")
        capture_logger.info(f"Saved certificate as livecapture_cert_{current_time}.crt\n")

        certificate_hash = calculate_sha256_from_bytes(cert_data)
        return certificate_hash, cert_data
    return None, None


def calculate_sha256_from_bytes(byte_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(byte_data)
    return sha256_hash.hexdigest()


def get_packet_timestamp(sniffed_packet):
    return str(datetime.fromtimestamp(float(sniffed_packet.sniff_timestamp)))


def get_packet_tracing(sniffed_packet, logger):
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

    logger.info(f"Detected certificate coming from [IP{traced_packet_ip_addresses['src']['addressType']} {traced_packet_ip_addresses['src']['address']}:{traced_packet_ip_addresses['src']['port']}] ---> "
                f"[IP{traced_packet_ip_addresses['dst']['addressType']} {traced_packet_ip_addresses['dst']['address']}:{traced_packet_ip_addresses['dst']['port']}]")
    return traced_packet_ip_addresses


def full_extract_from_file(file_path: str):
    all_packets = extract_tls_cert_packets_from_file(capture_filepath)
    relevant_transmissions = defaultdict(list)
    all_certificates = dict()

    for cert_num, (full_packet, tls_packet) in enumerate(all_packets):
        cert_data = extract_tls_certificate_as_bytes(tls_packet)
        save_certificate(cert_data, f"extracted_certificates/{file_path.split('/')[-1]}cert_{cert_num}.crt")

        certificate_hash = calculate_sha256_from_bytes(cert_data)
        if certificate_hash not in all_certificates:
            all_certificates[certificate_hash] = cert_data
        relevant_transmissions[certificate_hash].append(get_packet_tracing(full_packet))

    print(json.dumps(relevant_transmissions, indent=2))


if __name__ == '__main__':
    logging.basicConfig()
    capture_filepath = "captures/non_vpn_refresh.pcapng"
    # full_extract_from_file(capture_filepath)
    extract_tls_cert_packets_from_livecapture("en0")
