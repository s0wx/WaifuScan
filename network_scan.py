import os

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


def calculate_sha256_from_bytes(byte_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(byte_data)
    return sha256_hash.hexdigest()


def get_packet_timestamp(sniffed_packet):
    return str(datetime.fromtimestamp(float(sniffed_packet.sniff_timestamp)))


def get_packet_tracing(sniffed_packet):
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
            "addressType": "V4",
            "address": src_address_ipv4,
            "port": src_port,
            "time": get_packet_timestamp(sniffed_packet)
        }
    if src_address_ipv6:
        traced_packet_ip_addresses["src"] = {
            "addressType": "V6",
            "address": src_address_ipv6,
            "port": src_port,
            "time": get_packet_timestamp(sniffed_packet)
        }
    if dst_address_ipv4:
        traced_packet_ip_addresses["dst"] = {
            "addressType": "V4",
            "address": dst_address_ipv4,
            "port": dst_port,
            "time": get_packet_timestamp(sniffed_packet)
        }
    if dst_address_ipv6:
        traced_packet_ip_addresses["dst"] = {
            "addressType": "V6",
            "address": dst_address_ipv6,
            "port": dst_port,
            "time": get_packet_timestamp(sniffed_packet)
        }

    print(traced_packet_ip_addresses)
    return traced_packet_ip_addresses


def system_cert_crawl(start_path="."):
    for root_path, dirs, files in os.walk(start_path):
        for file in files:
            if file.endswith(".pem"):
                print(os.path.join(root_path, file))


if __name__ == '__main__':
    capture_filepath = "captures/non_vpn_refresh.pcapng"
    all_packets = extract_tls_cert_packets_from_file(capture_filepath)
    relevant_transmissions = defaultdict(list)
    all_certificates = dict()

    for cert_num, (full_packet, tls_packet) in enumerate(all_packets):
        cert_data = extract_tls_certificate_as_bytes(tls_packet)
        save_certificate(cert_data, f"extracted_certificates/{capture_filepath.split('/')[-1]}cert_{cert_num}.crt")

        certificate_hash = calculate_sha256_from_bytes(cert_data)
        if certificate_hash not in all_certificates:
            all_certificates[certificate_hash] = cert_data
        relevant_transmissions[certificate_hash].append(get_packet_tracing(full_packet))

    print(json.dumps(relevant_transmissions, indent=2))

    system_cert_crawl("/Users/lennard/Documents/")
