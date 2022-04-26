import pyshark
import hashlib
import json
from datetime import datetime


def extract_tls_certificate_as_bytes(captured_packet):
    # print(json.dumps(captured_packet.__dict__, indent=2))
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
    return datetime.fromtimestamp(float(sniffed_packet.sniff_timestamp))


def get_packet_tracing(sniffed_packet):
    src_address_ipv4 = None
    src_address_ipv6 = None
    dest_address_ipv4 = None
    dest_address_ipv6 = None

    if hasattr(sniffed_packet, 'ip'):
        # packet contains at least one IPv4 address
        print(sniffed_packet.__dict__)
        ip_data = sniffed_packet.ip
        # print(ip_data.__all_fields)

        if hasattr(sniffed_packet, 'ip.src'):
            src_address_ipv4 = sniffed_packet.ip.src
        if hasattr(sniffed_packet, 'ip.dst'):
            dest_address_ipv4 = sniffed_packet.ip.dst

    if hasattr(sniffed_packet, 'ipv6'):
        # packet contains at least one IPv6 address
        print(sniffed_packet.ipv6.__dict__)

        if hasattr(sniffed_packet, 'ipv6.src'):
            src_address_ipv6 = sniffed_packet.ipv6.src
        if hasattr(sniffed_packet, 'ipv6.dst'):
            dest_address_ipv6 = sniffed_packet.ipv6.dst
    print(src_address_ipv4, src_address_ipv6, dest_address_ipv4, dest_address_ipv6)


if __name__ == '__main__':
    all_packets = extract_tls_cert_packets_from_file("captures/example_rwth.pcapng")

    for cert_num, (full_packet, tls_packet) in enumerate(all_packets):
        cert_data = extract_tls_certificate_as_bytes(tls_packet)
        print(full_packet.__dict__)
        print(get_packet_timestamp(full_packet))
        save_certificate(cert_data, f"cert_{cert_num}.crt")
        get_packet_tracing(full_packet)
        print("hash", cert_num, calculate_sha256_from_bytes(cert_data))
        print("\n\n\n")
