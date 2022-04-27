from datetime import datetime
from pyshark import FileCapture


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

    logger.info(
        f"Detected TLS Certificate Packet for [IP{traced_packet_ip_addresses['src']['addressType']} "
        f"{traced_packet_ip_addresses['src']['address']}:"
        f"{traced_packet_ip_addresses['src']['port']}] ---(CERTIFICATE)---> "
        f"[IP{traced_packet_ip_addresses['dst']['addressType']} "
        f"{traced_packet_ip_addresses['dst']['address']}:{traced_packet_ip_addresses['dst']['port']}]"
    )

    return traced_packet_ip_addresses


def extract_tls_cert_packets_from_file(file_path):
    """
    Extract certificates from network capture file (e.g. .pcapng)

    :param file_path: file path to capture file
    :return: all found relevant packages for further processing
    """

    capture = FileCapture(file_path, display_filter="ssl.handshake.type==11")
    return [(capture_packet, capture_packet.tls) for capture_packet in capture if hasattr(capture_packet, 'tls')]


def extract_tls_certificate_as_bytes(captured_packet):
    """
    Extracts only the certificate byte content from the packet as bytes

    :param captured_packet:
    :return:
    """

    cert_hex = captured_packet._all_fields["tls.handshake.certificate"].split(":")
    return bytes.fromhex("".join(cert_hex))
