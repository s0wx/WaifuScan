from pyshark import FileCapture


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
