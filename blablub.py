import pyshark


def extract_tls_certificate_as_bytes(packet):
    cert_hex = packet._all_fields["tls.handshake.certificate"].split(":")
    return bytes.fromhex("".join(cert_hex))


def save_certificate(certificate_data: bytes, file_path: str):
    with open(f"{file_path}", "wb") as cert_file:
        cert_file.write(certificate_data)


def extract_tls_cert_packets_from_file(file_path):
    capture = pyshark.FileCapture(file_path, display_filter="ssl.handshake.type==11")
    return [packet.tls for packet in capture if hasattr(packet, 'tls')]


if __name__ == '__main__':
    tls_cert_packets = extract_tls_cert_packets_from_file("captures/example_rwth.pcapng")

    for cert_num, packet in enumerate(tls_cert_packets):
        cert_data = extract_tls_certificate_as_bytes(packet)
        save_certificate(cert_data, f"cert_{cert_num}.crt")
