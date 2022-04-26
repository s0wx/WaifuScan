import pyshark
import hashlib


def extract_tls_certificate_as_bytes(captured_packet):
    cert_hex = captured_packet._all_fields["tls.handshake.certificate"].split(":")
    return bytes.fromhex("".join(cert_hex))


def save_certificate(certificate_data: bytes, file_path: str):
    with open(f"{file_path}", "wb") as cert_file:
        cert_file.write(certificate_data)


def extract_tls_cert_packets_from_file(file_path):
    capture = pyshark.FileCapture(file_path, display_filter="ssl.handshake.type==11")
    return [capture_packet.tls for capture_packet in capture if hasattr(capture_packet, 'tls')]


def calculate_sha256_from_bytes(byte_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(byte_data)
    return sha256_hash.hexdigest()


if __name__ == '__main__':
    tls_cert_packets = extract_tls_cert_packets_from_file("captures/example_rwth.pcapng")

    for cert_num, packet in enumerate(tls_cert_packets):
        cert_data = extract_tls_certificate_as_bytes(packet)
        save_certificate(cert_data, f"cert_{cert_num}.crt")
        print("hash", cert_num, calculate_sha256_from_bytes(cert_data))
