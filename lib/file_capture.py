import logging
from collections import defaultdict

from lib.data_utilities import calculate_sha256_from_bytes
from lib.file_processing import save_certificate
from lib.packet_utilities import extract_tls_cert_packets_from_file, extract_tls_certificate_as_bytes, get_packet_tracing


def full_extract_from_file(file_path: str):
    capture_logger = logging.getLogger("[WaifuScan] (Local)")
    capture_logger.setLevel(level=logging.INFO)

    all_packets = extract_tls_cert_packets_from_file(file_path)
    relevant_transmissions = defaultdict(list)
    all_certificates = dict()

    for cert_num, (full_packet, tls_packet) in enumerate(all_packets):
        cert_data = extract_tls_certificate_as_bytes(tls_packet)
        save_certificate(cert_data, f"extracted_certificates/{file_path.split('/')[-1]}cert_{cert_num}.crt")

        certificate_hash = calculate_sha256_from_bytes(cert_data)
        if certificate_hash not in all_certificates:
            all_certificates[certificate_hash] = cert_data
        relevant_transmissions[certificate_hash].append(get_packet_tracing(full_packet, capture_logger))
