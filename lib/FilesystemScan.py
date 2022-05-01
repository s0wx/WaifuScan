import json
import logging
import os
import time
from collections import defaultdict

from pyshark import FileCapture

from lib.byte_utilities import calculate_sha256_from_bytes
from lib.byte_utilities import filetype_from_path
from lib.file_processing import save_certificate
from lib.mongo_utilities import CertificateDatabase


class FilesystemScan:
    def __init__(self):
        """
        Used to scan the local file system or specific files
        """

        self.capture_logger = logging.getLogger("[WaifuScan] (Local)")
        self.capture_logger.setLevel(level=logging.INFO)

    def start_tls_cert_scan(self, database: CertificateDatabase, start_path="."):
        start = time.time()
        counting = defaultdict(int)
        certificate_extensions = [
            ".pem",
            ".crt"
            ".ca-bundle",
            ".p7b",
            ".p7s",
            ".der",
            ".cer",
            ".pfx",
            ".p12"
        ]

        for root_path, dirs, files in os.walk(start_path):
            for file in files:
                for ext in certificate_extensions:
                    if file.endswith(ext):
                        file_type = filetype_from_path(root_path=root_path, file=file)
                        counting[file_type] += 1
                        stopped = time.time() - start
                        if any(file_type_option in file_type for file_type_option in ["certificate", "key"]):
                            with open(os.path.join(root_path, file), "rb") as cert_file:
                                cert_data = cert_file.read()
                                certificate_hash = calculate_sha256_from_bytes(cert_data)
                                database.add_certificate({
                                    "sha256": certificate_hash,
                                    "certificateBytes": cert_data,
                                    "dataType": file_type
                                }, self.capture_logger)

                        # edge case for remaining filetypes
                        print(json.dumps(dict(counting), indent=2))
                        self.capture_logger.info(f"Running {int(stopped)}s for {sum(counting.values())} checks --> [found: {file, file_type}]")

    def scan_tls_certs_from_dump(self, extractor, file_path):
        """
        Extract certificates from network capture file (e.g. .pcapng)

        :param extractor: extractor instance for certificate extraction
        :param file_path: file path to capture file
        :return: all found relevant packages for further processing
        """

        capture = FileCapture(file_path, display_filter="ssl.handshake.type==11")
        all_packets = [(capture_packet, capture_packet.tls) for capture_packet in capture if hasattr(capture_packet, 'tls')]
        relevant_transmissions = defaultdict(list)
        all_certificates = {}

        for cert_num, (full_packet, tls_packet) in enumerate(all_packets):
            cert_data = extractor.tls_certificate_to_bytes(tls_packet)
            save_certificate(cert_data, f"extracted_certificates/{file_path.split('/')[-1]}cert_{cert_num}.crt")

            certificate_hash = calculate_sha256_from_bytes(cert_data)
            if certificate_hash not in all_certificates:
                all_certificates[certificate_hash] = cert_data
            relevant_transmissions[certificate_hash].append(
                extractor.get_packet_tracing(full_packet)
            )
