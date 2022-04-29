import json
import logging
import os
import time
from collections import defaultdict

from pyshark import FileCapture

from lib.PacketExtractor import PacketExtractor
from lib.data_utilities import calculate_sha256_from_bytes
from lib.byte_utilities import get_data_filetype_path


class FilesystemScan:
    def __init__(self, extractor: PacketExtractor):
        """
        Used to scan the local file system or specific files
        """

        self.capture_logger = logging.getLogger("[WaifuScan] (Local)")
        self.capture_logger.setLevel(level=logging.INFO)
        self.extractor = extractor

    def start_tls_cert_scan(self, start_path="."):
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
                        file_type = get_data_filetype_path(root_path=root_path, file=file)
                        counting[file_type] += 1
                        stopped = time.time() - start
                        if any(file_type_option in file_type for file_type_option in ["certificate", "key"]):
                            with open(os.path.join(root_path, file), "rb") as cert_file:
                                cert_data = cert_file.read()
                                certificate_hash = calculate_sha256_from_bytes(cert_data)
                                self.extractor.extract_to_database({
                                    "sha256": certificate_hash,
                                    "certificateBytes": cert_data,
                                    "dataType": file_type
                                })

                        # edge case for remaining filetypes
                        print(json.dumps(dict(counting), indent=2))
                        self.capture_logger.info(f"Running {int(stopped)}s for {sum(counting.values())} checks --> [found: {file, file_type}]")

    def scan_tls_certs_from_traffic_dump(self, file_path):
        """
        Extract certificates from network capture file (e.g. .pcapng)

        :param file_path: file path to capture file
        :return: all found relevant packages for further processing
        """

        capture = FileCapture(file_path, display_filter="ssl.handshake.type==11")
        return [(capture_packet, capture_packet.tls) for capture_packet in capture if hasattr(capture_packet, 'tls')]
