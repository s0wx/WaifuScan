import logging
import os

from lib.data_utilities import calculate_sha256_from_bytes
from lib.file_processing import save_certificate
from lib.mongo_utilities import certificate_database
from lib.packet_utilities import extract_tls_certificate_as_bytes, get_packet_tracing


class PacketExtractor:
    def __init__(self):
        """
        Used to extract relevant packet data to storage solutions like the filesystem, a database or both
        """

        self.capture_logger = logging.getLogger("[WaifuScan] (Extractor)")
        self.capture_logger.setLevel(level=logging.INFO)

    def extract_to_local(self, packet, file_path="extracted_certificates/live_capture_cert.crt"):
        """
        Extract detected TLS Certificate to provided file path

        :param packet: full PyShark packet
        :param file_path: file path where to save the detected certificate
        :return: None
        """

        if hasattr(packet, 'tls'):
            packet_full, packet_tls = packet, packet.tls
            _ = get_packet_tracing(packet_full, self.capture_logger)
            cert_data = extract_tls_certificate_as_bytes(packet_tls)
            certificate_hash = calculate_sha256_from_bytes(cert_data)
            file_path_split = file_path.split(".")
            new_file_path = "".join(file_path_split[:-1]) + certificate_hash + "".join(file_path_split[-1:])

            if not os.path.exists(new_file_path):
                save_certificate(cert_data, new_file_path)
                self.capture_logger.info(" saved new certificate at provided location")
            else:
                self.capture_logger.info(" already found certificate before")

    def extract_to_database(self, packet):
        """
        Extract detected TLS Certificate and save to database

        :param packet: full PyShark packet
        :return: None
        """

        if hasattr(packet, 'tls'):
            packet_full, packet_tls = packet, packet.tls
            _ = get_packet_tracing(packet_full, self.capture_logger)
            cert_data = extract_tls_certificate_as_bytes(packet_tls)
            certificate_hash = calculate_sha256_from_bytes(cert_data)
            certificate_database.add_certificate({
                "sha256": certificate_hash,
                "certificateBytes": cert_data
            }, self.capture_logger)
