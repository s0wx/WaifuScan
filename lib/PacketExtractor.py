import logging
import os

from datetime import datetime

from lib.data_utilities import calculate_sha256_from_bytes
from lib.file_processing import save_certificate
from lib.mongo_utilities import certificate_database


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
            _ = self.get_packet_tracing(packet_full)
            cert_data = self.tls_certificate_to_bytes(packet_tls)
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
            _ = self.get_packet_tracing(packet_full)
            cert_data = self.tls_certificate_to_bytes(packet_tls)
            certificate_hash = calculate_sha256_from_bytes(cert_data)
            certificate_database.add_certificate({
                "sha256": certificate_hash,
                "certificateBytes": cert_data
            }, self.capture_logger)

    def tls_certificate_to_bytes(self, packet):
        """
        Extracts only the certificate byte content from the packet as bytes

        :param packet: PyShark packet containing a certificate to extract
        :return: Certificate data as bytes
        """

        cert_hex = packet._all_fields["tls.handshake.certificate"].split(":")
        return bytes.fromhex("".join(cert_hex))

    def timestamp_to_string(self, packet):
        """
        Returns the sniff_timestamp as readable string date format

        :param packet: packet to track
        :return: packet date as string
        """

        return str(datetime.fromtimestamp(float(packet.sniff_timestamp)))

    def get_packet_tracing(self, packet):
        """
        Get SRC and DST data from traced packet

        :param packet: packet to check
        :return: dictionary of packet trace data
        """

        src_address_ipv4 = None
        src_address_ipv6 = None
        dst_address_ipv4 = None
        dst_address_ipv6 = None

        src_port = None
        dst_port = None

        # track src and dst ports of packet
        if hasattr(packet, 'tcp'):
            tcp_data = packet.tcp
            src_port = tcp_data.srcport
            dst_port = tcp_data.dstport

        if hasattr(packet, 'ip'):
            # packet contains at least one IPv4 address
            ip_data = packet.ip

            if hasattr(ip_data, 'src'):
                src_address_ipv4 = ip_data.src
            if hasattr(ip_data, 'dst'):
                dst_address_ipv4 = ip_data.dst

        if hasattr(packet, 'ipv6'):
            # packet contains at least one IPv6 address
            ipv6_data = packet.ipv6

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
                "time": self.timestamp_to_string(packet)
            }

        if src_address_ipv6:
            traced_packet_ip_addresses["src"] = {
                "addressType": "v6",
                "address": src_address_ipv6,
                "port": src_port,
                "time": self.timestamp_to_string(packet)
            }

        if dst_address_ipv4:
            traced_packet_ip_addresses["dst"] = {
                "addressType": "v4",
                "address": dst_address_ipv4,
                "port": dst_port,
                "time": self.timestamp_to_string(packet)
            }

        if dst_address_ipv6:
            traced_packet_ip_addresses["dst"] = {
                "addressType": "v6",
                "address": dst_address_ipv6,
                "port": dst_port,
                "time": self.timestamp_to_string(packet)
            }

        self.capture_logger.info(
            f" detected TLS certificate packet for [IP{traced_packet_ip_addresses['src']['addressType']} "
            f"{traced_packet_ip_addresses['src']['address']}:"
            f"{traced_packet_ip_addresses['src']['port']}] ---(CERTIFICATE)---> "
            f"[IP{traced_packet_ip_addresses['dst']['addressType']} "
            f"{traced_packet_ip_addresses['dst']['address']}:{traced_packet_ip_addresses['dst']['port']}]"
        )

        return traced_packet_ip_addresses
