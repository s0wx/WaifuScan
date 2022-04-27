import logging
from lib.packet_utilities import extract_tls_cert_packets_from_livecapture


if __name__ == '__main__':
    logging.basicConfig()
    capture_filepath = "captures/non_vpn_refresh.pcapng"
    # full_extract_from_file(capture_filepath)
    extract_tls_cert_packets_from_livecapture("en0")
