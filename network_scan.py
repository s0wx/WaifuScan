import logging
import argparse
import sys

from lib.packet_utilities import extract_tls_cert_packets_from_livecapture


if __name__ == '__main__':
    logging.basicConfig()
    process_logger = logging.getLogger("Certificate_Extraction")

    parser = argparse.ArgumentParser()

    local_group = parser.add_argument_group("Local Scanning")
    local_group.add_argument(
        "--localScan",
        type=str,
        nargs=1,
        help="run local scan starting in provided path",
        metavar="FILEPATH"
    )

    local_group.add_argument(
        "--localCheck",
        type=str,
        nargs=1,
        help="run local check for file provided by path (e.g. pcap format)",
        metavar="FILEPATH"
    )

    network_group = parser.add_argument_group("Network Scanning")
    network_group.add_argument(
        "--networkScan",
        type=str,
        nargs=1,
        help="run network scan on provided interface to sniff (e.g. en0 on macOS for Wifi)",
        metavar="INTERFACE"
    )

    args = parser.parse_args()

    # Run Network Scan
    if args.command == "scannetwork" and args.interface:
        extract_tls_cert_packets_from_livecapture("en0")

    elif not args.file and not args.live:
        process_logger.error("no arguments provided, terminating...")
        sys.exit(0)
    capture_filepath = "captures/non_vpn_refresh.pcapng"
    # full_extract_from_file(capture_filepath)
