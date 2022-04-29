import logging
import argparse

from lib.PacketExtractor import PacketExtractor
from lib.file_capture import full_extract_from_file
from lib.file_processing import check_required_folders
from lib.byte_utilities import update_missing_cert_attributes, export_database
from lib.NetworkScan import NetworkScan
from lib.FilesystemScan import FilesystemScan


if __name__ == '__main__':
    logging.basicConfig()
    check_required_folders()

    parser = argparse.ArgumentParser()

    local_group = parser.add_argument_group("Local Scanning")
    local_group.add_argument(
        "--local", "-L",
        type=str,
        nargs=1,
        help="run local scan starting in provided path",
        metavar="FILEPATH"
    )

    local_group.add_argument(
        "--file", "-F",
        type=str,
        nargs=1,
        help="run local check for file provided by path (e.g. pcap format)",
        metavar="FILEPATH"
    )

    network_group = parser.add_argument_group("Network Scanning")
    network_group.add_argument(
        "--network", "-N",
        type=str,
        nargs=1,
        help="run network scan on provided interface to sniff (e.g. en0 on macOS for Wifi)",
        metavar="INTERFACE"
    )

    database_group = parser.add_argument_group("Database Management")
    database_group.add_argument(
        "--dbAlign", "-dA",
        action="store_true",
        help="align all database objects which differ from latest defined properties (e.g. missing dataType)",
    )

    database_group.add_argument(
        "--export", "-E",
        action="store_true",
        help="export all certificates from database",
    )

    args = parser.parse_args()

    # Run Network Scan
    if args.network:
        packet_extractor = PacketExtractor()
        network_scanner = NetworkScan(interface=args.network[0], extractor=packet_extractor)
        network_scanner.start_tls_cert_scan()

    # Run File System Scan
    elif args.local:
        packet_extractor = PacketExtractor()
        filesystem_scanner = FilesystemScan(extractor=packet_extractor)
        filesystem_scanner.start_tls_cert_scan(
            start_path=args.local[0]
        )

    # Run Traffic Dump Scan
    elif args.file:
        full_extract_from_file(args.file)

    # Align Database entries to use same properties
    elif args.dbAlign:
        update_missing_cert_attributes()

    # Export Database
    elif args.export:
        export_database()

    else:
        parser.print_help()
