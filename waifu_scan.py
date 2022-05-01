import logging
import argparse

from lib.PacketExtractor import PacketExtractor
from lib.file_processing import check_required_folders
from lib.byte_utilities import update_missing_cert_attributes, export_database
from lib.NetworkScan import NetworkScan
from lib.FilesystemScan import FilesystemScan
from lib.mongo_utilities import CertificateDatabase

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
    database = CertificateDatabase()
    packet_extractor = PacketExtractor(database)

    # Run Network Scan
    if args.network:
        network_scanner = NetworkScan(interface=args.network[0], extractor=packet_extractor)
        network_scanner.start_tls_cert_scan()

    # Run File System Scan
    elif args.local:
        filesystem_scanner = FilesystemScan()
        filesystem_scanner.start_tls_cert_scan(
            database=database,
            start_path=args.local[0]
        )

    # Run Traffic Dump Scan
    elif args.file:
        dump_scanner = FilesystemScan()
        dump_scanner.scan_tls_certs_from_dump(extractor=packet_extractor, file_path=args.file)

    # Align Database entries to use same properties
    elif args.dbAlign:
        update_missing_cert_attributes(database=database)

    # Export Database
    elif args.export:
        update_missing_cert_attributes(database=database)
        export_database(database=database)

    else:
        parser.print_help()
