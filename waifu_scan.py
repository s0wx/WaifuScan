import logging
import argparse

from lib.file_capture import full_extract_from_file
from lib.file_processing import check_required_folders
from lib.local_capture import system_cert_crawl
from lib.mongo_utilities import database_setup
from lib.network_capture import livecapture_tls_cert


if __name__ == '__main__':
    logging.basicConfig()
    check_required_folders()
    database_setup()

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

    args = parser.parse_args()

    # Run Network Scan
    if args.network:
        livecapture_tls_cert(args.network)

    elif args.local:
        for doc in certificate_database.certificates_collection.find({"dataType": None}):
            print(get_data_filetype_bytes(doc["certificateBytes"]))
            # certificate_database.certificates_collection.update_one({ "_id": doc["_id"]}, {"dataType": })
            print(doc)
        # system_cert_crawl(args.local[0])

    elif args.file:
        full_extract_from_file(args.file)

    else:
        parser.print_help()
