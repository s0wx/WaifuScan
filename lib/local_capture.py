import json
import logging
import os
import subprocess
import time
from collections import defaultdict

from lib.data_utilities import calculate_sha256_from_bytes
from lib.mongo_utilities import certificate_database


def system_cert_crawl(start_path="."):
    capture_logger = logging.getLogger("[WaifuScan] (Network)")
    capture_logger.setLevel(level=logging.INFO)

    start = time.time()
    counting = defaultdict(int)
    pattern_detection = dict()
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
                    if file_type not in pattern_detection:
                        pattern_detection[file_type] = read_file_bytes_pattern(os.path.join(root_path, file))
                    else:
                        pattern_detection[file_type] = compare_byte_pattern(
                            read_file_bytes_pattern(os.path.join(root_path, file)),
                            pattern_detection[file_type]
                        )

                    stopped = time.time() - start
                    print(f"{int(stopped)}s", file, file_type)
                    if any(file_type_option in file_type for file_type_option in ["certificate", "key"]):
                        with open(os.path.join(root_path, file), "rb") as cert_file:
                            cert_data = cert_file.read()
                            certificate_hash = calculate_sha256_from_bytes(cert_data)
                            certificate_database.add_certificate({
                                "sha256": certificate_hash,
                                "certificateBytes": cert_data,
                                "dataType": file_type
                            }, capture_logger)

                    # edge case for remaining filetypes
                    print(json.dumps(dict(counting), indent=2))
                    print(f"{int(stopped)}s for {sum(counting.values())} checks")
    print(f"TOTAL: {int(time.time() - start)} seconds for {sum(counting.values())} checks")


def read_file_bytes_pattern(file_path):
    with open(file_path, "rb") as read_file:
        file_bytes = read_file.read()
        return {i: hex(file_bytes[i]) for i in range(len(file_bytes))}


def compare_byte_pattern(check, reference):
    if (len(check) >= len(reference)):
        ref_copy = reference.copy()
        for key, value in reference.items():
            if key not in check or check[key] != reference[key]:
                ref_copy.pop(key)
        return ref_copy
    else:
        check_copy = check.copy()
        for key, value in check.items():
            if key not in reference or check[key] != reference[key]:
                check_copy.pop(key)
        return check_copy


def check_byte_pattern_nested(check_pattern, existing_patterns):
    next_patterns = set(existing_patterns)
    patterns_updated = False
    for pattern in existing_patterns:
        start_found = False
        end_found = False


def get_data_filetype_bytes(data_bytes):
    with open("cert_buffer_file", "wb") as buffer_file:
        buffer_file.write(data_bytes)
    file_type_command = subprocess.check_output("file cert_buffer_file", shell=True)
    os.unlink("cert_buffer_file")
    file_info = file_type_command.decode("utf-8").split(":")[-1].strip()
    return file_info.lower()


def get_data_filetype_path(root_path, file):
    file_type_command = subprocess.check_output("file " + os.path.join(root_path, file).replace(' ', '\ '), shell=True)
    file_info = file_type_command.decode("utf-8").split(":")[-1].strip()
    return file_info.lower()


def update_missing_cert_attributes():
    """
    Add missing certificate type to database object

    :return:
    """

    capture_logger = logging.getLogger("[WaifuScan] (DB Alignment)")
    capture_logger.setLevel(level=logging.INFO)

    for doc in certificate_database.certificates_collection.find({"dataType": None}):
        file_type = get_data_filetype_bytes(doc["certificateBytes"])
        certificate_database.certificates_collection.update_one({"_id": doc["_id"]}, {"$set": {"dataType": file_type}})

    capture_logger.info("successfully aligned all database entries")
