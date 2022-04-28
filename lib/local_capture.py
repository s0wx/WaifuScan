import json
import os
import subprocess
import sys
import time
from collections import defaultdict


def system_cert_crawl(start_path="."):
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
                    file_type_command = subprocess.check_output("file " + os.path.join(root_path, file).replace(' ', '\ '), shell=True)
                    file_info = file_type_command.decode("utf-8").split(":")[-1].strip()
                    counting[file_info.lower()] += 1
                    if file_info.lower() not in pattern_detection:
                        pattern_detection[file_info.lower()] = read_file_bytes_pattern(os.path.join(root_path, file))
                    else:
                        pattern_detection[file_info.lower()] = compare_byte_pattern(
                            read_file_bytes_pattern(os.path.join(root_path, file)),
                            pattern_detection[file_info.lower()]
                        )

                    stopped = time.time() - start
                    print(f"{int(stopped)}s", file, file_info)
                    if "certificate" in file_info.lower():
                        print("CERTIFICATE\n")
                    elif "key" in file_info.lower():
                        print("KEY\n")
                    print(json.dumps(dict(counting), indent=2))
                    print(f"{int(stopped)}s for {sum(counting.values())} checks")
                    print(json.dumps({key: f"{len(value)} pattern length" for key, value in pattern_detection.items()}, indent=2))
    print(f"TOTAL: {int(time.time() - start)} seconds for {sum(counting.values())} checks")
    print(json.dumps(pattern_detection, indent=2))


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
