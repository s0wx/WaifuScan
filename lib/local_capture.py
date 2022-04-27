import os
import subprocess


def system_cert_crawl(start_path="."):
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

                    print(file, file_info)
                    if "certificate" in file_info.lower():
                        print("CERTIFICATE\n")
                    elif "key" in file_info.lower():
                        print("KEY\n")
