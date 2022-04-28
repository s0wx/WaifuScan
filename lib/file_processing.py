import os


def save_certificate(certificate_data: bytes, file_path: str):
    with open(f"{file_path}", "wb") as cert_file:
        cert_file.write(certificate_data)


def check_required_folders():
    required_folders = [
        "extracted_certificates",
        "captures",
        "CertificateDatabase",
        "ExportDB"
    ]

    for directory in required_folders:
        if not os.path.exists(directory):
            os.mkdir(directory)
