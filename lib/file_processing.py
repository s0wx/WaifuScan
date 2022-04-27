

def save_certificate(certificate_data: bytes, file_path: str):
    with open(f"{file_path}", "wb") as cert_file:
        cert_file.write(certificate_data)
