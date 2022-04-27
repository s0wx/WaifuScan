import os


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
                    print(os.path.join(root_path, file))
