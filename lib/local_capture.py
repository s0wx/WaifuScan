import os


def system_cert_crawl(start_path="."):
    for root_path, dirs, files in os.walk(start_path):
        for file in files:
            if file.endswith(".pem"):
                print(os.path.join(root_path, file))
