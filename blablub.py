import pyshark
import json


def extract_tls_certificate_as_bytes(packet):
    cert_hex = packet._all_fields["tls.handshake.certificate"].split(":")
    return bytes.fromhex("".join(cert_hex))


def save_certificate(certificate_data: bytes, file_path: str):
    with open(f"{file_path}", "wb") as cert_file:
        cert_file.write(certificate_data)




if __name__ == '__main__':
    cap = pyshark.FileCapture("captures/wiki_reddit_ipleak.pcapng", display_filter="ssl.handshake.type==11")
    # cap = pyshark.FileCapture("captures/example_rwth.pcapng", display_filter="ssl.handshake.type==11")
    tls_packets = [packet.tls for packet in cap if hasattr(packet, 'tls')]

    cert_num = 0
    for packet in tls_packets:
        cert_hex = packet._all_fields["tls.handshake.certificate"].split(":")
        print(len(cert_hex))
        print(cert_hex)
        print(bytes.fromhex("".join(cert_hex)))
        cert_str = [bytes.fromhex(elem) for elem in cert_hex]
        with open(f"cert0{cert_num}.crt", "wb") as crt_file:
            crt_file.write(bytes.fromhex("".join(cert_hex)))

        cert_num += 1
        print(cert_str)

        print(json.dumps(packet.__dict__, indent=2))

