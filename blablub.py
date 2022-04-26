import pyshark
import json


if __name__ == '__main__':
    cap = pyshark.FileCapture("captures/example_rwth.pcapng", display_filter="ssl.handshake.type==11")
    tls_packets = [packet.tls for packet in cap if hasattr(packet, 'tls')]
    for packet in tls_packets:
        # print(packet._all_fields["tls.handshake.certificate"])
        print(json.dumps(packet.__dict__, indent=2))

