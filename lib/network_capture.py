import logging
from pyshark import LiveCapture

from network_scan import single_live_packet_extraction


def livecapture_tls_cert(interface="en0"):
    capture_logger = logging.getLogger("LiveCaptureCertificates")
    capture_logger.setLevel(level=logging.INFO)

    capture = LiveCapture(interface=interface, display_filter="ssl.handshake.type==11")
    capture.set_debug()
    capture_logger.info(f"Selecting {interface} for live capture...")

    capture.apply_on_packets(single_live_packet_extraction, timeout=10000)
    capture.sniff(timeout=50)
