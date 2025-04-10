#!/usr/bin/env python3
"""
network_sniffer.py

A simple network packet analyzer using Scapy.
Captures packets and displays:
  - Timestamp
  - Source IP
  - Destination IP
  - Protocol
  - Payload (truncated)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(pkt):
    """
    Called for each captured packet.
    Extracts and prints relevant info.
    """
    # Only process IP packets
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine protocol name
        if proto == 6 and TCP in pkt:
            proto_name = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif proto == 17 and UDP in pkt:
            proto_name = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif proto == 1 and ICMP in pkt:
            proto_name = "ICMP"
            sport = dport = None
        else:
            proto_name = str(proto)
            sport = dport = None

        # Payload (raw bytes) — truncated for readability
        raw = bytes(pkt.payload)
        payload = raw[:50] + b'...' if len(raw) > 50 else raw

        # Timestamp
        ts = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')

        # Print summary
        print(f"[{ts}] {src_ip}"
              + (f":{sport}" if sport else "")
              + f" → {dst_ip}"
              + (f":{dport}" if dport else "")
              + f" | {proto_name}"
              + f" | Payload: {payload!r}")

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Simple Network Packet Analyzer (sniffer) with Scapy"
    )
    parser.add_argument(
        '-i', '--interface',
        help="Network interface to sniff on (e.g., eth0, wlan0)",
        required=True
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help="Number of packets to capture (0 = infinite)"
    )
    args = parser.parse_args()

    print(f"[*] Starting packet capture on interface '{args.interface}' "
          f"{'(infinite)' if args.count==0 else f'({args.count} packets)'}")
    try:
        sniff(
            iface=args.interface,
            prn=packet_callback,
            count=args.count,
            store=False
        )
    except PermissionError:
        print("Error: Need to run as root/Administrator to capture packets.")
    except KeyboardInterrupt:
        print("\n[*] Stopped by user")

if __name__ == "__main__":
    main()
