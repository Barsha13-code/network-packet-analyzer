from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


def analyze_packet(packet):
    print("\n" + "=" * 70)

    # Time
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("Time       :", timestamp)

    # Check for IP packet
    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        print("Source IP  :", source_ip)
        print("Dest. IP   :", destination_ip)

        # TCP
        if TCP in packet:
            print("Protocol   : TCP")
            print("Source Port:", packet[TCP].sport)
            print("Dest. Port :", packet[TCP].dport)

        # UDP
        elif UDP in packet:
            print("Protocol   : UDP")
            print("Source Port:", packet[UDP].sport)
            print("Dest. Port :", packet[UDP].dport)

        # ICMP
        elif ICMP in packet:
            print("Protocol   : ICMP")

        # Other IP protocol
        else:
            print("Protocol   :", packet[IP].proto)

        # Payload
        if Raw in packet:
            payload = bytes(packet[Raw].load)

            print("Payload Size:", len(payload), "bytes")

            # Show first 100 bytes only
            preview = payload[:100]

            print("Payload (Hex):")
            print(preview.hex(" "))

            # Safe printable representation
            printable = "".join(
                chr(byte) if 32 <= byte <= 126 else "."
                for byte in preview
            )

            print("Payload (Text):")
            print(printable)

        else:
            print("Payload    : No application payload")

    else:
        print("Non-IP packet detected")
        print("Packet Type:", packet.summary())


def main():
    print("=" * 70)
    print("             NETWORK PACKET ANALYZER")
    print("=" * 70)

    print("\nStarting packet capture...")
    print("Press CTRL+C to stop.\n")

    try:
        sniff(
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nPacket capture stopped.")
        print("Thank you for using Network Packet Analyzer.")

    except PermissionError:
        print("\nPermission denied.")
        print("Run this program with administrator/root privileges.")

    except Exception as error:
        print("\nAn error occurred:")
        print(error)


if __name__ == "__main__":
    main()