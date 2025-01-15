from scapy.all import sniff, Ether, IP

def packet_callback(packet):
    if Ether in packet:
        eth_layer = packet[Ether]
        print(f"\nEthernet Frame:")
        print(f"Source MAC: {eth_layer.src}")
        print(f"Destination MAC: {eth_layer.dst}")
        if IP in packet:
            ip_layer = packet[IP]
            print(f"\nIP Packet:")
            print(f"Source IP: {ip_layer.src}")
            print(f"Destination IP: {ip_layer.dst}")
            print(f"Protocol: {ip_layer.proto}")

def main():
    print("Starting sniffer... Press Ctrl+C to stop.")
    # Sniff packets and call packet_callback for each packet
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
