"""
Randomly edit packet fields in a PCAP file.
"""

import argparse
import json
import scapy.all as scapy
from packet.Packet import Packet


if __name__ == "__main__":

    ### ARGUMENT PARSING ###
    
    parser = argparse.ArgumentParser(
        prog="pcap-tweaker.py",
        description="Randomly edit packet fields in a PCAP file."
    )

    # Positional argument #1: input PCAP file
    parser.add_argument("input_pcap", type=str, help="Input PCAP file.")
    # Optional argument -o: output PCAP file
    parser.add_argument("-o", "--output_pcap", type=str, help="Output PCAP file. Default is input file name with '.tweak' appended.")

    args = parser.parse_args()
    if args.output_pcap is None:
        args.output_pcap = args.input_pcap.replace(".pcap", ".tweak.pcap")

    
    ### LOAD SUPPORTED PROTOCOLS ###
    protocols = {}
    with open("protocols.json", "r") as f:
        protocols = json.load(f)

    
    ### MAIN PROGRAM ###

    # Read input PCAP file
    packets = scapy.rdpcap(args.input_pcap)
    new_packets = []

    # Loop on packets
    i = 0
    for packet in packets:

        # Choose randomly if we edit this packet
        #if random.randint(0, 1) != 0:
        if i != 0:
            # Packet won't be edited
            # Go to next packet
            new_packets.append(packet)
            i += 1
            continue

        # Edit packet, if possible
        try:
            packet = Packet.init_packet(packet.lastlayer().name, packet, i)
            packet.tweak()
            new_packets.append(packet.get_packet())
            i += 1
        except ModuleNotFoundError:
            new_packets.append(packet)
            i += 1

    # Write output PCAP file
    scapy.wrpcap(args.output_pcap, new_packets)
