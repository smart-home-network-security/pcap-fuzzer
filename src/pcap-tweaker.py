"""
Randomly edit packet fields in a PCAP file.
"""

import os
import argparse
import logging
import csv
import scapy.all as scapy
from scapy.layers import dhcp, dns, http
from scapy.contrib import coap, igmp, igmpv3
from packet.Packet import Packet


if __name__ == "__main__":

    script_name = os.path.basename(__file__)

    ### LOGGING CONFIGURATION ###
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting {script_name}")


    ### ARGUMENT PARSING ###
    
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Randomly edit packet fields in a PCAP file."
    )

    # Positional argument #1: input PCAP file
    parser.add_argument("input_pcap", type=str, help="Input PCAP file.")
    # Optional argument -o: output PCAP file
    parser.add_argument("-o", "--output_pcap", type=str, help="Output PCAP file. Default is input file name with '.tweak' appended.")

    args = parser.parse_args()
    if args.output_pcap is None:
        args.output_pcap = args.input_pcap.replace(".pcap", ".tweak.pcap")

    
    ### MAIN PROGRAM ###

    # Read input PCAP file
    packets = scapy.rdpcap(args.input_pcap)
    logging.info(f"Read input PCAP file: {args.output_pcap}")
    new_packets = []

    # Open log CSV file
    with open("tweaked_packets.csv", "w") as csv_file:
        field_names = ["id", "protocol", "field", "old_value", "new_value"]
        writer = csv.DictWriter(csv_file, fieldnames=field_names)
        writer.writeheader()

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
                d = packet.tweak()
                new_packets.append(packet.get_packet())
                writer.writerow(d)
            except ModuleNotFoundError:
                new_packets.append(packet)
            finally:
                i += 1

    # Write output PCAP file
    #scapy.wrpcap(args.output_pcap, new_packets)
    logging.info(f"Wrote output PCAP file: {args.output_pcap}")
