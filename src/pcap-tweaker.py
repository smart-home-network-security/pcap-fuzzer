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

    # Script-related variables
    script_name = os.path.basename(__file__)
    script_path = os.path.dirname(os.path.abspath(__file__))
    base_path = os.path.dirname(script_path)

    ### LOGGING CONFIGURATION ###
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting {script_name}")


    ### ARGUMENT PARSING ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Randomly edit packet fields in a PCAP file."
    )
    # Positional arguments: input PCAP file
    parser.add_argument("input_pcaps", metavar="pcap", type=str, nargs="+", help="Input PCAP files.")
    args = parser.parse_args()

    
    ### MAIN PROGRAM ###

    # Loop on given input PCAP files
    for input_pcap in args.input_pcaps:
        # Read input PCAP file
        packets = scapy.rdpcap(input_pcap)
        logging.info(f"Read input PCAP file: {input_pcap}")
        new_packets = []

        # Open log CSV file
        csv_dir = os.path.join(base_path, "csv")
        os.makedirs(csv_dir, exist_ok=True)
        csv_log = input_pcap.replace(".pcap", ".edit.csv")
        csv_log = os.path.join(csv_dir, os.path.basename(csv_log))
        with open(csv_log, "w") as csv_file:
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
        output_pcap = input_pcap.replace(".pcap", ".edit.pcap")
        #scapy.wrpcap(output_pcap, new_packets)
        logging.info(f"Wrote output PCAP file: {output_pcap}")
