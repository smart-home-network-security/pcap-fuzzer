"""
Randomly edit packet fields in a PCAP file.
"""

import os
import argparse
import random
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
    # Optional flag: -d / --dry-run
    parser.add_argument("-d", "--dry-run", action="store_true", help="Dry run: do not write output PCAP file.")
    # Optional flag: -r / --random-range
    parser.add_argument("-r", "--random-range", type=int, default=0, help="Upper bound for random range.")
    # Optional flag: -n / --packet-number
    parser.add_argument("-n", "--packet-number", type=int, action="append", help="Index of the packet to edit, starting form 1. Can be specifed multiple times.")
    # Parse arguments
    args = parser.parse_args()


    ### MAIN PROGRAM ###

    # Loop on given input PCAP files
    for input_pcap in args.input_pcaps:
        # Useful paths
        input_dir = os.path.dirname(input_pcap)

        # Read input PCAP file
        packets = scapy.rdpcap(input_pcap)
        logging.info(f"Read input PCAP file: {input_pcap}")

        # Open log CSV file
        csv_dir = os.path.join(input_dir, "csv")
        os.makedirs(csv_dir, exist_ok=True)
        csv_log = os.path.basename(input_pcap).replace(".pcap", ".edit.csv")
        csv_log = os.path.join(csv_dir, csv_log)
        with open(csv_log, "w") as csv_file:
            field_names = ["id", "timestamp", "protocol", "field", "old_value", "new_value"]
            writer = csv.DictWriter(csv_file, fieldnames=field_names)
            writer.writeheader()

            if args.packet_number is not None:
                # Edit specific packets
                for i in args.packet_number:
                    packet = packets[i - 1]  # -1 because packet numbers start at 1
                    try:
                        my_packet = Packet.init_packet(packet, i)
                    except ValueError:
                        # No supported protocol found in packet, skip it
                        pass
                    else:
                        d = my_packet.tweak()
                        if d is not None:
                            writer.writerow(d)

            else:
                # Randomly edit packets
                i = 1
                for packet in packets:

                    # Choose randomly if we edit this packet
                    if random.randint(0, args.random_range) != 0:
                        # Packet won't be edited
                        # Go to next packet
                        i += 1
                        continue

                    # Edit packet, if possible
                    try:
                        my_packet = Packet.init_packet(packet, i)
                    except ValueError:
                        # No supported protocol found in packet, skip it
                        pass
                    else:
                        d = my_packet.tweak()
                        if d is not None:
                            writer.writerow(d)
                    finally:
                        i += 1

        # Write output PCAP file
        output_dir = os.path.join(os.path.dirname(input_pcap), "edited")
        os.makedirs(output_dir, exist_ok=True)
        output_pcap = os.path.basename(input_pcap).replace(".pcap", ".edit.pcap")
        output_pcap = os.path.join(output_dir, output_pcap)
        if args.dry_run:
            logging.info(f"Dry run: did not write output PCAP file: {output_pcap}")
        else:
            scapy.wrpcap(output_pcap, packets)
            logging.info(f"Wrote output PCAP file: {output_pcap}")
