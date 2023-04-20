"""
Randomly edit packet fields in a PCAP file.
"""

import string
import argparse
import json
import random
import scapy.all as scapy
from scapy.layers import dhcp, dhcp6, dns, http, inet, inet6, l2, ntp


# List of all alphanumerical characters
ALPHANUM = list(string.ascii_letters + string.digits)


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

    # Loop on packets
    i = 0
    for packet in packets:

        if i == 3:
            layer = packet.lastlayer()
            print(layer.Path)

        # Choose randomly if we edit this packet
        if random.randint(0, 10) != 0:
            # Packet won't be edited
            # Go to next packet
            continue

        # Packet will be edited
        # Get packet highest layer
        layer = packet.lastlayer().name

        # Check if layer is supported
        if layer not in protocols:
            # Layer not supported
            # Go to next packet
            continue

        # Get layer modifiable fields
        fields = protocols[layer]["fields"]

        # Get field which will be modified
        field, value_type = random.choice(list(fields.items()))

        # Store current value of field
        old_value = packet.getfieldval(field)

        # Modify field
        if isinstance(value_type, list):
            # Field value is a list
            # Choose randomly a value from the list
            values = value_type
            new_value = old_value
            # Randomly pick new value until it is different from old value
            while new_value == old_value:
                new_value = random.choice(values)
        elif value_type == "str":
            # Field value is a string
            # Randomly change one character
            char = random.choice(ALPHANUM)
            new_value = list(old_value)
            new_value[random.randint(0, len(new_value) - 1)] = char
            new_value = "".join(new_value)
        # TODO elif value_type == "int":

        
        i += 1

    # Write output PCAP file
    scapy.wrpcap(args.output_pcap, packets)
