"""
Randomly edit packet fields in a PCAP file.
"""

import string
import argparse
import json
import random
from ipaddress import ip_address, IPv4Address, IPv6Address
import scapy.all as scapy
from scapy.layers import dhcp, dhcp6, dns, http, inet, inet6, l2, ntp


# List of all alphanumerical characters
ALPHANUM = list(bytes(string.ascii_letters + string.digits, "utf-8"))


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
        if i != 3:
            # Packet won't be edited
            # Go to next packet
            new_packets.append(packet)
            i += 1
            continue

        # Packet will be edited
        # Get packet highest layer
        #layer = packet.lastlayer().name
        layer = packet.getlayer("IP")

        # Check if layer is supported
        if layer.name not in protocols:
            # Layer not supported
            # Go to next packet
            new_packets.append(packet)
            i += 1
            continue

        # Get layer modifiable fields
        fields = protocols[layer.name]["fields"]

        # Get field which will be modified
        #field, value_type = random.choice(list(fields.items()))
        field, value_type = "src", "ipv4"

        # Store current value of field
        old_value = layer.getfieldval(field)

        # Modify field value until it is different from old value
        new_value = old_value
        while new_value == old_value:
            if isinstance(value_type, list):
                # Field value is a list
                # Choose randomly a value from the list
                values = value_type
                new_value = old_value
                # Randomly pick new value
                new_value = bytes(random.choice(values), "utf-8")
            elif value_type == "int":
                # Field value is an integer
                # Generate a random integer between 0 and 65535
                new_value = random.randint(0, 65535)
            elif value_type == "str":
                # Field value is a string
                # Randomly change one character
                char = random.choice(ALPHANUM)
                new_value = list(old_value)
                new_value[random.randint(0, len(new_value) - 1)] = char
                new_value = bytes(new_value)
            elif value_type == "port":
                # Field value is an port number
                # Generate a random port number between 1024 and 65535
                new_value = random.randint(1024, 65535)
            elif value_type == "ipv4":
                # Field value is an IPv4 address
                # Generate a random IPv4 address
                new_value = str(IPv4Address(random.randint(0, IPv4Address._ALL_ONES)))
            elif value_type == "ipv6":
                # Field value is an IPv6 address
                # Generate a random IPv6 address
                new_value = str(IPv6Address(random.randint(0, IPv6Address._ALL_ONES)))
        
        # Set new value for field
        print(f"Packet {i}: {layer.name}.{field} = {old_value} -> {new_value}")
        layer.setfieldval(field, new_value)

        # Update checksums
        del packet.getlayer(1).len
        del packet.getlayer(1).chksum
        if packet.getlayer(2).name == "UDP":
            del packet.getlayer(2).len
        del packet.getlayer(2).chksum
        packet = scapy.Ether(packet.build())

        new_packets.append(packet)
        i += 1

    # Write output PCAP file
    scapy.wrpcap(args.output_pcap, new_packets)
