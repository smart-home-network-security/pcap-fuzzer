from __future__ import annotations
import importlib
import logging
import string
import re
import random
from ipaddress import IPv4Address, IPv6Address
import scapy.all as scapy

class Packet:
    """
    Wrapper around the Scapy `Packet` class.
    """

    # List of all alphanumerical characters
    ALPHANUM_CHARS = list(string.ascii_letters + string.digits)
    ALPHANUM_BYTES = list(bytes(string.ascii_letters + string.digits, "utf-8"))

    # Protocol name correspondences
    protocols = {
        "DHCP": "BOOTP"
    }

    # Modifiable fields, will be overridden by child classes
    fields = {}


    @staticmethod
    def string_edit_char(s: str) -> str:
        """
        Randomly change one character in a string.

        :param s: String to be edited.
        :return: Edited string.
        """
        char = random.choice(Packet.ALPHANUM_CHARS)
        new_value = list(s)
        new_value[random.randint(0, len(new_value) - 1)] = char
        print(new_value)
        return "".join(new_value)
    

    @staticmethod
    def bytes_edit_char(s: bytes) -> bytes:
        """
        Randomly change one character in a byte array.

        :param s: Byte array to be edited.
        :return: Edited byte array.
        """
        byte = random.choice(Packet.ALPHANUM_BYTES)
        new_value = list(s)
        new_value[random.randint(0, len(new_value) - 1)] = byte
        return bytes(new_value)


    @staticmethod
    def random_mac_address() -> str:
        """
        Generate a random MAC address.

        :return: Random MAC address.
        """
        return ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])


    @staticmethod
    def random_ip_address(version: int = 4) -> str:
        """
        Generate a random IP address.

        :param version: IP version (4 or 6).
        :return: Random IP address.
        :raises ValueError: If IP version is not 4 or 6.
        """
        if version == 4:
            return str(IPv4Address(random.randint(0, IPv4Address._ALL_ONES)))
        elif version == 6:
            return str(IPv6Address(random.randint(0, IPv6Address._ALL_ONES)))   
        else:
            raise ValueError("Invalid IP version (should be 4 or 6).")       


    @classmethod
    def init_packet(c, protocol: str, packet: scapy.Packet, id: int = 0) -> Packet:
        """
        Factory method to create a packet of a given protocol.

        :param protocol: Packet highest layer protocol.
        :param packet: Scapy Packet to be edited.
        :param id: Packet integer identifier.
        :return: Packet of given protocol,
                 or generic Packet if protocol is not supported.
        """
        # Try creating specific packet if possible
        protocol = protocol.split()[0]
        if protocol == "IP" and packet.getfieldval("version") == 4:
            protocol = "IPv4"
        elif protocol == "IP" and packet.getfieldval("version") == 6:
            protocol = "IPv6"
        else:
            protocol = Packet.protocols.get(protocol, protocol)
        module = importlib.import_module(f"packet.{protocol}")
        cls = getattr(module, protocol)
        return cls(packet, id)


    def __init__(self, packet: scapy.Packet, id: int = 0) -> None:
        """
        Generic packet constructor.

        :param packet: Scapy Packet to be edited.
        :param id: Packet integer identifier.
        """
        self.id = id
        self.packet = packet
        try:
            self.layer = packet.getlayer(self.name)
        except AttributeError:
            self.layer = packet.lastlayer()

    
    def get_packet(self) -> scapy.Packet:
        """
        Get Scapy packet.

        :return: Scapy Packet.
        """
        return self.packet
    

    def update_checksums(self) -> None:
        """
        Update packet checksums, if needed.
        """
        if self.packet.haslayer("IP"):
            ip_layer = self.packet.getlayer("IP")
            ip_layer.delfieldval("len")
            ip_layer.delfieldval("chksum")
            transport_layer = self.packet.getlayer(2)
            if hasattr(transport_layer, "len"):
                transport_layer.delfieldval("len")
            if hasattr(transport_layer, "chksum"):
                transport_layer.delfieldval("chksum")
            self.packet = scapy.Ether(self.packet.build())

        
    def get_dict_log(self, field: str, old_value: str, new_value: str) -> dict:
        """
        Log packet field modification,
        and return a dictionary containing tweak information.

        :param field: Field name.
        :param old_value: Old field value.
        :param new_value: New field value.
        :return: Dictionary containing tweak information.
        """
        logging.info(f"Packet {self.id}: {self.name}.{field} = {old_value} -> {new_value}")
        d = {
            "id": self.id,
            "protocol": self.name,
            "field": field,
            "old_value": old_value,
            "new_value": new_value
        }
        return d


    def tweak(self) -> dict:
        """
        Randomly edit one packet field.

        :return: Dictionary containing tweak information.
        """
        # Get field which will be modified
        field, value_type = random.choice(list(self.fields.items()))
        # Store old value of field
        old_value = self.layer.getfieldval(field)

        # Modify field value until it is different from old value
        new_value = old_value
        while new_value == old_value:

            if isinstance(value_type, list):
                # Field value is a list
                # Choose randomly a value from the list
                values = value_type
                new_value = old_value
                # Randomly pick new value
                new_value = random.choice(values)

            elif "int" in value_type:
                # Field value is an integer
                # Generate a random integer between given range
                if value_type == "int":
                    # No range given, default is 0-65535
                    new_value = random.randint(0, 65535)
                else:
                    # Range given
                    pattern = re.compile(r"int\[\s*(?P<start>\d+),\s*(?P<end>\d+)\s*\]")
                    match = pattern.match(value_type)
                    start = int(match.group("start"))
                    end = int(match.group("end"))
                    new_value = random.randint(start, end)

            elif value_type == "str":
                # Field value is a string
                # Randomly change one character
                new_value = Packet.string_edit_char(old_value)
            
            elif value_type == "bytes":
                # Field value is a byte array
                # Randomly change one byte
                new_value = Packet.bytes_edit_char(old_value)

            elif value_type == "port":
                # Field value is an port number
                # Generate a random port number between 1024 and 65535
                new_value = random.randint(1024, 65535)

            elif value_type == "ipv4":
                # Field value is an IPv4 address
                # Generate a random IPv4 address
                new_value = Packet.random_ip_address(version=4)

            elif value_type == "ipv6":
                # Field value is an IPv6 address
                # Generate a random IPv6 address
                new_value = Packet.random_ip_address(version=6)
            
            elif value_type == "mac":
                # Field value is a MAC address
                # Generate a random MAC address
                new_value = Packet.random_mac_address()
            
        # Set new value for field
        self.layer.setfieldval(field, new_value)

        # Update checksums, if needed
        self.update_checksums()

        # Return value: dictionary containing tweak information
        return self.get_dict_log(field, old_value, new_value)
