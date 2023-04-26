from typing import Tuple
import re
import random
import scapy.all as scapy
from scapy.layers import dhcp
from packet.Packet import Packet

class DHCP(Packet):

    # Class variables
    name = "DHCP"

    # Modifiable fields
    fields = {
        "message-type": "int[1,8]",
        "client_id": "str",  # Actually a byte array
    }


    def get_dhcp_option(self, option_name) -> Tuple[str, any]:
        """
        Retrieve a DHCP option from the packet.

        :param option_name: Name of the DHCP option to retrieve.
        :return: DHCP option, as a tuple (name, value).
        """
        dhcp_options = self.layer.getfieldval("options")
        for option in dhcp_options:
            if option[0] == option_name:
                return option
            
    
    def set_dhcp_option(self, option_name, option_value) -> None:
        """
        Set a DHCP option in the packet.

        :param option_name: Name of the DHCP option to set.
        :param option_value: Value of the DHCP option to set.
        """
        dhcp_options = self.layer.getfieldval("options")
        for i in range(len(dhcp_options)):
            if dhcp_options[i][0] == option_name:
                dhcp_options[i] = option_name, option_value
                break
        self.layer.setfieldval("options", dhcp_options)


    def tweak(self) -> None:
        """
        Randomly edit one DHCP option.
        """
        # Get field which will be modified
        field, value_type = random.choice(list(self.fields.items()))
        # Store old value of field
        old_value = self.get_dhcp_option(field)[1]

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
                char = random.choice(Packet.ALPHANUM)
                new_value = list(old_value)
                new_value[random.randint(0, len(new_value) - 1)] = char
                new_value = bytes(new_value)

        # Set new value for field
        print(f"Packet {self.id}: {self.name}.{field} = {old_value} -> {new_value}")
        self.set_dhcp_option(field, new_value)

        # Update checksums
        self.update_checksums()
