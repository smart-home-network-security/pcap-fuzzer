from typing import Tuple
import random
import scapy.all as scapy
from scapy.layers import dhcp
from packet.Packet import Packet

class DHCP(Packet):

    # Class variables
    name = "DHCP"

    # Modifiable fields
    fields = [
        "message-type",
        "client_id"
    ]


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
        field = random.choice(self.fields)
        # Store old value of field
        old_value = self.get_dhcp_option(field)[1]

        # Modify field value until it is different from old value
        new_value = old_value
        while new_value == old_value:

            if field == "message-type":
                # Message type is an integer between 1 and 8
                new_value = random.randint(1, 8)

            elif field == "client_id":
                # Client ID is a byte array
                # Randomly change one character
                new_value = Packet.string_edit_char(old_value)

        # Set new value for field
        print(f"Packet {self.id}: {self.name}.{field} = {old_value} -> {new_value}")
        self.set_dhcp_option(field, new_value)

        # Update checksums
        self.update_checksums()
