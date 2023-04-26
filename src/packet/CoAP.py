import random
import scapy.all as scapy
from scapy.contrib import coap
from packet.Packet import Packet

class CoAP(Packet):

    # Class variables
    name = "CoAP"

    # Modifiable fields
    fields = {
        "type": "int[0,3]",
        "code": "int[1,4]",
    }
    fields = [
        "type",
        "code",
        "uri"
    ]


    @staticmethod
    def new_int_value(old_value: int, start: int, end: int) -> int:
        """
        Generate a new random integer value between start and end, different from old_value.

        :param old_value: Old value of the integer.
        :param start: Start of the range.
        :param end: End of the range.
        :return: New random integer value.
        :raises ValueError: If start is greater than end.
        """
        # Invalid parameters handling
        if start > end:
            raise ValueError("Start value must be smaller than end value.")
        
        # Generate new random int value
        new_value = old_value
        while new_value == old_value:
            new_value = random.randint(start, end)
        return new_value
    

    @staticmethod
    def edit_uri(options: list) -> list:
        """
        Randomly edit one character in each part of the URI of a CoAP packet.

        :param options: List of CoAP options.
        :return: Edited list of CoAP options.
        """
        new_options = []
        for i in range(len(options)):
            if options[i][0] == "Uri-Path" or options[i][0] == "Uri-Query":
                new_options.append((options[i][0], Packet.string_edit_char(options[i][1])))
            else:
                new_options.append(options[i])
        return new_options


    def tweak(self) -> None:
        """
        Randomly edit one field of the CoAP packet.
        """
        # Get field which will be modified
        field = random.choice(self.fields)

        # Chosen field is an integer
        if field == "type" or field == "code":
            old_value = self.layer.getfieldval(field)
            if field == "type":
                new_value = CoAP.new_int_value(old_value, 0, 3)
            elif field == "code":
                new_value = CoAP.new_int_value(old_value, 1, 4)
            print(f"Packet {self.id}: {self.name}.{field} = {old_value} -> {new_value}")
            self.layer.setfieldval(field, new_value)
        
        # Chosen field is the URI
        elif field == "uri":
            options = CoAP.edit_uri(self.layer.getfieldval("options"))
            print(f"Packet {self.id}: Randomly edit CoAP URI")
            self.layer.setfieldval("options", CoAP.edit_uri(options))
        
        # Update checksums
        self.update_checksums()
