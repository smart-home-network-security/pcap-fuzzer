import logging
import random
import scapy.all as scapy
from scapy.layers import dns
from packet.Packet import Packet

class DNS(Packet):

    # Class variables
    name = "DNS"
    qtypes = [
        1,   # A
        2,   # NS
        3,   # MD
        4,   # MF
        5,   # CNAME
        6,   # SOA
        7,   # MB
        8,   # MG
        9,   # MR
        10,  # NULL
        11,  # WKS
        12,  # PTR
        13,  # HINFO
        14,  # MINFO
        15,  # MX
        16,  # TXT
        28,  # AAAA
        41,  # OPT
        255  # ANY
    ]

    # Modifiable fields
    fields = [
        "qr",
        "qtype",
        "qname"
    ]


    def tweak(self) -> dict:
        """
        Randomly edit one DNS field, among the following:
            - QR flag
            - Query type
            - Query name

        :return: Dictionary containing tweak information.
        """
        # Get field which will be modified
        field = random.choice(self.fields)
        # Get auxiliary fields
        qdcount = self.layer.getfieldval("qdcount")
        question_record = self.layer.getfieldval("qd") if qdcount > 0 else None
        
        # Field is QR flag
        if field == "qr":
            # Flip QR flag value
            old_value = self.layer.getfieldval("qr")
            new_value = int(not old_value)
            self.layer.setfieldval("qr", new_value)
        
        # Field is query type
        elif field == "qtype" and question_record is not None:
            old_value = question_record.getfieldval("qtype")
            # Randomly pick new query type
            new_value = old_value
            while new_value == old_value:
                new_value = random.choice(self.qtypes)
            question_record.setfieldval("qtype", new_value)
        
        # Field is query name
        elif field == "qname" and question_record is not None:
            old_value = question_record.getfieldval("qname")
            # Randomly change one character in query name
            new_value = old_value
            while new_value == old_value:
                new_value = Packet.bytes_edit_char(old_value)
            question_record.setfieldval("qname", new_value)
        
        # Update checksums
        self.update_checksums()

        # Return value: dictionary containing tweak information
        return self.get_dict_log(field, old_value, new_value)
