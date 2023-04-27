import logging
import scapy.all as scapy
from scapy.contrib import igmpv3
from packet.Packet import Packet

class IGMPv3mr(Packet):
    """
    IGMP Version 3 Membership Report packet.
    """

    # Class variables
    name = "IGMPv3mr"


    def tweak(self) -> dict:
        """
        Tweak the IGMPv3 Membership Report packet,
        by randomizing all group addresses.

        :return: Dictionary containing tweak information.
        """
        # Set random IP address for all group records
        old_value = ""
        new_value = ""
        groups = self.packet.getfieldval("records")
        i = 0
        for group in groups:
            if i != 0:
                old_value += "-"
                new_value += "-"
            old_value += group.getfieldval("maddr")
            new_address = Packet.random_ip_address(version=4)
            new_value += new_address
            group.setfieldval("maddr", new_address)
            i += 1
        
        logging.info(f"Packet {self.id}: randomized all IGMPv3 group addresses.")

        # Update checksums
        del self.packet.getlayer("IGMPv3").chksum
        del self.packet.getlayer("IP").len
        del self.packet.getlayer("IP").chksum
        self.packet = scapy.Ether(self.packet.build())

        # Return value: dictionary containing tweak information
        return self.get_dict_log("maddr", old_value, new_value)
