import scapy.all as scapy
from scapy.contrib import igmpv3
from packet.Packet import Packet

class IGMPv3mr(Packet):
    """
    IGMP Version 3 Membership Report packet.
    """

    # Class variables
    name = "IGMPv3mr"


    def tweak(self) -> None:
        """
        Tweak the IGMPv3 Membership Report packet,
        by randomizing all group addresses.
        """

        # Set random IP address for all group records
        groups = self.packet.getfieldval("records")
        for group in groups:
            group.setfieldval("maddr", Packet.random_ip_address(version=4))
        
        print(f"Packet {self.id}: randomized all IGMPv3 group addresses.")

        # Update checksums
        del self.packet.getlayer("IGMPv3").chksum
        del self.packet.getlayer("IP").len
        del self.packet.getlayer("IP").chksum
        self.packet = scapy.Ether(self.packet.build())
