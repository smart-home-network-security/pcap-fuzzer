import scapy.all as scapy
from packet.Packet import Packet

class ICMP(Packet):

    # Class variables
    name = "ICMP"

    # Modifiable fields
    fields = {
        "type": "int[0,255]"
    }
