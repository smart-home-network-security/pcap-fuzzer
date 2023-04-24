import scapy.all as scapy
from packet.Packet import Packet

class UDP(Packet):

    # Class variables
    name = "UDP"

    # Modifiable fields
    fields = {
        "sport": "port",
        "dport": "port"
    }
