import scapy.all as scapy
from packet.Packet import Packet

class TCP(Packet):

    # Class variables
    name = "TCP"

    # Modifiable fields
    fields = {
        "sport": "port",
        "dport": "port"
    }
