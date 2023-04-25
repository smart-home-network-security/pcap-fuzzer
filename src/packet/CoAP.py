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
