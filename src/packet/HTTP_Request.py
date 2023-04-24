import scapy.all as scapy
from scapy.layers import http
from packet.Packet import Packet

class HTTP_Request(Packet):

    # Class variables
    name = "HTTP Request"

    # Modifiable fields
    fields = {
        "Method": [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "TRACE",
            "CONNECT"
        ],
        "Path": "str"
    }
