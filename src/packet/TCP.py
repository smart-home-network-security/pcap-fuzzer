import scapy.all as scapy
from packet.Transport import Transport

class TCP(Transport):

    # Class variables
    name = "TCP"

    # Modifiable fields
    fields = {
        "sport": "port",
        "dport": "port"
    }

    # Well-known ports
    ports = [
        80,    # HTTP
        443,   # HTTPS
        8080,  # HTTP alternate
        9999   # TP-Link
    ]
