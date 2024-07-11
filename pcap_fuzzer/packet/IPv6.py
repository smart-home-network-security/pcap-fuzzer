from Packet import Packet

class IPv6(Packet):

    # Class variables
    name = "IPv6"

    # Modifiable fields
    fields = {
        "src": "ipv6",
        "dst": "ipv6"
    }
