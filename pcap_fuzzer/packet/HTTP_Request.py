from Packet import Packet

class HTTP_Request(Packet):

    # Class variables
    name = "HTTP Request"

    # Modifiable fields
    fields = {
        "Method": [
            b"GET",
            b"POST",
            b"PUT",
            b"DELETE",
            b"HEAD",
            b"OPTIONS",
            b"TRACE",
            b"CONNECT"
        ],
        "Path": "bytes"
    }
