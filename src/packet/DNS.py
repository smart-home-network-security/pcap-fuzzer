import scapy.all as scapy
from scapy.layers import dns
from Packet import Packet

class DNS(Packet):

    # Class variables
    layer = 7


    def __init__(self, packet: scapy.Packet) -> None:
        """
        DNS packet constructor.

        :param packet: Scapy Packet to be edited.
        """
        self.packet = packet
        self.dns_layer = packet.getlayer(scapy.DNS)


    def tweak(self) -> None:
        pass
