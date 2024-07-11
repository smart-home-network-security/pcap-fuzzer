from Packet import Packet

class IGMPv3mr(Packet):
    """
    IGMP Version 3 Membership Report packet.
    """

    # Class variables
    name = "IGMPv3mr"


    def fuzz(self) -> dict:
        """
        fuzz the IGMPv3 Membership Report packet,
        by randomizing all group addresses.

        :return: Dictionary containing fuzz information.
        """
        # Store old hash value
        old_hash = self.get_hash()
        # Set random IP address for all group records
        old_value = ""
        new_value = ""
        groups = self.packet.getfieldval("records")
        i = 0
        for group in groups:
            if i != 0:
                old_value += "-"
                new_value += "-"
            old_value += group.getfieldval("maddr")
            new_address = Packet.random_ip_address(version=4)
            new_value += new_address
            group.setfieldval("maddr", new_address)
            i += 1

        # Update checksums
        self.update_fields()

        # Return value: dictionary containing fuzz information
        return self.get_dict_log("maddr", old_value, new_value, old_hash)
