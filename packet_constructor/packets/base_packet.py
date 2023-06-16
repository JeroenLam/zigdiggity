import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../../")
import zigdiggity.crypto.utils as zb_crypto_utils
from Crypto.Util.number import long_to_bytes
from scapy.packet import Packet
from scapy.all import hexdump
from scapy.layers.dot15d4 import Dot15d4FCS
from scapy.layers.zigbee import ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeClusterLibrary


class BasePacket:
    # Unecnrypted packet
    unecnrypted_packet: Packet      # Complete unencrypted packet

    # Components needed to encrypt packet at NWK level
    unencrypted_frame_part: Packet  # Unencrypted portion of packet
    encryptable_frame_part: Packet  # Encrypted portion of packet
    aux_mac_addr: int               # Source address of last transmitter

    
    def __str__(self):
        """
        String casting function
        """
        return hexdump(self.unecnrypted_packet)

    
    def __hex__(self):
        """
        Hex casting function
        """
        return bytes(self.unecnrypted_packet).hex()

    
    def __bytes__(self):
        """
        Bytes casting function
        """
        return bytes(self.unecnrypted_packet)

    
    def __sizeof__(self):
        """
        Sizeof interpreting function
        """
        return len(self.unecnrypted_packet)

    
    def show(self):
        """
        For a developed view of the packet
        """
        return self.unecnrypted_packet.show()

    
    def hexdump(self):
        """
        Return a hexdump of the packet content
        """
        return hexdump(self.unecnrypted_packet)
    
    
    def nwk_encrypted_packet(self, key: bytes):    
        """
        Encrypt a packet using the ZigDiggity crypto utilities.

        Parameters:
        key (bytes): The NWK key used to encrypt the packet.
        """  
        return zb_crypto_utils.zigbee_packet_encrypt(key, 
                                                    self.unencrypted_frame_part, 
                                                    bytes(self.encryptable_frame_part), 
                                                    long_to_bytes(self.aux_mac_addr))


    def set_mac_cnt(self, sequence_number: int):
        """
        Set the MAC sequence number of the packet.
        
        Parameters:
        sequence_number (int): The new sequence number of the packet.
        """
        try:
            self.unencrypted_frame_part[Dot15d4FCS].seqnum = sequence_number
            self.unecnrypted_packet[Dot15d4FCS].seqnum = sequence_number
        except:
            pass
    
    
    def get_mac_cnt(self):
        """
        Get the MAC sequence number of the packet.
        """
        try:
            return self.unencrypted_frame_part[Dot15d4FCS].seqnum
        except:
            return -1
    

    def inc_mac_cnt(self, sequence_number_delta: int):
        """
        Increment the MAC sequence number of the packet.
        
        Parameters:
        sequence_number_delta (int): The value to add to the current sequence number.
        """
        try:
            self.unencrypted_frame_part[Dot15d4FCS].seqnum += sequence_number_delta
            self.unecnrypted_packet[Dot15d4FCS].seqnum += sequence_number_delta
        except:
            pass

    
    def set_nwk_cnt(self, sequence_number: int):
        """
        Set the NWK sequence number of the packet.
        
        Parameters:
        sequence_number (int): The new sequence number of the packet.
        """
        try:
            self.unencrypted_frame_part[ZigbeeNWK].seqnum = sequence_number
            self.unecnrypted_packet[ZigbeeNWK].seqnum = sequence_number
        except:
            pass
    

    def get_nwk_cnt(self):
        """
        Get the NWK sequence number of the packet.
        """
        try:
            return self.unencrypted_frame_part[ZigbeeNWK].seqnum
        except:
            return -1


    def inc_nwk_cnt(self, sequence_number_delta: int):
        """
        Increment the NWK sequence number of the packet.
        
        Parameters:
        sequence_number_delta (int): The value to add to the current sequence number.
        """
        try:
            self.unencrypted_frame_part[ZigbeeNWK].seqnum += sequence_number_delta
            self.unecnrypted_packet[ZigbeeNWK].seqnum += sequence_number_delta
        except:
            pass

    
    def set_aps_cnt(self, sequence_number: int):
        """
        Set the APS sequence number of the packet.
        
        Parameters:
        sequence_number (int): The new sequence number of the packet.
        """
        try:
            self.encryptable_frame_part[ZigbeeAppDataPayload].counter = sequence_number
            self.unecnrypted_packet[ZigbeeAppDataPayload].counter = sequence_number
        except:
            pass

    
    def get_aps_cnt(self):
        """
        Get the APS sequence number of the packet.
        """
        try:
            return self.encryptable_frame_part[ZigbeeAppDataPayload].counter
        except:
            return -1
        
    
    def inc_aps_cnt(self, sequence_number_delta: int):
        """
        Increment the APS sequence number of the packet.
        
        Parameters:
        sequence_number_delta (int): The value to add to the current sequence number.
        """
        try:
            self.encryptable_frame_part[ZigbeeAppDataPayload].counter += sequence_number_delta
            self.unecnrypted_packet[ZigbeeAppDataPayload].counter += sequence_number_delta
        except:
            pass

    
    def set_zcl_cnt(self, sequence_number: int):
        """
        Set the ZCL sequence number of the packet.
        
        Parameters:
        sequence_number (int): The new sequence number of the packet.
        """
        try:
            self.encryptable_frame_part[ZigbeeClusterLibrary].transaction_sequence = sequence_number
            self.unecnrypted_packet[ZigbeeClusterLibrary].transaction_sequence = sequence_number
        except:
            pass

    
    def get_zcl_cnt(self):
        """
        Get the ZCL sequence number of the packet.
        """
        try:
            return self.encryptable_frame_part[ZigbeeClusterLibrary].transaction_sequence
        except:
            return -1

    
    def inc_zcl_cnt(self, sequence_number_delta: int):
        """
        Increment the ZCL sequence number of the packet.
        
        Parameters:
        sequence_number_delta (int): The value to add to the current sequence number.
        """
        try:
            self.encryptable_frame_part[ZigbeeClusterLibrary].transaction_sequence += sequence_number_delta
            self.unecnrypted_packet[ZigbeeClusterLibrary].transaction_sequence += sequence_number_delta
        except:
            pass

 
    def set_nwk_fc(self, frame_counter: int):
        """
        Set the NWK frame counter of the packet.
        
        Parameters:
        frame_counter (int): The new frame counter of the packet.
        """
        try:
            self.unencrypted_frame_part[ZigbeeSecurityHeader].fc = frame_counter
        except:
            pass

    
    def get_nwk_fc(self):
        """
        Get the NWK frame counter of the packet.
        """
        try:
            return self.unencrypted_frame_part[ZigbeeSecurityHeader].fc
        except:
            return -1


    def inc_nwk_fc(self, frame_counter_delta: int):
        """
        Increment the NWK frame counter of the packet.
        
        Parameters:
        frame_counter_delta (int): The value to add to the current frame counter.
        """
        try:
            self.unencrypted_frame_part[ZigbeeSecurityHeader].fc += frame_counter_delta
        except:
            pass


    def print_cnt(self):
        """
        Print all sequence numbers and framecounters of the 802.15.4 / ZigBee packet.
        """
        print('==== Sequence numbers ====')
        try:
            print(' MAC Sequence number : ', self.get_mac_cnt())
        except:
            pass
        try:
            print(' NWK Sequence number : ', self.get_nwk_cnt())
        except:
            pass
        try:
            print(' APS Sequence number : ', self.get_aps_cnt())
        except:
            pass
        try:
            print(' ZCL Sequence number : ', self.get_zcl_cnt())
        except:
            pass
        try:
            nwk_fc = self.get_nwk_fc()
            print('------ Frame counter -----')
            print(' NWK Frame counter : ', nwk_fc)
        except:
            pass
        print('==========================')
        
