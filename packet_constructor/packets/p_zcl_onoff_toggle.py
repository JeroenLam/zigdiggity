import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../../")
import argparse

from packet_constructor.packets.base_packet import BasePacket
from scapy.layers.dot15d4 import Dot15d4FCS, Dot15d4Data
from scapy.layers.zigbee import ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeClusterLibrary
from scapy.all import PcapWriter


class ZCLOnOffToggle(BasePacket):
    def __init__(self, nwk_src: int, nwk_dst: int, pan_id: int, 
                 aux_mac_addr: int, nwk_fc: int, dst_endpoint: int,
                 mac_cnt: int, nwk_cnt: int, aps_cnt: int, zcl_cnt: int):
        """
        Creates a ZCL OnOff toggle ZigBee frame.

        Parameters:
        nwk_src (int): The NWK address of the source device.
        nwk_dst (int): The NWK address of the destination device.
        pan_id (int): The PAN ID of the ZigBee network.
        aux_mac_addr (int): The MAC address of the current sender.
        nwk_fc (int): The NWK AUX header frame counter.
        dst_endpoint (int): The endpoint of the onOff cluster on the light/socket.
        mac_cnt (int): The MAC sequence number.
        nwk_cnt (int): The NWK sequence number.
        aps_cnt (int): The APS sequence number.
        zcl_cnt (int): The ZCL sequence number.
        """
        # 802.15.4 MAC header
        mac_head = Dot15d4FCS()
        mac_head.fcf_frametype = 1      # Frame Type (data)
        mac_head.fcf_pending = 0        # Frame pending (false)
        mac_head.fcf_ackreq = 1         # Ack request (true)
        mac_head.fcf_panidcompress = 1  # 0:EPAN ID - 1:PAN ID 
        mac_head.fcf_framever = 0       # Frame version (2003)
        mac_head.fcf_destaddrmode = 2   # DST address format (NWK adr)
        mac_head.fcf_srcaddrmode = 2    # SRC address format (NWK adr)
        mac_head.seqnum = mac_cnt       # IEEE seq num

        # IEEE 802.15.4 Data
        mac_data = Dot15d4Data()
        mac_data.dest_panid = pan_id   # PAN ID
        mac_data.dest_addr = nwk_dst   # Address next hop
        mac_data.src_addr = nwk_src    # Address current sender

        # ZigBee NWK header
        nwk_head = ZigbeeNWK()
        nwk_head.frametype = 0                # Frame type (data)
        nwk_head.proto_version = 2            # ZigBee version (PRO)
        nwk_head.destination = nwk_dst        # Dst NWK address
        nwk_head.source = nwk_src             # Src NWK address
        nwk_head.radius = 30                  # Radius of message
        nwk_head.seqnum = nwk_cnt             # NWK seq num

        # ZigBee NWK Aux header
        nwk_sec = ZigbeeSecurityHeader()
        nwk_sec.extended_nonce = 1           # Extended nonce (true)
        nwk_sec.key_type = 1                 # Key type (NWK key)
        nwk_sec.fc = nwk_fc                  # NWK AUX framecounter
        nwk_sec.source = aux_mac_addr        # MAC of current sender
        nwk_sec.key_seqnum = 0               # Key sequence number
        self.aux_mac_addr = aux_mac_addr     # Store MAC of current sender for encryption

        # ZigBee APS layer
        aps_data = ZigbeeAppDataPayload()
        aps_data.frame_control = 0                  # Application level security (false)
        aps_data.src_endpoint = 1                   # Endpoint of 'remote'
        aps_data.dst_endpoint = dst_endpoint        # Endpoint of 'light/socket'
        aps_data.profile = 0x0104                   # ZigBee Profile (Home Automation / 3.0)
        aps_data.cluster = 0x0006                   # ZigBee Cluster (OnOff)
        aps_data.counter = aps_cnt                  # APS counter

        # ZigBee Cluster Library
        zcl_data = ZigbeeClusterLibrary()
        zcl_data.zcl_frametype = 1                 # Frame type (Cluster specific)
        zcl_data.disable_default_response = 1      # Disable default response (true)
        zcl_data.command_direction = 0             # Client -> Server
        zcl_data.command_identifier = int(2)       # 1 = on, 0 = off, 2 = toggle
        zcl_data.transaction_sequence = zcl_cnt    # ZCL counter

        # Store data to encrypt packet
        nwk_head.flags.security = 1
        self.unencrypted_frame_part = mac_head / mac_data / nwk_head / nwk_sec
        self.encryptable_frame_part = aps_data / zcl_data
        
        # Create the unencrypted packet
        nwk_head.flags.security = 0
        self.unecnrypted_packet = mac_head / mac_data / nwk_head / aps_data / zcl_data

# Parsing arguments 
def parse_arguments():
    parser = argparse.ArgumentParser(description='Parsing on off command parameters.')
    parser.add_argument('--pcap-path',      type=str, default='out.pcap', help='PCAP path (string), default=out.pcap')
    parser.add_argument('--append',         type=bool, default=True, help='Append flag (boolean)')
    parser.add_argument('--key',            type=str, default=None, help='Key (integer), default=None')
    parser.add_argument('--nwk-src',        type=lambda x: int(x, 16), default=0x466e, help='NWK source (integer), default=0x466e')
    parser.add_argument('--nwk-dst',        type=lambda x: int(x, 16), default=0x0000, help='NWK destination (integer), default=0x0000')
    parser.add_argument('--pan-id',         type=lambda x: int(x, 16), default=0x1a3e, help='PAN ID (integer), default=0x1a3e')
    parser.add_argument('--aux-mac-addr',   type=lambda x: int(x, 16), default=0x842e14fffef9494c, help='Auxiliary MAC address (integer), default=0x842e14fffef9494c')
    parser.add_argument('--dst-endpoint',   type=int, default=9, help='Destination endpoint (integer), default=9')
    parser.add_argument('--nwk-fc',         type=int, default=20, help='NWK FC (integer), default=20')
    parser.add_argument('--mac-cnt',        type=int, default=1, help='MAC count (integer), default=1')
    parser.add_argument('--nwk-cnt',        type=int, default=2, help='NWK count (integer), default=2')
    parser.add_argument('--aps-cnt',        type=int, default=3, help='APS count (integer), default=3')
    parser.add_argument('--zcl-cnt',        type=int, default=4, help='ZCL count (integer), default=4')

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    # Parse user arguments
    arguments = parse_arguments()
    pcap_path = arguments.pcap_path
    append = arguments.append
    key = arguments.key
    nwk_src = arguments.nwk_src
    nwk_dst = arguments.nwk_dst
    pan_id = arguments.pan_id
    aux_mac_addr = arguments.aux_mac_addr
    dst_endpoint = arguments.dst_endpoint
    nwk_fc = arguments.nwk_fc
    mac_cnt = arguments.mac_cnt
    nwk_cnt = arguments.nwk_cnt
    aps_cnt = arguments.aps_cnt
    zcl_cnt = arguments.zcl_cnt

    # Create the packet
    p = ZCLOnOffToggle(nwk_src, nwk_dst, pan_id, aux_mac_addr, nwk_fc, dst_endpoint, mac_cnt, nwk_cnt, aps_cnt, zcl_cnt)
    
    # Create a Pcap writer object
    pcap_writer = PcapWriter(pcap_path, append=append)

    # If a key is provided, encrypt the packet, else provided unencrypted packet
    if key == None:
        pcap_writer.write(p.unecnrypted_packet)
    else:
        pcap_writer.write(p.nwk_encrypted_packet(bytes.fromhex(key)))

    # Close the Pcap writer
    pcap_writer.close()