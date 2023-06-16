import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../../")
import argparse

from p_zcl_onoff_toggle import ZCLOnOffToggle
from packet_constructor.utility.pcap_processing import write_pcap_arr

# Parsing arguments 
def parse_arguments():
    parser = argparse.ArgumentParser(description='Parsing command parameters.')
    parser.add_argument('--key',            type=str, default=None, help='Network key (integer), default=None')
    parser.add_argument('--nwk-random',     type=lambda x: int(x, 16), default=0x0001, help='NWK address not in use by the network (integer), default=0x0001')
    parser.add_argument('--nwk-remote',     type=lambda x: int(x, 16), help='NWK address of remote (integer)')
    parser.add_argument('--nwk-bulb',       type=lambda x: int(x, 16), help='NWK address of bulb (integer)')
    parser.add_argument('--pan-id',         type=lambda x: int(x, 16), help='PAN ID of the network (integer)')
    parser.add_argument('--aux-mac-random', type=lambda x: int(x, 16), default=0x842e14fffe01f9f3, help='MAC address of device not in network (integer), default=0x842e14fffe01f9f3')
    parser.add_argument('--aux-mac-remote', type=lambda x: int(x, 16), help='MAC address of remote (integer)')
    parser.add_argument('--dst-endpoint',   type=int, default=1, help='Destination endpoint (integer), default=1')
    parser.add_argument('--nwk-fc',         type=int, default=0x80000000, help='NWK FC (integer), default=0x80000000')
    parser.add_argument('--mac-cnt',        type=int, default=10, help='MAC count (integer), default=10')
    parser.add_argument('--nwk-cnt',        type=int, default=10, help='NWK count (integer), default=10')
    parser.add_argument('--aps-cnt',        type=int, default=10, help='APS count (integer), default=10')
    parser.add_argument('--zcl-cnt',        type=int, default=10, help='ZCL count (integer), default=10')
    parser.add_argument('--amount',         type=int, default=10, help='Number of packets to generate for each experiment (integer), default=10')

    args = parser.parse_args()
    return args

# Create an array of packets with increasing frame counter and sequence numbers
def gen_packet_array(nwk_src: int, nwk_dst: int, pan_id: int, 
                     aux_mac_addr: int, nwk_fc: int, dst_endpoint: int,
                     mac_cnt: int, nwk_cnt: int, aps_cnt: int, zcl_cnt: int,
                     amount: int, key:str = None):
    """
        Creates an array of ZCL OnOff Toggle packets with the provided arguments. 
        The sequence numbers and framecounters will be incremented for each generated packet.

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
        amount (int): The number of packets to contrsuct.
    """
    # Create an empty array to store the packets
    packets = []

    # Create the requested amount of packets while incrementing the appropriate counters
    for idx in range(amount):
        p = ZCLOnOffToggle(nwk_src, nwk_dst, pan_id,
                           aux_mac_addr, (nwk_fc + idx) % 0x100000000 , dst_endpoint,
                           (mac_cnt + idx) % 0x100, (nwk_cnt + idx) % 0x100,
                           (aps_cnt + idx) % 0x100, (zcl_cnt + idx) % 0x100)
        if key == None:
            packets.append(p.unecnrypted_packet)
        else:
            packets.append(p.nwk_encrypted_packet(bytes.fromhex(key)))
    return packets


if __name__ == "__main__":
    # Parse user arguments
    arguments = parse_arguments()
    nwk_key = arguments.key
    nwk_random = arguments.nwk_random
    mac_random = arguments.aux_mac_random
    nwk_remote = arguments.nwk_remote
    mac_remote = arguments.aux_mac_remote
    nwk_bulb = arguments.nwk_bulb
    nwk_coord = 0x000
    pan_id = arguments.pan_id    
    dst_endpoint = arguments.dst_endpoint
    nwk_fc = arguments.nwk_fc
    mac_cnt = arguments.mac_cnt
    nwk_cnt = arguments.nwk_cnt
    aps_cnt = arguments.aps_cnt
    zcl_cnt = arguments.zcl_cnt
    amount = arguments.amount


    # Create packets first experiment (Not in network -> bulb)
    packets_ex1 = gen_packet_array(nwk_random, nwk_bulb, pan_id, mac_random, nwk_fc, dst_endpoint, mac_cnt, nwk_cnt, aps_cnt, zcl_cnt, amount, nwk_key)
    write_pcap_arr('ex1.pcap', packets_ex1)

    # Create packets second experiment (Not in network -> gateway)
    packets_ex2 = gen_packet_array(nwk_random, nwk_coord, pan_id, mac_random, nwk_fc + amount, dst_endpoint, mac_cnt + amount, nwk_cnt + amount, aps_cnt + amount, zcl_cnt + amount, amount, nwk_key)
    write_pcap_arr('ex2.pcap', packets_ex2)

    # Create packets third experiment (In network -> bulb)
    packets_ex3 = gen_packet_array(nwk_remote, nwk_bulb, pan_id, mac_remote, nwk_fc, dst_endpoint, mac_cnt, nwk_cnt, aps_cnt, zcl_cnt, amount, nwk_key)
    write_pcap_arr('ex3.pcap', packets_ex3)

    # Create packets fourth experiment (In network -> gateway)
    packets_ex4 = gen_packet_array(nwk_remote, nwk_coord, pan_id, mac_remote, nwk_fc + amount, dst_endpoint, mac_cnt + amount, nwk_cnt + amount, aps_cnt + amount, zcl_cnt + amount, amount, nwk_key)
    write_pcap_arr('ex4.pcap', packets_ex4)    