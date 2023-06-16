from scapy.all import PcapReader, PcapWriter ,Packet
from typing import List


def extract_pcap(input_file_path: str, index_arr: List[int] = None):
    """
    Opens the target pcap file and extracts the entries specified in the index array.

    Parameters:
    input_file_path (str): Path to pcap file.
    index_arr (List[int]): Array containing the entries which need to be extracted.
    """
    # Create a pcap reader
    pcap_reader = PcapReader(input_file_path)

    if index_arr == None:
        # Extract the given packets from the pcap and return packets in an array
        return [pcap_reader[i] for i in index_arr]
    else:
        ret_arr = []
        for packet in pcap_reader:
            ret_arr.append(packet)
        return ret_arr


def write_pcap_arr(output_file_path: str, packet_arr: List[Packet], append: bool = True):
    """
    Write an array of packets to a pcap file.

    Parameters:
    output_file_path (str): Path to pcap file.
    packet_arr (List[Packet]): Array containing packets to write to disk.
    append (bool): Append the packets if the output file already exists.
    """
    # Create a pcap writer
    pcap_writer = PcapWriter(output_file_path, append=append)

    # Write the packets to disk
    for packet in packet_arr:
        pcap_writer.write(packet)
    pcap_writer.close()