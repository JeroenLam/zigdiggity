from scapy.all import PcapReader
from zigdiggity.radios.raspbee_radio import RaspbeeRadio
from zigdiggity.radios.observer_radio import ObserverRadio
import argparse
import time

# Define the argument parser
def parse_arguments():
    parser = argparse.ArgumentParser(description='Replay command argument parser.')
    parser.add_argument('-c', '--channel',      type=int, default=20, help='Channel (integer), default=20')
    parser.add_argument('-r', '--radio-path',   type=str, default='/dev/ttyS0', help='Radio path (string), default=/dev/ttys0')
    parser.add_argument('-f', '--pcap-path',    type=str, required=True, help='PCAP path (string), required')
    parser.add_argument('-t', '--time-delay',   type=int, default=1, help='Time delay (integer), default=1')

    args = parser.parse_args()
    return args

# Initiate the radio module
def init_raspbee_radio(radio_path: str, channel: int):
    hardwareradio = RaspbeeRadio(radio_path)
    hardwareradio.set_channel(channel)
    radio = ObserverRadio(hardwareradio)
    radio.set_channel(channel)
    return radio, hardwareradio


if __name__ == "__main__":
    # Parse the arguments
    arguments = parse_arguments()
    channel = arguments.channel
    radio_path = arguments.radio_path
    pcap_path = arguments.pcap_path
    time_delay = arguments.time_delay

    # Define the Raspbee radio in ZigDiggity
    [radio, hwradio] = init_raspbee_radio(radio_path, channel)

    # Open a pcap file
    pcap_reader = PcapReader(pcap_path)

    # Send all packets in the pcap file
    for packet in pcap_reader:
        print(packet.summary())
        radio.send_and_retry(packet)
        time.sleep(time_delay) 

    # Close the pcap file
    pcap_reader.close()