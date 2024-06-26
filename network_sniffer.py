import binascii
import socket
import struct

# Function to convert a hexdump to a readable format
def hexdump_to_readable(hexdump):
    # Remove any whitespace from the hexdump
    hexdump = hexdump.replace(" ", "")

    # Convert the hexdump to a byte array
    byte_array = binascii.unhexlify(hexdump)

    # Parse the Ethernet header
    eth_dst_mac = byte_array[:6]  # Destination MAC address
    eth_src_mac = byte_array[6:12]  # Source MAC address
    eth_type = byte_array[12:14]  # Ethernet type (e.g. 0x0800 for IPv4)

    # Parse the IPv4 header
    ip_version = byte_array[14] >> 4  # IP version (e.g. 4 for IPv4)
    ip_ihl = byte_array[14] & 0x0F  # IP header length
    ip_dscp = byte_array[15] >> 2  # Differentiated services code point
    ip_ecn = byte_array[15] & 0x03  # Explicit congestion notification
    ip_total_len = int.from_bytes(byte_array[16:18], byteorder='big')  # Total length of the packet
    ip_identification = int.from_bytes(byte_array[18:20], byteorder='big')  # Identification number
    ip_flags = byte_array[20] >> 5  # Flags (e.g. 0x04 for don't fragment)
    ip_frag_offset = int.from_bytes(byte_array[20:22], byteorder='big')  # Fragment offset
    ip_ttl = byte_array[22]  # Time to live
    ip_protocol = byte_array[23]  # Protocol (e.g. 6 for TCP)
    ip_checksum = int.from_bytes(byte_array[24:26], byteorder='big')  # Header checksum
    ip_src_addr = byte_array[26:30]  # Source IP address
    ip_dst_addr = byte_array[30:34]  # Destination IP address

    # Parse the TCP header
    tcp_src_port = int.from_bytes(byte_array[34:36], byteorder='big')  # Source port
    tcp_dst_port = int.from_bytes(byte_array[36:38], byteorder='big')  # Destination port
    tcp_seq_num = int.from_bytes(byte_array[38:42], byteorder='big')  # Sequence number
    tcp_ack_num = int.from_bytes(byte_array[42:46], byteorder='big')  # Acknowledgment number
    tcp_data_offset = byte_array[46] >> 4  # Data offset
    tcp_reserved = byte_array[46] & 0x0F  # Reserved bits
    tcp_flags = byte_array[47]  # Flags (e.g. 0x018 for SYN and ACK)
    tcp_window = int.from_bytes(byte_array[48:50], byteorder='big')  # Window size
    tcp_checksum = int.from_bytes(byte_array[50:52], byteorder='big')  # Checksum
    tcp_urg_ptr = int.from_bytes(byte_array[52:54], byteorder='big')  # Urgent pointer

    # Format the output
    output = f"Packet: {ip_src_addr.hex().upper()}:{tcp_src_port} -> {ip_dst_addr.hex().upper()}:{tcp_dst_port} - "

    # Get the TCP flags
    tcp_flags_str = ""
    if tcp_flags & 0x01:
        tcp_flags_str += "FIN, "
    if tcp_flags & 0x02:
        tcp_flags_str += "SYN, "
    if tcp_flags & 0x04:
        tcp_flags_str += "RST, "
    if tcp_flags & 0x08:
        tcp_flags_str += "PSH, "
    if tcp_flags & 0x10:
        tcp_flags_str += "ACK, "
    if tcp_flags & 0x20:
        tcp_flags_str += "URG, "
    if tcp_flags_str:
        tcp_flags_str = tcp_flags_str[:-2]  # Remove trailing comma and space

    # Get the packet data
    packet_data = byte_array[54:]
    if packet_data:
        packet_data_str = packet_data.decode('utf-8', errors='replace')
    else:
        packet_data_str = ""

    # Add the TCP flags and packet data to the output
    output += f"TCP {tcp_flags_str} - {packet_data_str}"

    return output

class Packet:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, payload):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_portself.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload

    def __str__(self):
        return f"Packet: {self.src_ip} -> {self.dst_ip} ({self.src_port} -> {self.dst_port}) - {self.payload}"

    def get_tcp_header(self):
        # set the TCP header
        tcp_header = struct.pack("!HHLLBBHHH",
                                 self.src_port,  # source port
                                 self.dst_port,     # destination port
                                 0,     # sequence
                                 0,     # acknowledgement number
                                 5,     # data offset (5*4)                                 0,     # reserved
                                 0x018,     # flags (SYN, ACK)
                                 1024,     # window
                                 0,     # checksum
                                 0)     # urgent pointer

        return tcp_header

    def get_ip_header(self):
        # set the IP header
        ip_header = struct.pack("!BBHHHBBH4s4s",
                                 0x45,     # version and header length
                                 0,     # differentiated services
                                 0,     # total length
                                 0,     # identification
                                 0,     # flags and fragment offset
                                 0,     # time to live
                                 6,     # protocol (TCP)
                                 0,     # header checksum
                                 self.src_ip,     # source IP
                                 self.dst_ip)     # destination IP

        return ip_header

    def get_packet(self):
        # create the packet
        packet = self.get_ip_header() + self.get_tcp_header() + self.payload
        return packet

def send_packet(packet, interface):
    # create a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.bind((interface, 0))

    # send the packet
    sock.sendto(packet, (packet.dst_ip, 0))

import netifaces as ni

def get_interface_ip(interface):
    return ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

def sniff_packets(interface, count):
    # get the IP address of the interface
    interface_ip = get_interface_ip(interface)

    # create a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.bind((interface_ip, 0))

    # sniff packets
    for i in range(count):
        packet_data, addr = sock.recvfrom(65565)
        hexdump = binascii.hexlify(packet_data).decode('utf-8')
        print(hexdump_to_readable(hexdump))
  # function hexdump_to_readable translates the payload which is in hexdacimal into readable text using the ascii encoding

# sniff 10 packets on interface usb0
sniff_packets("usb0", 10) # --> interface of your  pc and the count or the number of packets u wish to send
