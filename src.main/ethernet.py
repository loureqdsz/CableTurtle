import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


# https://www.youtube.com/watch?v=dM9grWOdTBI&ab_channel=thenewboston
# aqui tem desenvolvido até a parte 3, mas da pra ir adiante


def main():
    host = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    conn.bind((host, 0))
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, source_mac, protocol_type, data = ethernet_frame(raw_data)
        print('\nEthernet Frame: ')
        print(TAB_1 + 'Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, source_mac, protocol_type))

        # 8 Ipv4
        if protocol_type == 8:
            (version, header_length, ttl, proto, src, target, data) = unpack_ipv4(data)
            print(TAB_1 + 'Ipv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICPM Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # TCP
            if proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                 flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(
                    TAB_2 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh,
                                                                                          flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))

            # UDP
            if proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segmnet: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print('Data: ')
            print(format_multi_line(DATA_TAB_1, data))


# Unpack ETHERNET
def ethernet_frame(data):
    destination_mac, source_mac, type_data = struct.unpack('! 6s 6s H', data[:14])

    return _get_mac_addr(destination_mac), _get_mac_addr(source_mac), socket.htons(type_data), data[:14]


# tranform mac into readable mac address (ex: param -> 271364871236487 return -> AA:BB:CC:DD
def _get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def unpack_ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, format_ipv4(src), format_ipv4(target), data[header_length:]


def format_ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icpm_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icpm_type, code, checksum, data[4:]


def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 5
    flag_psh = (offset_reserved_flags & 8) >> 5
    flag_rst = (offset_reserved_flags & 4) >> 5
    flag_syn = (offset_reserved_flags & 2) >> 5
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, \
           flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2X H', data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size = len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size = 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
