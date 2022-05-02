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
        dados_ethernet, addr = conn.recvfrom(65536)
        mac_destino, mac_fonte, tipo_protocolo, dados = ethernet_frame(dados_ethernet)
        print('\nEthernet Frame: ')
        print(TAB_1 + 'MAC Destino: {}, MAC Source: {}, Protocolo: {}'.format(mac_destino, mac_fonte, tipo_protocolo))

        # 8 Ipv4
        if tipo_protocolo == 8:
            (versao, hlen, ttl, protocolo, fonte, destino, dados) = ipv4(dados)
            print(TAB_1 + 'Ipv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(versao, hlen, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(protocolo, fonte, destino))

            # ICMP
            if protocolo == 1:
                icmp_type, code, checksum, dados = icmp(dados)
                print(TAB_1 + 'ICPM Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, dados))

            # TCP
            if protocolo == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                 flag_fin, dados) = tcp(dados)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(
                    TAB_2 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh,
                                                                                          flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, dados))

            # UDP
            if protocolo == 17:
                src_port, dest_port, length, dados = udp(dados)
                print(TAB_1 + 'UDP Segmnet: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line(DATA_TAB_2, dados))

        else:
            print('Data: ')
            print(format_multi_line(DATA_TAB_1, dados))


# Unpack ETHERNET
def ethernet_frame(data):
    destination_mac, source_mac, type_data = struct.unpack('! 6s 6s H', data[:14])

    return map_mac(destination_mac), map_mac(source_mac), socket.htons(type_data), data[:14]


# tranform mac into readable mac address (ex: param -> 271364871236487 return -> AA:BB:CC:DD
def map_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, map_ipv4(src), map_ipv4(target), data[header_length:]


def map_ipv4(addr):
    return '.'.join(map(str, addr))


def icmp(data):
    icpm_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icpm_type, code, checksum, data[4:]


def tcp(data):
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


def udp(data):
    src_port, dest_port, size = struct.unpack('! H H 2X H', data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size = len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size = 1
    return '/n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
