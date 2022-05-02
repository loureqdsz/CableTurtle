import socket
import struct

from general import *
from ethernet import Ethernet
from ipv4 import IPv4
from icmp import ICMP
from tcp import TCP
from udp import UDP
from http import HTTP

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
    host = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    conn.bind((host, 0))
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:

        raw_data, addr = conn.recvfrom(65535)
        mac_destino, mac_fonte, tipo_protocolo, dados = ethernet_frame(raw_data)

        print('\nEthernet II: ')
        print('___MAC Destino: {}, MAC Source: {}, Protocolo: {}'.format(mac_destino, mac_fonte, tipo_protocolo))

        if tipo_protocolo == 8:  # IPv4
            (version_ip, hlen_ip, ttl_ip, proto_ip, src, target, dados_transporte) = ipv_4(dados)
            print('___IPv4:')
            print('______Version: {}, Header Length: {}, ttl_ip: {},'.format(version_ip, hlen_ip, ttl_ip))
            print('______Protocol: {}, Source: {}, Target: {}'.format(proto_ip, src, target))

            # ICMP
            if proto_ip == 1:
                icmp = ICMP(dados_transporte)
                print('___ICMP Packet:')
                print('______Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print('______ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif proto_ip == 6:
                tcp = TCP(dados_transporte)
                print('___TCP Segment:')
                print('______Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print('______Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print('______Flags:')
                print('_________URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print('_________RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print('______HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print('______TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif proto_ip == 17:
                udp = UDP(dados_transporte)
                print('___UDP Segment:')
                print('______Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port,
                                                                                       udp.size))

            # Other IPv4
            else:
                print('___Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, dados_transporte))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, dados))


def ethernet_frame(data):
    destination_mac, source_mac, type_data = struct.unpack('! 6s 6s H', data[:14])

    return map_mac(destination_mac), map_mac(source_mac), socket.htons(type_data), data[14:]


def map_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv_4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src = '.'.join(map(str, src))
    target = '.'.join(map(str, target))
    dados_ipv4 = data[header_length:]

    return version, header_length, ttl, proto, src, target, dados_ipv4


main()
