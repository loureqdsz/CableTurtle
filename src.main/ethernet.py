import socket
import struct
import textwrap
import signal
import os
import sys
from tcp import TCP
from udp import UDP


def main():
    host = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    conn.bind((host, 0))
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Parte definicao estatistica
    percentIpv4 = 0
    percentIpv6 = 0
    percentIcmp = 0
    percentTcp = 0
    percentUdp = 0
    percentHttp = 0
    percentIcmp6 = 0
    percentTotal = 0


    def signal_handler ():
        exit_handler(percentIpv4, percentIpv6, percentIcmp, percentTcp, percentUdp, percentHttp, percentIcmp6, percentTotal)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler())
    print('\n-------------- Pressione CRTL + C para Exibir Estatisticas:\n')

    while True:
        percentTotal = percentTotal + 1

        raw_data, addr = conn.recvfrom(65535)
        mac_destino, mac_fonte, tipo_protocolo_ethernet, dados = ethernet_frame(raw_data)

        print('\nEthernet II: ')
        print('___MAC Destino: {}, \n___MAC Source: {},\n ___Protocolo: {}'.format(mac_destino,
                                                                                   mac_fonte,
                                                                                   tipo_protocolo_ethernet))

        if tipo_protocolo_ethernet == 43200:  # IPv4
            percentIpv4 = percentIpv4 + 1

            (version_ip, hlen_ip, ttl_ip, proto_ip, origem, target, dados_transporte) = ipv_4(dados)
            print('___IPv4:')
            print('______Versao: {},\n ______HLength: {},\n ______TTL: {},\n ______Protocolo: {}'.format(version_ip,
                                                                                                         hlen_ip,
                                                                                                         ttl_ip,
                                                                                                         proto_ip))
            print('______Origem: {},\n ______Destino: {}'.format(origem, target))

            # ICMP
            if proto_ip == 1:
                percentIcmp = percentIcmp + 1

                tipo, codigo, checksum, dados_aplicacao = icmp(dados_transporte)
                print('___ICMP:')
                print('______Tipo: {},\n ______Codigo: {},\n ______Checksum: {},'.format(tipo, codigo, checksum))
                print('______ICMP Data:')
                print(format_multi_line('_________', dados_aplicacao))


            # UDP
            # elif proto_ip == 17:
            elif proto_ip == 108:
                percentUdp = percentUdp + 1

                udp = UDP(dados_transporte)
                print('___UDP Segment:')
                print('______Porta Fonte: {},\n ______Porta Destino: {}, \n______Tamanho: {}'.format(udp.src_port,
                                                                                                     udp.dest_port,
                                                                                                     udp.size))

            # TCP
            elif proto_ip == 6:
                percentTcp = percentTcp + 1

                tcp = TCP(dados_transporte)
                print('___TCP:')
                print('______Porta Origem: {}, \n______Porta Destino: {}'.format(tcp.origem,
                                                                                 tcp.destino))
                print('______Sequence: {}, \n______Acknowledgment: {}'.format(tcp.seq,
                                                                              tcp.acknowledgment))
                print('______Flags:')
                print('_________RST: {}, \n_________SYN: {}, \n_________FIN:{}'.format(tcp.flag_rst,
                                                                                       tcp.flag_syn,
                                                                                       tcp.flag_fin))
                print('_________ACK: {}, \n_________PSH: {}'.format(tcp.flag_ack, tcp.flag_psh))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.origem == 80 or tcp.destino == 80:
                        percentHttp = percentHttp + 1

                        try:
                            print('______HTTP:')
                            http_decode = tcp.data.decode('utf-8')
                            dados_http = str(http_decode) \
                                .split('\n')
                            for line in dados_http:
                                print('_________' + str(line))
                        except:
                            print(format_multi_line('_________', tcp.data))
                    else:
                        print('______TCP:')
                        print(format_multi_line('_________', tcp.data))


            # Other IPv4
            else:
                print('___Dump de dados nao identificados:')
                print(format_multi_line('______', dados_transporte))

        # 86DD (ipv6)
        if tipo_protocolo_ethernet == 34525:
            percentIpv6 = percentIpv6 + 1

            version_trafic, tamanho_payload, proximo_protocolo, hop_limit, endereco_origem, endereco_destino = struct.unpack(
                "!IHBB16s16s", dados[:40])
            proximos_dados = dados[40:]
            print('___IPv6:')
            print('______Versao: {},'
                  '\n ______Tamanho Payload: {},'
                  '\n ______Proximo Cabecalho: {},'
                  '\n ______Hop Limit: {},'
                  '\n ______Endereco Origem: {},'
                  '\n ______Endereco Destino: {}'.format(version_trafic >> 28, tamanho_payload, proximo_protocolo,
                                                         hop_limit,
                                                         endereco_origem, endereco_destino))

            if proximo_protocolo == 58: ##ICMPv6
                percentIcmp6 = percentIcmp6 + 1
                tipo, codigo, checksum, resto = struct.unpack("!BBHI", proximos_dados)
                print('______ICMPv6'
                      '\n _________Tipo: {},'
                      '\n _________Codigo: {},'
                      '\n _________Checksum: {},'
                      '\n _________ICMP Data: {}'.format(tipo, codigo, checksum, resto))

        if tipo_protocolo_ethernet == 2054:
            p1 = dados[:8]
            p2 = dados[8:28]
            tipo_hardware, tipo_protocolo, tamanho_endereco_hardware, \
            tamanho_endereco_protocolo, opcode = struct.unpack("!HHBBH",
                                                               p1)
            source_mac, source_prot_addr, target_mac, target_prot_addr = struct.unpack("!6s4s6s4s", p2)

            print('___ARP')
            print('______MAC Origem: {},'
                  '\n______ MAC Destino: {}'.format(map_mac(source_mac), map_mac(target_mac)))

        else:
            print('Dump de dados nao identificados:')
            print(format_multi_line('___', dados))


def ethernet_frame(data):
    destination_mac, source_mac, type_data = struct.unpack('!6s6sH', data[:14])

    return map_mac(destination_mac), map_mac(source_mac), socket.htons(type_data), data[14:]


def map_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv_4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    src = '.'.join(map(str, src))
    target = '.'.join(map(str, target))
    dados_ipv4 = data[header_length:]

    return version, header_length, ttl, proto, src, target, dados_ipv4


def icmp(dados):
    tipo, codigo, checksum = struct.unpack('!BBH', dados[:4])

    return tipo, codigo, checksum, dados[4:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def exit_handler(ipv4Qnt, ipv6Qnt, icmpQnt, tcpQnt, udpQnt, httpQnt, icmp6Qnt, total):
    if total == 0:
        total = 1

    print('----Sessão de Estatistica: ')
    print('------ Porcentagem Ipv4:  {value:.2f} %'.format(value=((ipv4Qnt * 100)/total)))
    print('------ Porcentagem Ipv6:  {value:.2f} %'.format(value=((ipv6Qnt * 100)/total)))
    print('------ Porcentagem Icmp:  {value:.2f} %'.format(value=((icmpQnt * 100)/total)))
    print('------ Porcentagem Tcp:   {value:.2f} %'.format(value=((tcpQnt * 100)/total)))
    print('------ Porcentagem Udp:   {value:.2f} %'.format(value=((udpQnt * 100)/total)))
    print('------ Porcentagem Http:  {value:.2f} %'.format(value=((httpQnt * 100)/total)))
    print('------ Porcentagem Icmp6: {value:.2f} %'.format(value=((icmp6Qnt * 100)/total)))
    print('------ Quantidade de Requisições feitas Ethernet II = {}'.format(total))

main()
