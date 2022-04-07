#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Programa scanner em python
# Para o sniffer usamos a biblioteca Pcapy, que é feita especialmente para isso
# Versão python usada: python 2.7
# A opção sniffer só captura pacotes TCP, UDP, e ICMP

from xml.dom import minidom as dom #biblioteca usada também para descobrir o ip externo
import socket
from struct import *
import datetime
import pcapy #biblioteca usada para o sniffer de rede
import sys
from os import system #biblioteca usada para algumas funções do programa
from scapy.all import * #biblioteca base do programa

def help():
   print("""
   ==============================================================================================================================================
   =		Scanner de rede em Python                                                                                                       =
   ==============================================================================================================================================
   =            by: Túlio Marcos                                                                                                                =
   ==============================================================================================================================================
   = Opções:                                                                                                                                    =
   = [-t] Utilizar o traceroute da scapy                                                                                                        =
   = EXEMPLO: python "arquivo.py" -t <ip>                                                                                                       =
   = [-q] Utilizar o traceroute d sistema    o                                                                                                  =
   = EXEMPLO: python "arquivo.py" -q <ip>                                                                                                       =
   = [-i] Ver o IP do link de internet                                                                                                          =
   = EXEMPLO: python "arquivo.py" -i                                                                                                            =
   = [-p] Utilizar o ping                                                                                                                       =
   = EXEMPLO: python "arquivo.py" -p <ip>                                                                                                       =
   = [-o] Descobrir o sistema operacional através do IP                                                                                         =
   = EXEMPLO: python "arquivo.py" -o <ip>                                                                                                       =
   = [-s] Sniffar a rede                                                                                                                        =
   = EXEMPLO: python "arquivo.py" -s                                                                                                            =
   ==============================================================================================================================================
   """)
if len(sys.argv) < 2:
   system('clear')
   print("ERRO!")
   print("Nenhum argumento foi passado. ")
   help()
   sys.exit()
elif sys.argv[1] == "-s": #sniffer de pacotes
   devices = pcapy.findalldevs()
   print(devices)
   print("Dispositivos disponiveis: ")
   for d in devices:
     print(d)
   dev = raw_input("Insira o nome do dispositivo que deseja sniffar: ")
   print("Sniffando o dispositivo " + dev)
   cap = pcapy.open_live(dev , 65536 , 1 , 0)
   while(1):
      (header, packet) = cap.next()
      parse_packet(packet) #DANDO ERRO (era pra pegar o pacote
def eth_addr (a):
   b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
   return b
def parse_packet (packet):
   eth_length = 14
   eth_header = packet[:eth_length]
   eth = unpack('!6s6sH' , eth_header)
   eth_protocol = socket.ntohs(eth[2])
   print('MAC destino: ' + eth_addr(packet[0:6]) + ' MAC fonte: ' + eth_addr(packet[6:12]) + ' Protocolo: ' + str(eth_protocol))
   if eth_protocol == 8:
       ip_header = packet[eth_length:20+eth_length]
       iph = unpack('!BBHHHBBH4s4s' , ip_header)
       version_ihl = iph[0]
       version = version_ihl >> 4
       ihl = version_ihl & 0xF
       iph_length = ihl * 4
       ttl = iph[5]
       protocol = iph[6]
       s_addr = socket.inet_ntoa(iph[8])
       d_addr = socket.inet_ntoa(iph[9])
       print('Versão: ' + str(version) + ' Tamanho do cabeçalho do IP: ' + str(ihl) + ' TTL: ' + str(ttl) + ' Protocolo: ' + str(protocol) + ' IP fonte: ' + str(s_addr) + ' IP       destino: ' + str(d_addr))
   if protocol == 6:
       t = iph_length + eth_length
       tcp_header = packet[t:t+20]
       tcph = unpack('!HHLLBBHHH' , tcp_header)
       source_port = tcph[0]
       dest_port = tcph[1]
       sequence = tcph[2]
       acknowledgement = tcph[3]
       doff_reserved = tcph[4]
       tcph_length = doff_reserved >> 4
       print('Porta fonte: ' +str(source_port) + ' Porta destino: ' + str(dest_port) + ' Número da sequência: ' + str(sequence) + 'Reconhecimento: ' + str(acknowledgement) + '     Tamanho cabeçalho TCP: ' + str(tcph_length))
       h_size = eth_length + iph_length + tcph_length * 4
       data_size = len(packet) - h_size
       data = packet[h_size:]
       print('Dados: ' + data)
   elif protocol == 1:
      u = iph_lenght + eth_length
      icmph_length = 4
      icmp_header = packet[u:u+4]
      icmph = unpack('!BBH' , icmp_header)
      icmp_type = icmph[0]
      code = icmph[1]
      checksum = icmph[2]
      print('Tipo: ' + str(icmp_type) + ' Código: ' + str(code) + ' Soma de verificação: ' + str(checksum))
      h_size = eth_length + iph_length + icmph_length
      data_size = len(packet) - h_size
      data = packet[h_size:]
      print('Dados: ' + data)
   elif protocol == 17:
      u = iph_length + eth_length
      udph_length = 8
      udp_header = packet[u:u+8]
      udph = unpack('!HHHH' , udp_header)
      source_port = udph[0]
      dest_port = udph[1]
      length = udph[2]
      checksum = udph[3]
      print('Porta fonte: ' + str(source_port) + ' Porta destino ' + str(dest_port) + ' Tamanho: ' + str(length) + ' Soma de verificação: ' + str(checksum))
      h_size = eth_length + iph_length + udph_length
      data_size = len(packet) - h_size
      data = packet[h_size:]
      print('Dados: ' + data)
   else:
      print('Nenhum pacote TCP/UDP/ICMP encontrado. ')
   if __name__ == "__main__":
     main(sys.argv)