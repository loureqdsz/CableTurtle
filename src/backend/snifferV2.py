#!/usr/bin/python 
import socket, sys
from struct import *
 
#Converter uma sequencia de caracteres de 6 caracteres do endereco ethernet em uma sequencia hexadecimal separada do tablao de instrumentos
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
#crie um socket bruto do tipo AF_PACKET (isto é basicamente o nivel do pacote)
#define ETH_P_ALL 0x0003 / * Todos os pacotes (tenha cuidado !!!) * /
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error as msg:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
 
# receber um pacote
while True:
    packet = s.recvfrom(65565)
     
    #corda de pacotes da tupla
    packet = packet[0]
     
    #Pare o cabecalho etherne
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print ('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
 
    #Parse pacotes IP, IP Protocolo numero = 8
    if eth_protocol == 8 :
        #Parse cabecalho IP
        #pegue os primeiros 20 caracteres para o cabecalho ip
        ip_header = packet[eth_length:20+eth_length]
         
        #agora descompactos :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
 
        print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
 
        #Protocolo TCP
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
 
            #agora descompactos :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)
             
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
             
            print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
             
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
             
            #obter dados do pacote
            data = packet[h_size:]
             
            print ('Data : ' + data)
 
        #Pacotes ICMP
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]
 
            #agora descompactos :)
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            print ('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))
             
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            #obter dados do pacote
            data = packet[h_size:]
             
            print ('Data : ' + data)
 
        #UDP pacotes
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            #agora descompactos :)
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
             
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
             
            #obter dados do pacote
            data = packet[h_size:]
             
            print ('Data : ' + data)
 
        #algum outro pacote IP como IGMP
        else :
            print ('Protocol other than TCP/UDP/ICMP')
             
        print