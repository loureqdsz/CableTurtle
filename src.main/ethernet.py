import socket
import struct


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
        print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, source_mac, protocol_type))


# Unpack ETHERNET
def ethernet_frame(data):
    destination_mac, source_mac, type_data = struct.unpack('! 6s 6s H', data[:14])

    return _get_mac_addr(destination_mac), _get_mac_addr(source_mac), socket.htons(type_data), data[:14]


# tranform mac into readable mac address (ex: param -> 271364871236487 return -> AA:BB:CC:DD
def _get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


main()
