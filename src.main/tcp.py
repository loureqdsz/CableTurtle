import struct


class TCP:

    def __init__(self, dados):
        (self.origem, self.destino, self.seq, self.acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', dados[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_fin = offset_reserved_flags & 1
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.data = dados[offset:]
