import struct


# [(name, length)]
_HEADER_VALUES = [
    ('OP', 1),
    ('HTYPE', 1),
    ('HLEN', 1),
    ('HOPS', 1),
    ('XID', 4),
    ('SECS', 2),
    ('FLAGS', 2),
    ('CIADDR', 4),
    ('YIADDR', 4),
    ('SIADDR', 4),
    ('GIADDR', 4),
    ('CHADR', 16)
]

_MAGIC_COOKIE = struct.pack('!I', 0x63825363)

# [(code, name)]
_DHCP_OPTIONS = [
    (1, 'SUBNET_MASK'),
    (3, 'ROUTER'),
    (6, 'DNS_SERVERS'),
    (51, 'LEASE_TIME'),
    (53, 'MESSAGE_TYPE'),
    (54, 'DHCP_SERVER'),
    (55, 'PARAMETER_REQUEST_LIST'),
    (61, 'CLIENT_IDENTIFIER')
]
_DHCP_OPTIONS_BY_NAME = {name: code for code, name in _DHCP_OPTIONS}
_DHCP_OPTIONS_BY_CODE = {code: name for code, name in _DHCP_OPTIONS}


class DHCPOffer(object):

    def __init__(self, packet_bytes):
        self.header = self._read_header(packet_bytes)
        self.dhcp_options = self._read_dhcp_options(packet_bytes)

    @staticmethod
    def _read_header(packet_bytes):
        header_dict = {}
        position = 0
        for name, length in _HEADER_VALUES:
            header_dict[name] = packet_bytes[position:position+length]
            position += length
        return header_dict

    @staticmethod
    def _read_dhcp_options(packet_bytes):
        packet_str = bytes(packet_bytes)
        dhcp_options_str = packet_str.split(_MAGIC_COOKIE, 1)[1][:-1]
        dhcp_options_bytes = bytes(dhcp_options_str)
        dhcp_options_dict = {}
        dhcp_options_bytes_iter = iter(dhcp_options_bytes)
        for byte in dhcp_options_bytes_iter:
            length = next(dhcp_options_bytes_iter)
            data_bytes = [next(dhcp_options_bytes_iter)
                          for _ in range(length)]
            if byte in _DHCP_OPTIONS_BY_CODE:
                name = _DHCP_OPTIONS_BY_CODE[byte]
                dhcp_options_dict[name] = data_bytes
        return dhcp_options_dict
