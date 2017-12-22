import itertools
import random

# dhcp https://www.ietf.org/rfc/rfc2131.txt
# dhcp options https://www.ietf.org/rfc/rfc2132.txt

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
    ('CHADDR', 16)
]

_MAGIC_COOKIE = [0x63, 0x82, 0x53, 0x63]

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
_END_OPTION = [0xff]


class DHCPDiscover(object):

    def __init__(self, client_mac):
        self.headers = {
            'OP': [0x01],
            'HTYPE': [0x01],
            'HLEN': [0x06],
            'HOPS': [0x00],
            'XID': [random.randint(0, 255) for _ in range(4)],
            'SECS': [0x00, 0x00],
            'FLAGS': [0x80, 0x00],
            'CIADDR': [0x00, 0x00, 0x00, 0x00],
            'YIADDR': [0x00, 0x00, 0x00, 0x00],
            'SIADDR': [0x00, 0x00, 0x00, 0x00],
            'GIADDR': [0x00, 0x00, 0x00, 0x00],
            'CHADDR': client_mac + [0x00] * 10
        }
        self.dhcp_options = {
            'MESSAGE_TYPE': [0x35, 0x01, 0x01],
            'CLIENT_IDENTIFIER': [0x3d, 0x06] + client_mac,
            'PARAMETER_REQUEST_LIST': [0x37, 0x03, 0x03, 0x01, 0x06]
        }

    def as_bytes(self):
        header_bytes = list(itertools.chain.from_iterable(
            self.headers[name] for name, _ in _HEADER_VALUES))
        dhcp_options_bytes = []
        for name, value in self.dhcp_options.items():
            code = _DHCP_OPTIONS_BY_NAME[name]
            length = len(value)
            dhcp_options_bytes += [code, length] + value
        return header_bytes + _MAGIC_COOKIE + dhcp_options_bytes + _END_OPTION


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
        dhcp_options_str = packet_str.split(bytes(_MAGIC_COOKIE), 1)[1][:-1]
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
