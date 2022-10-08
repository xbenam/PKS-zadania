import copy

from scapy.all import rdpcap, raw
from yaml import dump

empty_pck = {'frame_number': None,
             'len_frame_pcap': None,
             'len_frame_medium': None,
             'frame_type': None,
             'src_mac': None,
             'dst_mac': None,
             'hexa_frame': None}

empty_yaml = {'name': None,
              'pcap_name': None,
              'packets': []}

ETH = {'0800': 'IPv4',
       '86DD': 'IPv6',
       '0806': 'ARP',
       '88CC': 'LLDP'}

SAP = {'42': 'STP',
       'E0': 'IPX',
       'AA': 'SNAP'}

PID = {'23': 'CDT'

}

def mac_builder(mac):
    mac_formatted = ''
    for i in range(6):
        mac_formatted += mac[:2].upper()
        mac = mac[2:]
        if len(mac):
            mac_formatted += ':'
    return mac_formatted


def hex_dump(frame):
    formatted_hex = ""
    i = 0
    while i + 2 <= len(frame):
        formatted_hex += frame[i:i + 2].upper()
        i += 2
        if not i % 32:
            formatted_hex += '\n'
        else:
            formatted_hex += ' '

    return formatted_hex


if __name__ == '__main__':
    file = rdpcap("eth-3.pcap")
    counter = int(0)
    task = copy.deepcopy(empty_yaml)
    task['name'] = 'PKS2022/23'
    task['pcap_name'] = 'eth-3.pcap'
    for frame in file:
        frame_bytes = raw(frame)
        pck = copy.deepcopy(empty_pck)

        pck['frame_number'] = counter
        counter += 1

        pck['len_frame_pcap'] = len(frame_bytes)

        if int(pck['len_frame_pcap'] + 4 < 64):
            pck['len_frame_medium'] = 64
        else:
            pck['len_frame_medium'] = 4 + int(pck['len_frame_pcap'])

        pck['hexa_frame'] = hex_dump(frame_bytes.hex())

        pck['dst_mac'] = mac_builder(frame_bytes[:6].hex())
        frame_bytes = frame_bytes[6:]
        pck['src_mac'] = mac_builder(frame_bytes[:6].hex())
        frame_bytes = frame_bytes[6:]
        if int(frame_bytes[:2].hex(), 16) > 1500 or int(frame_bytes[:2].hex(), 16) == 1536:
            pck['frame_type'] = 'ETHERNET II'
            # pck['ether_type'] = ETH[frame_bytes[:2].hex().upper()]
        else:
            if frame_bytes[:2].hex().upper() == 'ffff':
                pck['frame_type'] = 'IEEE 802.3 RAW'
            elif frame_bytes[:2].hex().upper() == 'aaaa':
                pck['frame_type'] = 'IEEE 802.3 LLC & SNAP'
            else:
                pck['frame_type'] = 'IEEE 802.3 LLC'
        task['packets'].append(pck)

    with open("ano.yaml", "w") as file:
        dump(task, file)
