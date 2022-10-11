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
       '0806': 'ARP',
       '86DD': 'IPv6',
       '88CC': 'LLDP',
       '9000': 'ECTP'}

SAP = {'42': 'STP',
       'AA': 'SNAP',
       'E0': 'IPX',
       'F0': 'NETBIOS'}

PID = {'010B': 'PVSTP+',
       '2000': 'CDP',
       '2004': 'DTP',
       '809B': 'AppleTalk'}

def mac_builder(mac):
    mac_formatted = ""
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
            formatted_hex += "\n"
        else:
            formatted_hex += " "

    return formatted_hex


if __name__ == '__main__':
    file = rdpcap("vzorky_pcap_na_analyzu\\eth-6.pcap")
    counter = int(1)
    task = copy.deepcopy(empty_yaml)
    task['name'] = 'PKS2022/23'
    task['pcap_name'] = 'trace-23.pcap'
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

        # ISL header
        if frame_bytes[:6].hex() == "01000c000000":
            frame_bytes = frame_bytes[26:]

        pck['dst_mac'] = mac_builder(frame_bytes[:6].hex())
        frame_bytes = frame_bytes[6:]
        pck['src_mac'] = mac_builder(frame_bytes[:6].hex())
        frame_bytes = frame_bytes[6:]
        if int(frame_bytes[:2].hex(), 16) > 1500 or int(frame_bytes[:2].hex(), 16) == 1536:
            pck['frame_type'] = 'ETHERNET II'
            # pck['ether_type'] = ETH[frame_bytes[:2].hex().upper()]
        else:
            if frame_bytes[2:4].hex().upper() == 'FFFF':
                pck['frame_type'] = 'IEEE 802.3 RAW'
            elif frame_bytes[2:4].hex().upper() == 'AAAA':
                pck['frame_type'] = 'IEEE 802.3 LLC & SNAP'
                a = frame_bytes[8:10].hex().upper()
                pck['pid'] = PID[a]
            else:
                pck['frame_type'] = 'IEEE 802.3 LLC'
                pck['sap'] = SAP[frame_bytes[2:3].hex().upper()]
        task['packets'].append(pck)

    with open("ano.yaml", "w") as file:
        dump(task, file,sort_keys=False)
