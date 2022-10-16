
from copy import deepcopy
from scapy.all import rdpcap, raw
from os import path
import yaml

import arp, icmp

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

empty_ipv4_senders = {'node': None,
                      'number_of_sent_packets': None}

# Layer 3 loader
with open("Protocols\\l2\\ETH.txt") as f, open("Protocols\\l2\\SAP.txt") as g, open("Protocols\\l2\\PID.txt") as h:
    ETH = yaml.load(f.read(), Loader=yaml.SafeLoader)
    SAP = yaml.load(g.read(), Loader=yaml.SafeLoader)
    PID = yaml.load(h.read(), Loader=yaml.SafeLoader)

with open("Protocols\\l3\\PROTOCOL.txt") as f, open("Protocols\\l3\\ARP_OPCODE.txt") as g:
    PROTOCOL = yaml.load(f.read(), Loader=yaml.SafeLoader)
    ARP_OPCODE = yaml.load(g.read(), Loader=yaml.SafeLoader)

with open("Protocols\\l4\\APP_PROTOCOL.txt") as f:
    APP_PROTOCOL = yaml.load(f.read(), Loader=yaml.SafeLoader)


def mac_builder(mac):
    mac_formatted = ""
    for i in range(6):
        mac_formatted += mac[:2].upper()
        mac = mac[2:]
        if len(mac):
            mac_formatted += ":"
    return mac_formatted


def hex_dump(frame):
    formatted_hex = ""
    i = 0
    while i + 2 <= len(frame):
        formatted_hex += "{}".format((frame[i:i + 2]))
        i += 2
        if not i % 32:
            formatted_hex += "\n"
        else:
            if (i + 2 > len(frame)):
                formatted_hex += "\n"
            else:
                formatted_hex += " "
    return formatted_hex


def ipv4_builder(ip_hex):
    ipv4 = ''
    for i in range(4):
        ipv4 += str(int(ip_hex[:1].hex(), 16))
        ip_hex = ip_hex[1:]
        if len(ip_hex):
            ipv4 += "."
    return ipv4


def ipv6_builder(ip_hex):
    ipv6 = ''
    check = 0
    for i in range(8):
        tmp = str((hex(int(ip_hex[:2].hex(), 16))))[2:]
        ip_hex = ip_hex[2:]
        if tmp != "0":
            check = 0
            ipv6 += tmp
        else:
            check += 1
        if len(ip_hex) and check < 2:
            ipv6 += ":"
    return ipv6


def ip_and_procotol_setter(pack, frame_b):
    match pack['ether_type']:
        case "IPv4":
            pack['protocol'] = PROTOCOL[frame_b[23:24].hex().upper()]
            pack['src_ip'] = ipv4_builder(frame_b[26:30])
            pack['dst_ip'] = ipv4_builder(frame_b[30:34])
        case "IPv6":
            pack['protocol'] = PROTOCOL[frame_b[20:21].hex().upper()]
            pack['src_ip'] = ipv6_builder(frame_b[22:38])
            pack['dst_ip'] = ipv6_builder(frame_b[38:54])
        case "ARP":
            pack['arp_opcode'] = ARP_OPCODE[frame_b[20:22].hex().upper()]
            pack['src_ip'] = ipv4_builder(frame_b[28:32])
            pack['dst_ip'] = ipv4_builder(frame_b[38:42])


# Parser formatter from internet
def str_presenter(dumper, data):
    if len(data.splitlines()) > 1:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


yaml.add_representer(str, str_presenter)

if __name__ == '__main__':
    prot = [value for key, value in APP_PROTOCOL.items()] + ["ICMP", "ARP"]
    flag = None
    file = None
    while True:
        inp = input("Pre klasicku analyzu zadaj iba nazov suboru \"*.pcap\", pre analyzu komunikacie zadaj \"-p ["
                    "TCP, UDP, ARP a ICMP]\" a nazov suboru \"*.pcap\":")
        if inp.split(" ")[0].__eq__("-p"):
            flag = inp.split(" ")[1].upper()
            if flag not in prot:
                print("Invalid protocol!")
                continue
            if path.exists("vzorky_pcap_na_analyzu\\" + inp.split(" ")[2]):
                file = rdpcap("vzorky_pcap_na_analyzu\\" + inp.split(" ")[2])
                break
        else:
            if path.exists("vzorky_pcap_na_analyzu\\" + inp.split(" ")[0]):
                flag = None
                file = rdpcap("vzorky_pcap_na_analyzu\\" + inp.split(" ")[0])
                break
        print("Invalid input!")
        # pcap_file_name = input("Write pcap file name with .pcap: ")
    # file = rdpcap("vzorky_pcap_na_analyzu\\" + pcap_file_name)
    # file = rdpcap("vzorky_pcap_na_analyzu\\trace-27.pcap")
    counter = 1
    task = deepcopy(empty_yaml)
    task['name'] = "PKS2022/23"
    # task['pcap_name'] = pcap_file_name
    task['pcap_name'] = "eth-3.pcap"
    ipv4_sender = {}

    for frame in file:
        frame_bytes = raw(frame)
        pck = deepcopy(empty_pck)

        pck['frame_number'] = counter
        counter += 1

        pck['len_frame_pcap'] = len(frame_bytes)

        if int(pck['len_frame_pcap'] + 4 < 64):
            pck['len_frame_medium'] = 64
        else:
            pck['len_frame_medium'] = 4 + int(pck['len_frame_pcap'])

        pck['hexa_frame'] = hex_dump(frame_bytes.hex())

        # ISL header
        if frame_bytes[0:6].hex() == "01000c000000":
            frame_bytes = frame_bytes[26:]

        pck['dst_mac'] = mac_builder(frame_bytes[0:6].hex())
        pck['src_mac'] = mac_builder(frame_bytes[6:12].hex())

        if int(frame_bytes[12:14].hex(), 16) > 1500 or int(frame_bytes[12:14].hex(), 16) == 1536:
            pck['frame_type'] = "ETHERNET II"
            pck['ether_type'] = ETH.get(frame_bytes[12:14].hex().upper(), "Unknown")
            ip_and_procotol_setter(pck, frame_bytes)
            if pck['ether_type'] == "IPv4":
                ipv4_sender[pck['src_ip']] = ipv4_sender.get(pck['src_ip'], 0) + 1
                if pck['protocol'] in ("TCP", "UDP"):
                    ip_header_length = int(frame_bytes[14:15].hex()[1], 16) * 4
                    pck['src_port'] = int(frame_bytes[ip_header_length + 14: ip_header_length + 16].hex(), 16)
                    pck['dst_port'] = int(frame_bytes[ip_header_length + 16: ip_header_length + 18].hex(), 16)
                    pck['app_protocol'] = APP_PROTOCOL.get((str(pck['src_port'])),
                                                           APP_PROTOCOL.get((str(pck['dst_port']))))
                    if pck['app_protocol'] is None:
                        pck.pop('app_protocol')
        else:
            if frame_bytes[14:16].hex().upper() == "FFFF":
                pck['frame_type'] = "IEEE 802.3 RAW"
            elif frame_bytes[14:16].hex().upper() == "AAAA":
                pck['frame_type'] = "IEEE 802.3 LLC & SNAP"
                pck['pid'] = PID[frame_bytes[20:22].hex().upper()]
            else:
                pck['frame_type'] = "IEEE 802.3 LLC"
                pck['sap'] = SAP[frame_bytes[14:15].hex().upper()]
        task['packets'].append(pck)

    ipv4_senders = []
    for sender in ipv4_sender:
        ipv4_senders.append({'node': sender, 'number_of_sent_packets': ipv4_sender[sender]})
    task['ipv4_senders'] = ipv4_senders
    task['max_send_packets_by'] = [key for key, value in ipv4_sender.items() if value == max(ipv4_sender.values())]

    if flag is not None:
        match flag:
            case "ARP":
                arp.main(task)
            case "ICMP":
                icmp.main(task)
    with open("ymal_output\\ano.yaml", "w") as file:
        yaml.dump(task, file, sort_keys=False)
