"""
author: Martin Beňa
consultant: Ing. Kristián Košťál, PhD.
date: 18.10.2022
"""
from copy import deepcopy
from os import path

import yaml
from scapy.all import rdpcap, raw

import arp
import icmp
import rest
import udp

# tento slovník používam ako predlohu ktorú kopírujem keď prechádzam prvou časťou zadania
empty_pck = {'frame_number': None,
             'len_frame_pcap': None,
             'len_frame_medium': None,
             'frame_type': None,
             'src_mac': None,
             'dst_mac': None,
             'hexa_frame': None}

# slovník ktorý v sebe bude mat všetky údaje, ktoré pôjdu do yaml súboru
empty_yaml = {'name': None,
              'pcap_name': None,
              'packets': []}

# slovnik pre
empty_ipv4_senders = {'node': None,
                      'number_of_sent_packets': None}

# Layer 2
with open("Protocols\\l2\\ETH.txt") as f, open("Protocols\\l2\\SAP.txt") as g, \
        open("Protocols\\l2\\PID.txt") as h, open("Protocols\\l2\\ARP_OPCODE.txt") as i:
    ETH = yaml.load(f.read(), Loader=yaml.SafeLoader)
    SAP = yaml.load(g.read(), Loader=yaml.SafeLoader)
    PID = yaml.load(h.read(), Loader=yaml.SafeLoader)
    ARP_OPCODE = yaml.load(i.read(), Loader=yaml.SafeLoader)

# Layer 3
with open("Protocols\\l3\\PROTOCOL.txt") as f:
    PROTOCOL = yaml.load(f.read(), Loader=yaml.SafeLoader)

# Layer 4
with open("Protocols\\l4\\APP_PROTOCOL.txt") as f:
    APP_PROTOCOL = yaml.load(f.read(), Loader=yaml.SafeLoader)


def mac_builder(mac):
    """
    Funkcia na upravenie mac adries na formát XX:XX:XX:XX:XX:XX
    :param mac: mac adresa vo formate stringu bez :
    :return: formátovaná mac adresa s :
    """
    mac_formatted = ""
    while len(mac) > 0:
        mac_formatted += mac[:2].upper()
        mac = mac[2:]
        if len(mac):
            mac_formatted += ":"
    return mac_formatted


def hex_dump(hex_data):
    """
    Funkcia na formátovanie hex časti dát do požadovaného tvaru podľa zadania
    :param hex_data: hex dáta v tvare stringu bez medzier
    :return: upravený tvar hex dát
    """
    formatted_hex = ""
    index = 0
    while index + 2 <= len(hex_data):
        formatted_hex += "{}".format((hex_data[index:index + 2]))
        index += 2
        if not index % 32:  # pridanie nového riadku na koniec kvôli yaml formátovaniu
            formatted_hex += "\n"
        else:
            if index + 2 > len(hex_data):  # posunutie na novy riadok po 16 bytoch
                formatted_hex += "\n"
            else:
                formatted_hex += " "  # medzera medzi bytmi
    return formatted_hex


def ipv4_builder(ip_hex):
    """
    Funkcia na upravenie ip adries na formát [0-255].[0-255].[0-255].[0-255]
    :param ip_hex: ip v hexadecimálnom  tvare bez bodiek
    :return: ip v desiatkovom tvare s bodkami
    """
    ipv4 = ''
    while len(ip_hex) > 0:
        ipv4 += str(int(ip_hex[:1].hex(), 16))
        ip_hex = ip_hex[1:]
        if len(ip_hex):
            ipv4 += "."
    return ipv4


def ipv6_builder(ip_hex):
    """
    Funkcia na upravenie ip adries na formát y:y:y:y:y:y:y:y
    :param ip_hex: ip v hexadecimálnom  tvare bez :
    :return: ip v upravenom IPv6 tvare
    """
    ipv6 = ''
    check = 0
    while len(ip_hex) > 0:
        tmp = str((hex(int(ip_hex[:2].hex(), 16))))[2:]
        ip_hex = ip_hex[2:]
        if tmp != "0":
            check = 0
            ipv6 += tmp
        else:
            check += 1
        if len(ip_hex) and check < 2:  # nepridávať viac ako :: medzi same nuly
            ipv6 += ":"
    return ipv6


def ip_and_protocol_setter(pack, frame_b):
    """
    Nastavenie protokolu 3. vrstvy a ip adries pre IPv4, IPv6 a ARP . Heaadery nemajú tieto info vždy na rovnakom mieste
    :param pack: packet ktorému sa ide nastaviť, typ = slovník, ktorý pôjde do yaml
    :param frame_b: frame ako hexa dáta
    """
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


def str_presenter(dumper, data):
    """
    Parser yaml súboru z internetu
    :@author https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data
    """
    if len(data.splitlines()) > 1:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


yaml.add_representer(str, str_presenter)

if __name__ == '__main__':
    filter_protocol = [value for key, value in APP_PROTOCOL.items()] + ["ICMP", "ARP"]
    flag = None
    file = None
    while True:  # Vstupne údaje od použivateľa
        inp = input("Pre klasicku analyzu zadaj iba nazov suboru \"*.pcap\", pre filtorvanie komunikacie zadaj \"-p ["
                    "TFTP, ARP, ICMP, ...]\" a nazov suboru \"*.pcap\":")
        # Vykonanie aj filtracie, druha cast
        if inp.split(" ")[0].__eq__("-p"):  # musel som pouzit toto lebo klasicke == neslo,
            flag = inp.split(" ")[1].upper()
            if flag not in filter_protocol:  # kontorla ci zadani protokol existuje
                print("Invalid protocol!")
                continue
            if path.exists("vzorky_pcap_na_analyzu\\" + inp.split(" ")[2]):  # kontorla ci zadani subor existuje
                file = rdpcap("vzorky_pcap_na_analyzu\\" + inp.split(" ")[2])
                break
        # Vykonanie iba analyzi, prva cast
        else:
            if path.exists("vzorky_pcap_na_analyzu\\" + inp.split(" ")[0]):  # kontorla ci zadani subor existuje
                flag = None
                file = rdpcap("vzorky_pcap_na_analyzu\\" + inp.split(" ")[0])
                break
        print("Invalid file!")

    task = deepcopy(empty_yaml)
    task['name'] = "PKS2022/23"
    if flag is None:  # pomenovanie podla toho ci sa vykonava aj druha cast
        task['pcap_name'] = inp.split(" ")[0]
    else:
        task['pcap_name'] = inp.split(" ")[2]
    ipv4_sender = {}
    counter = 1

    # Prechadzanie kazdym ramcom zo zadaneho subora
    for frame in file:
        frame_bytes = raw(frame)  # konvertovanie na hex pole dat
        pck = deepcopy(empty_pck)  # kopirovanie paketu ktory pojde do yaml

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

        # MAC adresy
        pck['dst_mac'] = mac_builder(frame_bytes[0:6].hex())
        pck['src_mac'] = mac_builder(frame_bytes[6:12].hex())

        # Protokoly na 1. vrstve
        # ETHERNET II a jeho pod protokoly
        if int(frame_bytes[12:14].hex(), 16) > 1500 or int(frame_bytes[12:14].hex(), 16) == 1536:
            pck['frame_type'] = "ETHERNET II"
            # protokol na 2. vrstve alebo Unknown
            pck['ether_type'] = ETH.get(frame_bytes[12:14].hex().upper(), "Unknown")
            ip_and_protocol_setter(pck, frame_bytes)  # nastavenie IP a protokolu na 3. verstve
            if pck['ether_type'] == "IPv4":
                ipv4_sender[pck['src_ip']] = ipv4_sender.get(pck['src_ip'], 0) + 1  # zapis odosielatela
                if pck['protocol'] in ("TCP", "UDP"):  # nastavenie portov a mena ak maju
                    ip_header_length = int(frame_bytes[14:15].hex()[1], 16) * 4  # velkost IPv4 hlavicky
                    pck['src_port'] = int(frame_bytes[ip_header_length + 14: ip_header_length + 16].hex(), 16)
                    pck['dst_port'] = int(frame_bytes[ip_header_length + 16: ip_header_length + 18].hex(), 16)
                    pck['app_protocol'] = APP_PROTOCOL.get((str(pck['src_port'])),
                                                           APP_PROTOCOL.get((str(pck['dst_port']))))
                    if pck['app_protocol'] is None:  # Port nema specialne meno
                        pck.pop('app_protocol')
        else:
            # RAW
            if frame_bytes[14:16].hex().upper() == "FFFF":
                pck['frame_type'] = "IEEE 802.3 RAW"
            # LLC & SNAP a PID
            elif frame_bytes[14:16].hex().upper() == "AAAA":
                pck['frame_type'] = "IEEE 802.3 LLC & SNAP"
                pck['pid'] = PID[frame_bytes[20:22].hex().upper()]
            # LLC a SAP
            else:
                pck['frame_type'] = "IEEE 802.3 LLC"
                pck['sap'] = SAP[frame_bytes[14:15].hex().upper()]
        task['packets'].append(pck)  # pridanie paketu do zoznamu co pojde do yaml subora

    # vyhodnotenie IPv4 odosielatelov
    ipv4_senders = []
    for sender in ipv4_sender:
        ipv4_senders.append({'node': sender, 'number_of_sent_packets': ipv4_sender[sender]})
    task['ipv4_senders'] = ipv4_senders
    task['max_send_packets_by'] = [key for key, value in ipv4_sender.items() if value == max(ipv4_sender.values())]

    # vykonanie filtracie ak bola poziadana
    if flag is not None:
        match flag:
            case "ARP":
                arp.arp_filter(task)
            case "ICMP":
                icmp.icmp_filter(task)
            case "TFTP":
                udp.tftp_filter(task)
            case _:
                rest.filter_frames_by_protocol(task, flag)

    # ulozenie dat do yaml subora
    with open("yaml_output\\output.yaml", "w") as file:
        yaml.dump(task, file, sort_keys=False)
    print("Výsledok bol uložený do súboru output.yaml, ktorý sa nachádza v zložke \"yaml_output\"\n")
