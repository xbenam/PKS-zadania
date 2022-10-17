"""
author: Martin Beňa
consultant: Ing. Kristián Košťál, PhD.
date: 18.10.2022
"""
from copy import deepcopy
import yaml

with open("Protocols\\l4\\TFTP.txt") as f:
    TFTP = yaml.load(f.read(), Loader=yaml.SafeLoader)

# slovník ktorý v sebe bude mat všetky vyfiltrovane TFTP komunikacie, ktoré pôjdu do yaml súboru
tftp_yaml = {'name': "PKS2022/23",
             'pcap_name': None,
             'filter_name': "TFTP",
             'communications': []}


def set_opcode(frame):
    """
    Nastavenie opcodu pre dany ramec
    :param frame: ramec bez opcodu
    """
    hexa_filed = frame['hexa_frame'].split()    # hex data ako pole
    ip_header_length = int(hexa_filed[14][1], 16) * 4   # velkost IPv4 hlavicky
    frame['opcode'] = TFTP.get("".join(hexa_filed[14 + ip_header_length + 8: 14 + ip_header_length + 10]))
    frame['app_protocol'] = "TFTP"


def tftp_filter(frames):
    """
    Zo zadaných packetov vyfiltruje tie ktore maju protokol TFTP a tie nasledne poparuje
    :param frames: zoznam vsetkych ramcov zo suboru
    """
    tftp_yaml['pcap_name'] = frames['pcap_name']
    # vyfltrovanie vsetkych ramcov s TFTP protokolom
    tftp_only = [i for i in frames['packets'] if i.get('app_protocol') == "TFTP"]
    communications = []  # zoznam komunikacii v zadanom dokumente

    for tftp in tftp_only:
        set_opcode(tftp)
        comm = [tftp]
        src_port = tftp.get('src_port')
        dst_port = tftp.get('dst_port')
        num = tftp.get('frame_number')
        # iteruj cez ramce pod najdeným ramcom az dokym nenajde zaciatok novej komunikacie
        while num < len(frames['packets']):
            next_com = deepcopy(frames['packets'][num])
            if next_com.get('protocol') == "UDP":
                if next_com['dst_port'] == src_port or next_com['src_port'] == src_port:
                    if dst_port == 69:
                        dst_port = next_com['src_port']
                    set_opcode(next_com)
                    comm.append(next_com)
                elif next_com['dst_port'] == 69:
                    break
            num += 1

        communications.append({'number_comm': len(communications) + 1, 'src_comm': comm[0]['src_ip'],
                               'dst_comm': comm[0]['dst_ip'], 'packets': comm})

    tftp_yaml['communications'] = communications
    with open("yaml_output\\tftp.yaml", "w") as file:
        yaml.dump(tftp_yaml, file, sort_keys=False)
    print("Výsledok filtrácie bol uložený do súboru tftp.yaml, ktorý sa nachádza v zložke \"yaml_output\"\n")
