"""
author: Martin Beňa
consultant: Ing. Kristián Košťál, PhD.
date: 18.10.2022
"""
from yaml import dump

# slovník ktorý v sebe bude mat všetky vyfiltrovane ARP komunikacie, ktoré pôjdu do yaml súboru
arp_yaml = {'name': "PKS2022/23",
            'pcap_name': None,
            'filter_name': "ARP",
            'complete_comms': [],
            'partial_comms': []}


def arp_filter(frames):
    """
    Zo zadaných packetov vyfiltruje tie ktore maju protokol ARP a tie nasledne poparuje
    :param frames: zoznam vsetkych ramcov zo suboru
    """
    arp_yaml['pcap_name'] = frames['pcap_name']

    # vyfltrovanie vsetkych ramcov s REQUEST alebo REPLY app_opcode
    com_rq = [request_frame for request_frame in frames['packets'] if request_frame.get('arp_opcode') == "REQUEST"]
    com_rp = [reply_frame for reply_frame in frames['packets'] if reply_frame.get('arp_opcode') == "REPLY"]
    # párovanie requestov s replys
    for rq in com_rq:
        for rp in com_rp:
            if rq['dst_ip'] == rp['src_ip'] and rp['dst_ip'] == rq['src_ip']:
                # pridelenie do completnej komunikacie
                arp_yaml['complete_comms'].append({'number_comm': len(arp_yaml['complete_comms']) + 1,
                                                   'src_comm': rq['src_ip'],
                                                   'dst_comm': rq['dst_ip'],
                                                   'packets': [rq, rp]})
                com_rp.remove(rp)
                com_rq.remove(rq)
    # nekompletne komunikacie
    for rq in com_rq:
        arp_yaml['partial_comms'].append({'number_comm': len(arp_yaml['partial_comms']) + 1,
                                          'packets': [rq]})
    for rp in com_rp:
        arp_yaml['partial_comms'].append({'number_comm': len(arp_yaml['partial_comms']) + 1,
                                          'packets': [rp]})

    with open("yaml_output\\arp.yaml", "w") as file:
        dump(arp_yaml, file, sort_keys=False)
    print("Výsledok filtrácie bol uložený do súboru arp.yaml, ktorý sa nachádza v zložke \"yaml_output\"\n")
