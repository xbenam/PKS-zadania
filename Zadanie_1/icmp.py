"""
author: Martin Beňa
consultant: Ing. Kristián Košťál, PhD.
date: 18.10.2022
"""
from copy import deepcopy
import yaml

with open("Protocols\\l4\\ICMP.txt") as f:
    ICMP = yaml.load(f.read(), Loader=yaml.SafeLoader)

# slovník ktorý v sebe bude mat všetky vyfiltrovane ICMP komunikacie, ktoré pôjdu do yaml súboru
icmp_yaml = {'name': "PKS2022/23",
             'pcap_name': None,
             'filter_name': "ICMP",
             'complete_comms': [],
             'partial_comms': []}


def check(request, reply):
    """
    Kontrola nastavenia portov
    :param request: packet s requestom
    :param reply: packet s reply
    :return: ak sa zhoduju v komunikacii tak True inak False
    """
    if len(request) == 0 or len(reply) == 0:
        return 0
    for req in request:
        for rep in reply:
            if req['dst_ip'] != rep['src_ip'] or req['src_ip'] != rep['dst_ip']:
                return False
    return True


def icmp_filter(frames):
    """
    Zo zadaných packetov vyfiltruje tie ktore maju protokol ICMP a tie nasledne poparuje
    :param frames: zoznam vsetkych ramcov zo suboru
    """
    icmp_yaml['pcap_name'] = frames['pcap_name']
    frag = (False, None, None)
    complete_comms = []
    partial_comms = []
    icp_full = []
    id_list = set()

    # vyfltrovanie vsetkych ramcov s TFTP protokolom
    icmp_only = [i for i in frames['packets'] if i.get('protocol') == 'ICMP']
    for frame in icmp_only:
        frame_copy = deepcopy(frame)
        hexa_filed = frame_copy['hexa_frame'].split()
        ip_header_length = int(hexa_filed[14][1], 16) * 4
        if hexa_filed[20] == "20":  # fragmentovany ramec
            frag = (True, ICMP.get(hexa_filed[14 + ip_header_length]),
                    int("".join(hexa_filed[20 + ip_header_length:22 + ip_header_length]), 16))
            frame_copy['icmp_type'] = frag[1]
            frame_copy['flags_mf'] = True
            frame_copy['seq_num(BE)'] = frag[2]
        elif frag[0]:   # koniec fragmentovaneho ramca
            frame_copy['icmp_type'] = frag[1]
            frame_copy['seq_num(BE)'] = frag[2]
            frag = (False, None, None)
            frame_copy['flags_mf'] = False
        else:   # normalny ramec
            frame_copy['icmp_type'] = ICMP.get(hexa_filed[14 + ip_header_length])
            frame_copy['flags_mf'] = False
            frame_copy['seq_num(BE)'] = int("".join(hexa_filed[20 + ip_header_length: 22 + ip_header_length]), 16)

        frame_copy['frag_offset'] = (int("".join(hexa_filed[20:22]), 16) & 8191) * 8    # prepocet offeset
        frame_copy['id'] = int("".join(hexa_filed[18:20]), 16)
        id_list.add(frame_copy['seq_num(BE)'])
        icp_full.append(frame_copy)

    for com_ID in id_list:
        # komunikacie s rovnakym seq cislom
        req_same_ID = [i for i in icp_full if i.get('seq_num(BE)') == com_ID and i.get('icmp_type') == "ECHO REQUEST"]
        rep_same_ID = [i for i in icp_full if i.get('seq_num(BE)') == com_ID and i.get('icmp_type') == "ECHO REPLY"]
        # kompletne kominikacie
        if check(req_same_ID, rep_same_ID):
            complete_comms.append({'number_comm': len(complete_comms) + 1, 'src_comm': req_same_ID[0]['src_ip'],
                                   'dst_comm': req_same_ID[0]['dst_ip'], 'packets': req_same_ID + rep_same_ID})
        # nekompletne kominikacie
        else:
            if len(req_same_ID) != 0:
                partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets': req_same_ID})
            if len(rep_same_ID) != 0:
                partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets': rep_same_ID})
            others = [i for i in icp_full if i.get('id') == com_ID and i.get('icmp_type') != "ECHO REQUEST" and
                 i.get('icmp_type') != "ECHO REPLY"]
            if len(others):
                partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets':others})


    icmp_yaml['complete_comms'] = complete_comms
    icmp_yaml['partial_comms'] = partial_comms
    with open("yaml_output\\icmp.yaml", "w") as file:
        yaml.dump(icmp_yaml, file, sort_keys=False)
    print("Výsledok filtrácie bol uložený do súboru icmp.yaml, ktorý sa nachádza v zložke \"yaml_output\"\n")
