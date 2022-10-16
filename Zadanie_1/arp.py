
from yaml import dump

arp_yaml = {'name': "PKS2022/23",
            'pcap_name': None,
            'filter_name': "ARP",
            'complete_comms': [],
            'partial_comms': []}

def main(task):
    arp_yaml['pcap_name'] = task['pcap_name']

    com_rq = [i for i in task['packets'] if i.get('arp_opcode') == "REQUEST"]
    com_rp = [i for i in task['packets'] if i.get('arp_opcode') == "REPLY"]
    for rq in com_rq:
        for rp in com_rp:
            if rq['dst_ip'] == rp['src_ip'] and rp['dst_ip'] == rq['src_ip']:
                arp_yaml['complete_comms'].append({'number_comm': len(arp_yaml['complete_comms']) + 1,
                                                   'src_comm': rq['src_ip'],
                                                   'dst_comm': rq['dst_ip'],
                                                   'packets': [rq, rp]})
                com_rp.remove(rp)
                com_rq.remove(rq)
    for rq in com_rq:
        arp_yaml['partial_comms'].append({'number_comm': len(arp_yaml['partial_comms']) + 1,
                                          'packets': [rq]})

    with open("ymal_output\\arp.yaml", "w") as file:
        dump(arp_yaml, file, sort_keys=False)
