
from copy import deepcopy
import yaml

with open("Protocols\\l4\\ICMP.txt") as f:
    ICMP = yaml.load(f.read(), Loader=yaml.SafeLoader)

icmp_yaml = {'name': "PKS2022/23",
             'pcap_name': None,
             'filter_name': "ICMP",
             'complete_comms': [],
             'partial_comms': []}


def check(request, reply):
    for req in request:
        for rep in reply:
            if req['dst_ip'] != rep['src_ip'] or req['src_ip'] != rep['dst_ip']:
                return False
    return True


def main(task):
    icmp_yaml['pcap_name'] = task['pcap_name']
    frag = (False, None)
    complete_comms = []
    partial_comms = []
    icp_full = []
    id_list = set()

    icmp_only = [i for i in task['packets'] if i.get('protocol') == 'ICMP']
    for frame in icmp_only:
        frame_copy = deepcopy(frame)
        hexa_filed = frame_copy['hexa_frame'].split()
        ip_header_length = int(hexa_filed[14][1], 16) * 4
        if hexa_filed[20] == "20":
            frag = (True, ICMP.get(hexa_filed[14 + ip_header_length]))
            frame_copy['icmp_type'] = frag[1]
            frame_copy['flags_mf'] = True
        elif frag[0]:
            frame_copy['icmp_type'] = frag[1]
            frag = (False, None)
            frame_copy['flags_mf'] = False
        frame_copy['frag_offset'] = (int("".join(hexa_filed[20:22]), 16) & 8191) * 8
        frame_copy['id'] = int("".join(hexa_filed[18:20]), 16)
        id_list.add(frame_copy['id'])
        icp_full.append(frame_copy)

    for com_ID in id_list:
        req_same_ID = [i for i in icp_full if i.get('id') == com_ID and i.get('icmp_type') == "ECHO REQUEST"]
        rep_same_ID = [i for i in icp_full if i.get('id') == com_ID and i.get('icmp_type') == "ECHO REPLY"]
        if check(req_same_ID, rep_same_ID):
            complete_comms.append({'number_comm': len(complete_comms) + 1, 'packets': req_same_ID + rep_same_ID})
        else:
            partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets': req_same_ID})
            partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets': rep_same_ID})
            partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets':
            [i for i in icp_full if i.get('id') == com_ID and i.get('icmp_type') != "ECHO REQUEST" and
             i.get('icmp_type') != "ECHO REPLY"]})



    # communication = []
    # for frame in icp_full:
    #     if frame['icmp_type'] == "ECHO REPLY":
    #         if len(communication) == 0:
    #             partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets': [frame]})
    #             communication = []
    #         else:
    #             if communication[0]['dst_ip'] == frame['src_ip'] and communication[0]['src_ip'] == frame['dst_ip']:
    #                 if frame['flag'] == 20:
    #                     communication.append(frame)
    #                 elif communication[-1]['src_ip'] == frame['src_ip'] and communication[-1]['dst_ip'] == frame['dst_ip']:
    #                     communication.append(frame)
    #                     complete_comms.append({'number_comm': len(complete_comms) + 1, 'packets': communication})
    #                     communication = []
    #     elif frame['icmp_type'] == "ECHO REQUEST":
    #         if len(communication) == 0:
    #             communication.append(frame)
    #         else:
    #             if communication[-1]['src_ip'] == frame['src_ip'] and communication[-1]['dst_ip'] == frame['dst_ip']:
    #                 if communication[-1]['flag'] == 20:
    #                     communication.append(frame)
    #                 else:
    #                     partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets': communication})
    #                     communication = [frame]
    #     else:
    #         partial_comms.append({'number_comm': len(partial_comms) + 1, 'packets': frame})

    icmp_yaml['complete_comms'] = complete_comms
    icmp_yaml['partial_comms'] = partial_comms
    with open("ymal_output\\icmp.yaml", "w") as file:
        yaml.dump(icmp_yaml, file, sort_keys=False)