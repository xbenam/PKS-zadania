from copy import deepcopy

import yaml


def doimplementacia(frames, protocol):
    """
    Vyfiltrovanie vsetkych packetov ktore maju zadany protokol
    :param frames: zoznam vsetkych ramcov zo suboru
    :param protocol: protokol podla ktoreho sa ma filtrovat
    """
    filtered_frame = deepcopy([i for i in frames.get("packets") if i.get('protocol') == "ICMP"])
    error_ty = []
    for frame in filtered_frame:
        frame_copy = deepcopy(frame)
        hexa_filed = frame_copy['hexa_frame'].split()
        ip_header_length = int(hexa_filed[14][1], 16) * 4
        ty = "".join(hexa_filed[14 + ip_header_length])
        if ty == "03":
            frame_copy['icmp_type'] = 3
            error_ty.append(frame)

    rest = {'name': "PKS2022/23",
            'pcap_name': frames['pcap_name'],
            'filter_name': "ICMP-type-3",
            'packets': error_ty,
            'count': len(error_ty)}

    with open("yaml_output\\doimplementacia.yaml", "w") as file:
        yaml.dump(rest, file, sort_keys=False)
    print("Výsledok filtrácie bol uložený do súboru doimplementacia.yaml, ktorý sa nachádza v zložke \"yaml_output\"\n")
