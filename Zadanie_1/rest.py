"""
author: Martin Beňa
consultant: Ing. Kristián Košťál, PhD.
date: 18.10.2022
"""
import yaml


def filter_frames_by_protocol(frames, protocol):
    """
    Vyfiltrovanie vsetkych packetov ktore maju zadany protokol
    :param frames: zoznam vsetkych ramcov zo suboru
    :param protocol: protokol podla ktoreho sa ma filtrovat
    """
    frames = [i for i in frames.get("packets") if i.get('app_protocol') == protocol]
    rest = {'name': "PKS2022/23",
            'pcap_name': frames['pcap_name'],
            'filter_name': protocol,
            'packets': frames}

    with open("ymal_output\\rest.yaml", "w") as file:
        yaml.dump(rest, file, sort_keys=False)
    print("Výsledok filtrácie bol uložený do súboru rest.yaml, ktorý sa nachádza v zložke \"yaml_output\"\n")
