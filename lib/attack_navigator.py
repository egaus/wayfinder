import json
import pandas as pd
import math
import pull_attack

def build_header(name = 'default', description = 'default description'):
    attack_header = {}
    attack_header['name'] = name
    attack_header['version'] = '2.0'
    attack_header['domain'] = 'mitre-enterprise'
    attack_header['description'] = description
    attack_header['sorting'] = 0
    attack_header['viewFullTable'] = True
    attack_header['hideDisabled'] = True
    attack_header['techniques'] = []
    attack_header["legendItems"] = []
    attack_header["showTacticRowBackground"] = True
    attack_header["tacticRowBackground"] = "#dddddd"
    attack_header["selectTechniquesAcrossTactics"] = True
    return attack_header

def generate_layer(header, techniques = [], attack_layer_filename=None):
    '''

    :param techniques: list containing dictionaries of "techniqueID", "color", "comment", and "enabled"
    :return:
    '''

    header['techniques'] = techniques
    with open(attack_layer_filename, 'w') as outfile:
        json.dump(header, outfile)


def get_color_mapping_offset(colors, min_weight, max_weight):
    '''
    Returns the idx_boundary based on the number of colors in the scale and min / max weight values.
    Note: Check out color schemes here: https://www.w3schools.com/colors/colors_picker.asp

    :param colors: list of color values
    :param min_weight: minimum weight value that will be displayed (if you want white to show up as 0, then be sure
    the min_weight is 0 and your index=0 color is white (0xffffff)
    :param max_weight: largest weight value in the range to map colors to
    :return: the idx_boundary, which is the spacing multiplier to equally distribute values across the min/max range
    '''
    number_colors = len(colors)
    idx_boundary = (max_weight - min_weight) / number_colors

    return idx_boundary


def get_color(this_weight, colors, min_weight, idx_boundary):
    '''
    Given the idx_boundary computed from get_color_mapping_offset() and the other parameters, returns the associated
    color index with the given "this_weight" value
    :param this_weight: the weight to find the associated color for
    :param colors: list of colors e.g.  colors=['#e6f7ff', '#cceeff', ... ]
    :param min_weight:
    :param idx_boundary:
    :return:
    '''
    color_idx = int(math.floor((this_weight - min_weight) / idx_boundary))
    if color_idx >= len(colors):
        color_idx = len(colors) - 1
    if color_idx < 0:
        color_idx = 0
    return colors[color_idx]


def create_navigator_layer(ontology, attack_data, attack_layer_filename, colors=['#e6f7ff', '#cceeff', '#b3e6ff', '#80d4ff', '#4dc3ff']):
    attack_layer = {}
    for attack in attack_data:
        attack_layer[attack['tid']] = {'enabled' : False, 'color' : '#a1d99b'}

    # Customize MITRE Layer
    for name, data in ontology.items():
        if 'attack_ids' in data.keys():
            tids = data['attack_ids']
            for tid in tids:
                attack_layer[tid]['enabled'] = True
                attack_layer[tid]['color'] = '#fdae6b'
                # attack_layer[tid]['comment'] = name + "\n" + attack_layer[tid]['comment']

    attack_layer_list = []
    for tid, data in attack_layer.items():
        attack_layer_list.append({'techniqueID' : tid, 'enabled' : data['enabled'],
                                  'color' : data['color']}) #, 'comment' : data['comment']})

    header = build_header()
    generate_layer(header, attack_layer_list, attack_layer_filename)


def load_csv_to_df(csv_filename, hide_missing=False, custom_colors=None):
    '''
    A csv minimally with headers 'techniqueID' (e.g. T1089) and weight (e.g. some number)
    Optional fields: 'enabled' (boolean like True), 'color' (str like '#b3e6ff'), tactic (str like '')
    By default the ATT&CK Navigator supports score / color gradient mappings of 0 = Red, 50 = Yellow, 100 = Green.
    :return:
    '''
    tactic_keywords = {'lateral-movement' : ['lateral'],
                       'persistence' : ['persistence'],
                       'discovery' : ['disc'],
                       'execution' : ['exec'],
                       'command-and-control' : ['c2', 'control'],
                       'defense-evasion' : ['evas'],
                       'exfiltration' : ['exfil'],
                       'collection' : ['collection'],
                       'initial-access' : ['initial'],
                       'privilege-escalation' : ['priv', 'escal'],
                       'credential-access' : ['cred']
                       }

    df = pd.DataFrame()
    return df

def normalize_df(df):

    return df


def create_navigator_layer(df, layer_name='test', layer_description='test', attack_layer_filename='./custom_layer.json', normalize_score=False, colors=None, disable_missing=False):
    attack_data = df.to_dict(orient='records')

    idx_boundary = 0
    if colors is not None:
        min_weight = df['score'].min()
        max_weight = df['score'].max()

        idx_boundary = get_color_mapping_offset(colors, min_weight, max_weight)


    attack_layer_list = []
    for attack_technique in attack_data:
        new_entry = {'techniqueID' : attack_technique['TechniqueID']}

        if 'comment' in attack_technique.keys():
            new_entry['comment'] = attack_technique['comment']

        if 'score' in attack_technique.keys():
            new_entry['score'] = attack_technique['score']

        if 'color' in attack_technique.keys():
            new_entry['color'] = attack_technique['color']
        else:
            if colors is not None and 'score' in new_entry.keys():
                color = get_color(new_entry['score'], colors, min_weight, idx_boundary)
                new_entry['color'] = color

        attack_layer_list.append(new_entry)

    if disable_missing:
        attack_df = pull_attack.retrieve_attack_as_df()
        technique_ids = attack_df.tid.tolist()
        for technique_id in technique_ids:
            found = False
            for attack in attack_layer_list:
                if attack['techniqueID'] == technique_id:
                    found = True
            if not found:
                attack_layer_list.append({'techniqueID' : technique_id, 'enabled' : False})

    header = build_header(name=layer_name, description=layer_description)
    generate_layer(header, attack_layer_list, attack_layer_filename)


if __name__ == '__main__':
    colors = ['#e6f7ff', '#cceeff', '#b3e6ff', '#80d4ff', '#4dc3ff']
    load_csv_to_df('./mitre_test.csv')
    data = [{'TechniqueID': 'T1192', 'score' : 7, 'comment' : '7 use cases\n - High-spearphishing_link_to_uncommon_domain'},
            {'TechniqueID': 'T1043', 'score': 23, 'comment': '23 use cases\n - High-beacon detected to social media url\n - medium-powershell_beaconing_detected_from_sensitive_server'},
            {'TechniqueID': 'T1085', 'score': 15, 'comment': '15 use cases\n - Low-rundll launching javascript'},
            {'TechniqueID': 'T1086', 'score': 10, 'comment': '10 use cases\n - Medium-powershell_downloading_exe'},
            {'TechniqueID': 'T1191', 'score': 5, 'comment': '5 use cases\n - Low-detects_when_cmstp_is_launched'},
            {'TechniqueID': 'T1095', 'score': 30, 'comment': '30 use cases\n - High-anomalous network traffic multiple rules'}]

    df = pd.DataFrame(data)
    create_navigator_layer(df,
                           layer_name='Rule Coverage',
                           layer_description='Number of rules by technique',
                           attack_layer_filename='./custom_layer.json',
                           normalize_score=False,
                           colors=['#ffffb3', '#ccff99', '#ccff66', '#8cff66'],
                           disable_missing=True)
