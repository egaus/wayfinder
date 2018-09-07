import lib.pull_attack as attack
import lib.pull_lolbins as lolbins
from nltk.tokenize import ToktokTokenizer
import pandas as pd
import json
import re
import ntpath

def get_attack_windows(local_file=None):
    '''
    Retrieves MITRE ATT&CK data.  If a local_file is provided, then it is loaded locally.  If not, it is retrieved via TAXII/STIX
    :param local_file: name of local ATT&CK cache file to load
    :return: list of attack dictionaries, one per technique
    '''
    if local_file is not None:
        attack_df = pd.read_csv(local_file)
        attack_data = attack_df.to_dict(orient='records')
    else:
        attack_data = attack.retrieve_attack_as_list()

    # just get MITRE ATT&CK that has windows as the platform
    attack_windows = []
    attack_layer = {}
    for attack in attack_data:
        attack_layer[attack['tid']] = {'enabled' : False, 'color' : '#a1d99b'} #, 'comment' : 'n/a'}
        platform = attack.get('x_mitre_platforms', '')
        if 'windows' in platform.lower():
            attack_windows.append(attack)
    print('{} total attacks, but {} are windows'.format(len(attack_data), len(attack_windows)))

    return attack_data

def create_lol_attack_ontology(lolbin_data, attack_windows):
    '''
    Takes in lolbin and attack lists and returns the resulting merged ontology
    :param lolbin_data: list of dictionaries of parsed lolbins
    :param attack_windows: list of dictionaries of parsed lolbins
    :return: merged ontology
    '''
    functions_to_attack = {'ADS' : 'T1096',
                           'Compile' : 'T1127',
                           'Create Service' : 'T1050',
                           'Start Service' : 'T1035',
                           'NTDS.dit' : 'T1003',
                           'UACBypass' : 'T1088',
                           'Download' : 'T1105'}

    toktok = ToktokTokenizer()
    ontology = {}
    for i in range(len(lolbin_data)):
        name = lolbin_data[i].get('name')
        functions = lolbin_data[i].get('functions', [])
        examples = lolbin_data[i].get('examples', [])
        lol_link = lolbin_data[i].get('link', None)
        if lol_link is None:
            lol_link = []
        short_name = name.split('.')[0]
        # clean up cases where the list of examples has comments and unrelated lines
        examples = [example for example in examples if short_name.lower() in example.lower()]
        found = False
        attack_tid_strong = set()
        attack_tid_weak = set()
        for attack in attack_windows:
            attack_name = attack.get('name')
            description = attack.get('description').lower()
            description_tokenized = toktok.tokenize(description)

            if name in description_tokenized:
                attack_tid_strong.add(attack.get('tid'))
            if short_name in description_tokenized:
                attack_tid_weak.add(attack.get('tid'))
            for function in functions:
                for k, v in functions_to_attack.items():
                    if k in function:
                        attack_tid_strong.add(v)
        ontology[name.lower()] = {'functions' : functions,
                          'examples' : examples,
                          'attack_ids_strong' : attack_tid_strong,
                          'attack_ids_weak' : attack_tid_weak,
                          'short_name' : short_name,
                          'references' : lol_link}

    # One more pass.  If all the examples for an executable, library, or script involve being invoked by a different executable, we will change the mapping
    ontology_tools = ontology.keys()
    for name, data in ontology.items():
        examples = data.get('examples')
        # Get deduped list of initial executable or tool name used in the example for each example
        tool_in_example = set()
        for example in examples:
            tokens = example.split()
            if len(tokens) > 0:
                tool_in_example.add(tokens[0].strip().lower())
        # Check if the tools listed are actually directly a MITRE ATT&CK technique.  If so, directly map to it.
        if len(tool_in_example) == 1:
            tool_name = tool_in_example.pop().strip().lower().split('.')[0]
            # the tool in the example is the only one given and it is different from the primary lolbas name
            for attack in attack_windows:
                attack_short_name = attack['name'].split('.')[0].lower()
                tid = attack['tid']
                if tool_name == attack_short_name:
                    ontology[name]['attack_ids_strong'].add(tid)

    # Exceptions:
    clear_weak = ['regsvr32.exe', 'powershell.exe', 'control.exe', 'expand.exe', 'winword.exe',
                  'explorer.exe', 'replace.exe', 'bash.exe']
    clear_strong = ['winword.exe', 'explorer.exe', 'replace.exe', 'bash.exe']
    for weak_to_clear in clear_weak:
        ontology[weak_to_clear]['attack_ids_weak'] = set()
    for strong_to_clear in clear_strong:
        ontology[strong_to_clear]['attack_ids_strong'] = set()

    ontology['powershell.exe']['attack_ids_strong'] = set(['T1086'])

    # Remove misclassifications
    try:
        ontology['sc.exe']['attack_ids_weak'].remove('T1197')
    except:
        pass
    try:
        ontology['url.dll']['attack_ids_weak'].remove('T1192')
    except:
        pass
    try:
        ontology['sc.exe']['attack_ids_strong'].remove('T1013')
    except:
        pass

    add_scripting = ['testxlst.js', 'scriptrunner.exe', 'runscripthelper.exe', 'msdeploy.exe', 'manage-bde.wsf', 'te.exe', 'cscript.exe']
    for add_script in add_scripting:
        ontology[add_script]['attack_ids_strong'].add('T1064')

    ontology['ieexec.exe']['attack_ids_strong'].add('T1105')
    ontology['msiexec.exe']['attack_ids_strong'].add('T1105')
    ontology['ieexec.exe']['functions'] = list(set(ontology['ieexec.exe']['functions']).union(['Download']))
    ontology['msiexec.exe']['functions'] = list(set(ontology['msiexec.exe']['functions']).union(['Download']))

    ### Add T1202 indirect execution
    indirect_execution = ['explorer.exe', 'dnscmd.exe', 'winword.exe', 'extexport.exe', 'vsjitdebugger.exe',
                          'csi.exe', 'hh.exe', 'appvlp.exe', 'scriptrunner.exe', 'dxcap.exe', 'ieexec.exe',
                          'openwith.exe', 'pcwrun.exe', 'msiexec.exe', 'bash.exe', 'msdeploy.exe', 'mftrace.exe']
    for indirect_exec in indirect_execution:
        ontology[indirect_exec]['attack_ids_strong'].add('T1202')

    # Combine all the strong and weak technique IDs
    for name, data in ontology.items():
        data['attack_ids'] = list(data['attack_ids_strong'].union(data['attack_ids_weak']))
        data.pop('attack_ids_strong')
        data.pop('attack_ids_weak')

    return ontology


def get_filename(filepath):
    filename_pattern = '^(.*?)\\\\([^\\\\]*)$'
    m = re.search(filename_pattern, filepath, re.IGNORECASE)

    filename_hit = m.group(1) if m else ""
    if filename_hit:
        filepath = m.group(1) if m.group(1) else ""
        filename = m.group(2) if m.group(1) else ""
    else:
        filename = ''
        filepath = ''
    return filename.lower(), filepath.lower()


def create_ms_ontology(ontology, ms_file_path):
    # Load Microsoft
    with open(ms_file_path, encoding='utf-8-sig') as f:
        microsoft_os_files = json.load(f)

    ontology_items = ontology.keys()
    for ms_file in microsoft_os_files:
        filepath = ms_file['FileName']
        filename, filepath = get_filename(filepath)
        if filename != '' and filepath != '':
            if filename not in ontology_items:
                ontology[filename] = {}
            else:
                if ontology[filename].get('functions', '') != '':
                    print("filename: {}".format(filename))
            ontology[filename]['ms_path'] = filepath
            ontology[filename]['ms_filename'] = filename
            ontology[filename]['ms_description'] = ms_file['FileDescription']
            ontology[filename]['ms_company_name'] = ms_file['CompanyName']
            ontology[filename]['ms_copyright'] = ms_file['LegalCopyright']
            ontology[filename]['ms_orig_filename'] = ms_file['OriginalFilename']

    return ontology

def save_ontology_lol_mitre_mapping(ontology, filename):
    ontology_to_df = []

    for name, item in ontology.items():
        if 'tid' in item.keys() and 'examples' in item.keys():
            ontology_to_df.append({'name' : name, 'tid' : item['attack_ids'], 'examples':', '.join(item['examples'])})

    df = pd.DataFrame(ontology_to_df)
    df.to_csv(filename, index=False, header=True, encoding='utf-8')

    everything = filename.replace('.csv', '_all.json')
    with open(everything, 'w') as outfile:
        json.dump(ontology, outfile)


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
    return attack_header

def generate_layer(header, techniques = [], attack_layer_filename=None):
    '''

    :param techniques: list containing dictionaries of "techniqueID", "color", "comment", and "enabled"
    :return:
    '''

    header['techniques'] = techniques
    with open(attack_layer_filename, 'w') as outfile:
        json.dump(header, outfile)


def create_navigator_layer(ontology, attack_data, attack_layer_filename):
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


if __name__ == '__main__':
    attack_data = get_attack_windows('./mitre_attack.csv')
    lolbin_data = lolbins.retrieve_lolbins('./lolbins', clear_cache=False)

    ontology = create_lol_attack_ontology(lolbin_data, attack_data)
    ontology = create_ms_ontology(ontology, './lib/windows_files.json')

    save_ontology_lol_mitre_mapping(ontology, './lol_mitre_mapping.csv')

    create_navigator_layer(ontology, attack_data, './mitre_attack_lolbin_mapping_layer.json')

    # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands
