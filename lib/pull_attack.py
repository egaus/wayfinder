from __future__ import unicode_literals
import six
from stix2 import TAXIICollectionSource, Filter, ExternalReference, KillChainPhase
from taxii2client import Server, Collection
from stix2.utils import STIXdatetime
import pandas as pd
import json
import logging
logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)

def list_of_strings(data_object):
    '''
    Converts a list like object to a comma separated string with the values
    :param data_object: list-like object
    :return: string containing the values of the list or if that fails, returns the original object
    '''
    if isinstance(data_object, list):
        if len(data_object) > 0:
            if isinstance(data_object[0], six.text_type):
                return ', '.join(data_object)
        else:
            return ''
    return data_object

def list_of_stix_objects(data_object):
    '''
    Handles lists of stix objects and flattens the values as possible
    :param data_object: json string object
    :return: returns flattened and parsed string, or the original object if conversion fails
    '''
    try:
        result = json.loads(str(data_object))
        parsed = list_of_strings(data_object)
        return parsed
    except:
        return data_object

def list_of_kill_chain_phases(phases):

    all_phase_names = []
    for phase in phases:
        if 'phase_name' in phase.keys():
            all_phase_names.append(phase.get('phase_name', 'none'))

    if len(all_phase_names) > 0:
        return ', '.join(all_phase_names)
    return 'none'

def list_of_references(references):
    reference_keys = gather_keys(references)
    if 'external_id' in reference_keys:
        reference_keys.remove('external_id')
    counter = 0
    reference_dict = {}
    # Technique id
    tid = 'none'
    for reference in references:
        if 'external_id' in reference.keys():
            tid = reference.get('external_id', 'none')

        for ref_key in reference_keys:
            reference_dict['ref_{}_{}'.format(counter, ref_key)] = reference.get(ref_key, 'none')
        counter += 1
    return reference_dict, tid


def gather_keys(list_of_dicts):
    all_keys = set()
    for this_dictionary in list_of_dicts:
        for key in this_dictionary.keys():
            all_keys.add(key)
    return all_keys


def flatten_technique(technique, all_keys):
    flattened_entry = {}
    for key in all_keys:
        value = technique.get(key, 'none')
        if value == 'none' or isinstance(value, six.text_type):
            # Easy case, key doesn't exist, or it's a simple string
            flattened_entry[key] = value
        elif isinstance(value, bool):
            if value:
                flattened_entry[key] = str(value)
            else:
                flattened_entry[key] = str(value)
        else:
            if isinstance(value, STIXdatetime):
                flattened_entry[key] = value.strftime('%Y-%m-%dT%H:%M:%S')
            if isinstance(value, list):
                if len(value) > 0:
                    if isinstance(value[0], dict):
                        # list of dictionaries, then unpack to flatten list
                        print('')
                    elif isinstance(value[0], ExternalReference):
                        references_flat, tid = list_of_references(value)
                        flattened_entry.update(references_flat)
                        flattened_entry['tid'] = tid
                    elif isinstance(value[0], KillChainPhase):
                        flattened_kill_chain_phases_str = list_of_kill_chain_phases(value)
                        if isinstance(flattened_kill_chain_phases_str, six.text_type):
                            flattened_entry[key] = flattened_kill_chain_phases_str
                    elif isinstance(value[0], six.text_type):
                        # list of strings
                        value = list_of_strings(value)
                        flattened_entry[key] = value
                    else:
                        # probably a list of stix objects
                        flattened_stix = list_of_stix_objects(value)
                        if isinstance(flattened_stix, six.text_type):
                            flattened_entry[key] = flattened_stix

    if 'kill_chain_phases' in flattened_entry:
        phases = flattened_entry['kill_chain_phases']
        all_phases = phases.split()
        # This technique applied to multiple phases
        if len(all_phases) > 1:
            all_flattened_entries = []
            for phase in all_phases:
                new_flattened_entry = flattened_entry.copy()
                new_flattened_entry['kill_chain_phases'] = phase
                all_flattened_entries.append(new_flattened_entry)
            return all_flattened_entries
        else:
            return [flattened_entry]

    return [flattened_entry]

def retrieve_attack_as_list():
    server = Server("https://cti-taxii.mitre.org/taxii/")
    api_root = server.api_roots[0]

    for collection in api_root.collections:
        logging.info(collection.title + ":" + collection.id)

    attack = {}
    collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")

    tc_source  = TAXIICollectionSource(collection)

    filter_objs = {"techniques": Filter("type", "=", "attack-pattern"),
                   "mitigations": Filter("type", "=", "course-of-action"),
                   "groups": Filter("type", "=", "intrusion-set"),
                   "malware": Filter("type", "=", "malware"),
                   "tools": Filter("type", "=", "tool"),
                   "relationships": Filter("type", "=", "relationship")
                   }

    techniques = tc_source.query(filter_objs['techniques'])

    all_keys = gather_keys(techniques)

    parsed_techniques = []
    for technique in techniques:
        parsed_technique = flatten_technique(technique, all_keys)
        parsed_techniques = parsed_techniques + parsed_technique

    return parsed_techniques


def retrieve_attack_as_df():
    parsed_techniques = retrieve_attack_as_list()
    df = pd.DataFrame(parsed_techniques)
    return df

def save_attack_as_csv(path_to_csv):
    df = retrieve_attack_as_df()
    fields = ['kill_chain_phases', 'tid', 'name', 'description', 'ref_0_url',
              'x_mitre_data_sources', 'x_mitre_defense_bypassed', 'x_mitre_permissions_required',
              'x_mitre_platforms', 'x_mitre_system_requirements']
    df[fields].to_csv(path_to_csv, index=False, header=True, encoding='utf-8')

if __name__ == '__main__':
    path_to_csv = './mitre_techniques.csv'
    save_attack_as_csv(path_to_csv)
