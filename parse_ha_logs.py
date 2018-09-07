import json
import re
import pandas as pd
from os import listdir
from os.path import isfile, join
from os.path import basename
import ipaddress

def load_ha_file(filepath):
    print(filepath)
    data = []
    with open(filepath) as ha_file:
        for line in ha_file:
            try:
                data_dict = json.loads(line)
                data.append(data_dict)
            except Exception as e:
                print(e)
        return data

    return None

def get_log_files(directory):
    return ['./ha_sample.json']


def get_execution_path(uid, tree):
    root = tree.get('root', '')
    cur_uid = uid
    chain = tree.get('uid_exec_name_map').get(cur_uid, '')
    chain_cnt = 1
    while cur_uid != root and root != '' and cur_uid != '':
        cur_uid = tree.get('parent_child_map').get(cur_uid, '')
        cur_exec = tree.get('uid_exec_name_map').get(cur_uid, '')
        if cur_exec != '':
            chain_cnt += 1
            chain = '{} => {}'.format(cur_exec, chain)

    return chain, chain_cnt

def build_tree_dict(process_list):
    tree = {'parent_child_map':{}, 'uid_exec_name_map':{}}
    for process in process_list:
        uid = process.get('uid', '')
        parentuid = process.get('parentuid', '')
        exec = process.get('name', '')

        if parentuid == '':
            tree['root'] = uid
        else:
            tree['parent_child_map'][uid] = parentuid
        tree['uid_exec_name_map'][uid] = exec

    return tree

def parse_processes(entry, process_list):
    tree = build_tree_dict(process_list)
    top_lvl_entry = entry[0]
    new_entry_list = []

    for process in process_list:
        new_entry = top_lvl_entry.copy()
        parentuid = ''
        uid = ''
        for k, v in process.items():
            if isinstance(v, str) or isinstance(v, int) or isinstance(v, bool):
                new_entry['proc_{}'.format(k)] = v
            else:
                print("not sure what this is: ", k, v)
            if k == 'uid':
                uid = v
        # build path
        new_entry['proc_chain'], new_entry['proc_chain_len']  = get_execution_path(uid, tree)
        new_entry_list.append(new_entry)

    return new_entry_list


def get_extension(filename, len_limit=5):
    extension_pattern = '.*?\.([a-z0-9]{1,' + str(len_limit) + '})$'
    m = re.search(extension_pattern, filename, re.IGNORECASE)
    ext_hit = m.group(1) if m else ""
    if ext_hit:
        extension = m.group(1) if m.group(1) else ""
    else:
        extension = ''
    return extension.lower()



def parse_dropped_files(entry, extracted_file_list):
    # cnt of files
    # cnt by type
    # unique types
    # extensions

    type_cnt = 0
    uniq_file_types = set()
    uniq_file_type_text = set()
    uniq_extensions = set()
    types = {}

    # Take a pass through the files to aggregate metadata into a single 1D record.
    for file in extracted_file_list:
        ext = get_extension(file.get('name', ''))
        type = ';'.join(file.get('type_tags', []))

        type_key = "extr_file_type_{}".format(type)
        ext_key = "extr_file_ext_{}".format(ext)
        type_text = file.get('type', '')
        if type_text != '':
            uniq_file_type_text.add(type_text)
        if type != '':
            uniq_file_types.add(type)
        if ext != '':
            uniq_extensions.add(ext)
        if ext_key in types.keys():
            types[ext_key] += 1
        else:
            types[ext_key] = 1
        if type != '' and type_key in types.keys():
            types[type_key] += 1
        elif type != '' and type_key not in types.keys():
            types[type_key] = 1
        else:
            # type_key was empty
            continue

    # Append summarized features
    #for k, v in types.items():
    #    entry[0][k] = v
    entry[0]['extr_file_types'] = '; '.join(list(uniq_file_types))
    entry[0]['extr_file_exts'] = '; '.join(list(uniq_extensions))
    entry[0]['extr_file_type_text'] = '; '.join(list(uniq_file_type_text))
    entry[0]['extr_file_cnt'] = len(extracted_file_list)
    
    return entry

def parse_hosts(entry, hosts, special_ip_addresses):
    host_set = set()

    private_ip = 0
    other_special_ip = 0
    localhost_cnt = 0
    other_cnt = 0

    for host in hosts:
        host_set.add(host)
        match = special_ip_match(host, special_ip_addresses)
        if match == 'Private-Use':
            private_ip += 1
        elif match == 'localhost':
            localhost_cnt += 1
        elif match != '':
            other_special_ip += 1
        else:
            other_cnt += 1

    entry[0]['host_private_ip_cnt'] = private_ip
    entry[0]['host_local_ip_cnt'] = localhost_cnt
    entry[0]['host_external_ip_cnt'] = other_cnt
    entry[0]['host_special_ip_cnt'] = other_special_ip
    entry[0]['hosts_uniq_cnt'] = len(host_set)

    return entry


def parse_hosts_geo(entry, hosts_geo):

    countries = set()
    for host_info in hosts_geo:
        country = host_info.get('cc', '')
        if country != '':
            countries.add(country)

    entry[0]['host_country_cnt'] = len(countries)
    entry[0]['host_countries'] = '; '.join(countries)

    return entry

def parse_domains(entry, domains):
    uniq_domains = set()
    uniq_tlds = set()
    for domain in domains:
        tld = get_extension(domain, len_limit=10)
        if tld != '':
            uniq_tlds.add(tld)
        if domain != '':
            uniq_domains.add(domain)

    entry[0]['domain_cnt'] = len(uniq_domains)
    entry[0]['domain_list'] = '; '.join(list(uniq_domains))
    entry[0]['domain_tld_cnt'] = len(uniq_tlds)
    entry[0]['domain_tld_list'] = '; '.join(list(uniq_tlds))

    return entry


def process_ha_dictionary(data, special_ip_addresses, hashes_today):
    if data is None:
        return []

    len_data = len(data)
    if len_data > 0:
        parsed_logs = []
        for i in range(len_data):
            entry = [{}]
            sample = data[i]
            key = sample['analysis_start_time'] + sample['sha1']

            # Get rid of duplicates if the key matches something we've already seen
            if key not in hashes_today:
                hashes_today.add(key)
                for k, v in sample.items():
                    if isinstance(v, str) or isinstance(v, int) or isinstance(v, bool):
                        entry[0][k] = v

                entry[0]['tags'] = '; '.join(sample.get('tags', ''))
                entry = parse_dropped_files(entry, sample.get('extracted_files', []))
                entry = parse_hosts(entry, sample.get('hosts', []), special_ip_addresses)
                entry = parse_hosts_geo(entry, sample.get('hosts_geo', []))
                entry = parse_domains(entry, sample.get('domains', []))
                entry = parse_processes(entry, sample.get('process_list', []))

                parsed_logs = parsed_logs + entry

        return parsed_logs, hashes_today

    return []

def organize_logs_by_day(all_log_files):
    logfiles_by_day = {}
    for full_file_path in all_log_files:
        filename = basename(full_file_path)
        day = filename.split('T')[0]
        if day in logfiles_by_day.keys():
            logfiles_by_day[day].append(full_file_path)
        else:
            logfiles_by_day[day] = [full_file_path]

    return logfiles_by_day


def get_cidr_range_matches():

    # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
    network_list = [('0.0.0.0/8','localhost'),
                    ('10.0.0.0/8', 'Private-Use'),
                    ('100.64.0.0/10',  'shared ip space'),
                    ('127.0.0.0/8', 'localhost'),
                    ('169.254.0.0/16', 'link local'),
                    ('172.16.0.0/12', 'Private-Use'),
                    ('192.0.0.0/24', 'ietf protocol assignments'),
                    ('192.0.0.0/29', 'IPv4 Service Continuity Prefix'),
                    ('192.0.0.8/32', 'IPv4 dummy address'),
                    ('192.0.0.9/32', 'Port Control Protocol Anycast'),
                    ('192.0.0.10/32', 'Traversal Using Relays around NAT Anycast'),
                    ('192.0.0.170/32', 'NAT64/DNS64 Discovery'),
                    ('192.0.0.171/32', 'NAT64/DNS64 Discovery'),
                    ('192.0.2.0/24', 'Documentation (TEST-NET-1)'),
                    ('192.31.196.0/24', 'AS112-v4'),
                    ('192.52.193.0/24', 'AMT'),
                    ('192.88.99.0/24', 'Deprecated (6to4 Relay Anycast)'),
                    ('192.168.0.0/16', 'Private-Use'),
                    ('192.175.48.0/24', 'Direct Delegation AS112 Service'),
                    ('198.18.0.0/15', 'Benchmarking'),
                    ('198.51.100.0/24', 'Documentation (TEST-NET-2)'),
                    ('203.0.113.0/24', 'Documentation (TEST-NET-3)'),
                    ('240.0.0.0/4', 'Reserved'),
                    ('255.255.255.255/32', 'Limited Broadcast')]
    special_ip_ranges = [
        {'name':name,
         'cidr':cidr,
         'mask':int(ipaddress.ip_network(cidr).netmask),
         'net_addr' : int(ipaddress.ip_network(cidr).network_address)}
        for cidr, name in network_list]

    return special_ip_ranges


def special_ip_match(ip, special_ip_ranges):
    a = int(ipaddress.ip_address(ip))
    for network in special_ip_ranges:
        if (a & network['mask']) == network['net_addr']:
            return network['name']
    return ''


if __name__ == '__main__':

    log_directory = './raw_data'
    all_log_files = [join(log_directory, f) for f in listdir(log_directory) if isfile(join(log_directory, f)) and '.json' in f]

    log_files_by_day = organize_logs_by_day(all_log_files)
    days = list(log_files_by_day.keys())
    days.sort()

    special_ip_addresses = get_cidr_range_matches()

    # For each file, might want to dedup by analysis time and hash.
    hashes_today = set()
    for this_day in days:
        todays_logs = log_files_by_day[this_day]
        todays_logs.sort()
        all_parsed_samples = []
        for log_file in todays_logs:
            try:
                data_dict = load_ha_file(log_file)
            except Exception as e:
                print(e)
                data_dict = {}
            parsed_samples, hashes_today = process_ha_dictionary(data_dict, special_ip_addresses, hashes_today)
            all_parsed_samples = all_parsed_samples + parsed_samples

        df = pd.DataFrame(all_parsed_samples)
        df.to_csv('./parsed/{}_parsed_logs.csv'.format(this_day), index=False, encoding='utf-8', header=True)
