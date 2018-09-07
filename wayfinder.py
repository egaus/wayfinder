from os import listdir
from os.path import isfile, join
import json
import re
import ntpath
from jellyfish import jaro_distance
from datetime import datetime
from elasticsearch import Elasticsearch
import wayfinder as wf
import pandas as pd
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

class Wayfinder:
    def __init__(self, ontology_filepath):
        self.load_ontology(ontology_filepath)
        self.memory = {}
        self.unknown_process = 'unknown_process'
        self.known_processes_ctr = 0
        self.unknown_processes_ctr = 0

        # Keeps track of recent examples to learn new common executables
        self.learning_buffer = []
        self.learning_buffer_max = 2000

        # TF-IDF
        self.tfidf_corpus_limit = 10 # if we have 5 or more examples, we will use tfidf + cosine matching instead of Jaro

    def get_closest_matches_proc_chain(self, proc_chain, proc_match, counter=False, timestamp=None):
        '''
        Given a process executable name, find the process chain that most closely matches the given proc_chain.
        :param proc_chain:
        :param proc_match:
        :param counter:
        :return:
        '''
        matches = {}
        matches['malicious'] = {'max_score' : 0.0, 'closest_match' : ''}
        matches['benign'] = {'max_score' : 0.0, 'closest_match' : ''}
        matches['verdict'] = {'label' : 'inconclusive', 'confidence' : 100.0, 'max_score' : 0.0}

        # Before doing fancy similarity scores, check for exact equality matches
        proc = proc_match.get('proc_name', '')
        benign_hit = False
        malicious_hit = False
        if proc_chain in proc_match['mal_proc_chain_examples'].keys():
            if counter:
                self.save_proc_chain_example(proc, proc_chain, 'malicious', timestamp)
            matches['malicious'] = {'max_score': 1.0, 'closest_match': proc_chain}
            malicious_hit = True
        if proc_chain in proc_match['ben_proc_chain_examples'].keys():
            if counter:
                self.save_proc_chain_example(proc, proc_chain, 'benign', timestamp)
            matches['benign'] = {'max_score': 1.0, 'closest_match': proc_chain}
            benign_hit = True

        if malicious_hit or benign_hit:
            label = 'inconclusive'
            if malicious_hit and not benign_hit:
                label = 'malicious'
            if benign_hit and not malicious_hit:
                label = 'benign'
            matches['verdict'] = {'label': label, 'confidence': 100.0, 'max_score': 1.0}

        else:
            if 'mal_proc_chain_examples' in proc_match.keys():
                for example in proc_match['mal_proc_chain_examples'].keys():
                    score = jaro_distance(proc_chain, example)
                    if score > matches['malicious']['max_score']:
                        matches['malicious']['max_score'] = score
                        matches['malicious']['closest_match'] = example

            if 'ben_proc_chain_examples' in proc_match.keys():
                for example in proc_match['ben_proc_chain_examples'].keys():
                    score = jaro_distance(proc_chain, example)
                    if score > matches['benign']['max_score']:
                        matches['benign']['max_score'] = score
                        matches['benign']['closest_match'] = example

            matches['verdict']['max_score'] = max(matches['malicious']['max_score'], matches['benign']['max_score'])
            matches['verdict']['confidence'] = abs(matches['benign']['max_score'] - matches['malicious']['max_score'])

            if matches['verdict']['max_score'] != 0.0:
                if matches['benign']['max_score'] > matches['malicious']['max_score']:
                    matches['verdict']['label'] = 'benign'
                else:
                    matches['verdict']['label'] = 'malicious'

        return matches


    def get_closest_match_command_line(self, proc_command_line, proc_match, counter=False, timestamp=None):
        '''
        Given process executable name and command line arguments, find the command line argument examples that most closely match.
        '''
        matches = {}
        matches['malicious'] = {'max_score' : 0.0, 'closest_match' : ''}
        matches['benign'] = {'max_score' : 0.0, 'closest_match' : ''}
        matches['verdict'] = {'label' : 'inconclusive', 'confidence' : 100.0, 'max_score' : 0.0}

        # TF-IDF + Cosine Matching
        if 'tfidf' in proc_match.keys():
            # TF-IDF and Cosine Distance
            new_example = pd.DataFrame([{'proc_commandline': proc_command_line}])
            # Get vocab and tfidf from existing corpus
            vocab = proc_match['tfidf_vectorizer'].vocabulary_
            tfidf = proc_match['tfidf']
            df_examples = proc_match['tfidf_df']

            tfidf_vectorizer_new_example = TfidfVectorizer(vocabulary=vocab)
            tfidf_new_example = tfidf_vectorizer_new_example.fit_transform(new_example['proc_commandline'])
            cosine_similarities = linear_kernel(tfidf_new_example, tfidf).flatten()

            # Closest matches malicious and benign:
            mal_indicies = df_examples.index[df_examples.label == 'malicious']
            ben_indicies = df_examples.index[df_examples.label == 'benign']
            mal_similarities = cosine_similarities[df_examples.label == 'malicious']
            ben_similarities = cosine_similarities[df_examples.label == 'benign']
            if len(ben_similarities) > 0:
                # max index among the malicious examples
                max_ben_idx = ben_similarities.argsort()[-1]
                # translate max index for malicious examples to index of overall set of examples
                max_idx = ben_indicies[max_ben_idx]
                matches['benign']['max_score'] = cosine_similarities[max_idx]
                matches['benign']['closest_match'] = df_examples.iloc[max_idx]['proc_commandline']
            if len(mal_similarities) > 0:
                # max index among the malicious examples
                max_mal_idx = mal_similarities.argsort()[-1]
                # translate max index for malicious examples to index of overall set of examples
                max_idx = mal_indicies[max_mal_idx]
                matches['malicious']['max_score'] = cosine_similarities[max_idx]
                matches['malicious']['closest_match'] = df_examples.iloc[max_idx]['proc_commandline']

        else:
            labels = ['malicious', 'benign']
            for this_label in labels:
                label_key = '{}_command_line_examples'.format(this_label)

                if label_key in proc_match.keys():
                    number_examples = len(proc_match[label_key].keys())

                    if number_examples <= self.tfidf_corpus_limit:
                        # Not many examples, using Jaro distance instead
                        for example in proc_match[label_key].keys():
                            score = jaro_distance(proc_command_line, example)
                            if score > matches[this_label]['max_score']:
                                matches[this_label]['max_score'] = score
                                matches[this_label]['closest_match'] = example

        matches['verdict']['max_score'] = max(matches['malicious']['max_score'], matches['benign']['max_score'])
        matches['verdict']['confidence'] = abs(matches['benign']['max_score'] - matches['malicious']['max_score'])

        if matches['verdict']['max_score'] != 0.0:
            if matches['benign']['max_score'] > matches['malicious']['max_score']:
                matches['verdict']['label'] = 'benign'
            else:
                matches['verdict']['label'] = 'malicious'

        return matches

    def save_proc_chain_example(self, proc, proc_chain, label, last_seen=None):
        '''
        Manages how examples are saved and stored.
        :param proc: process name for ontology
        :param proc_chain: relationship to save
        :param label: whether the example is malicious or benign
        :return: None
        '''
        if last_seen is None:
            last_seen = datetime.now().date()
        try:
            if label == 'malicious':
                fieldname = 'mal_proc_chain_examples'
            if label == 'benign':
                fieldname = 'ben_proc_chain_examples'

            # Ensure 'ben_proc_chain_examples' and 'mal_proc_chain_examples' exsits as a key
            if fieldname not in self.ontology[proc].keys():
                self.ontology[proc][fieldname] = {}

            # Shouldn't happen, but confirm the proc_chain isn't already saved
            if proc_chain in self.ontology[proc][fieldname].keys():
                self.ontology[proc][fieldname][proc_chain]['cnt'] += 1
                self.ontology[proc][fieldname][proc_chain]['last_seen'] = last_seen
            else:
                self.ontology[proc][fieldname][proc_chain] = {'cnt': 1, 'last_seen': last_seen, 'first_seen' : last_seen}

        except Exception as e:
            print('Error saving {}: {}'.format(proc, e))

    def save_command_line_example(self, proc, proc_command_line, label, last_seen=None):
        '''
        Manages how examples are saved and stored.
        :param proc: process name for ontology
        :param proc_command_line: relationship to save
        :param label: whether the example is malicious or benign
        :return: None
        '''
        if last_seen is None:
            last_seen = datetime.now().date()
        try:
            fieldname = '{}_command_line_examples'.format(label)

            # Ensure 'ben_proc_chain_examples' and 'mal_proc_chain_examples' exsits as a key
            if fieldname not in self.ontology[proc].keys():
                self.ontology[proc][fieldname] = {}

            # Shouldn't happen, but confirm the proc_command_line isn't already saved
            if proc_command_line in self.ontology[proc][fieldname].keys():
                self.ontology[proc][fieldname][proc_command_line]['cnt'] += 1
                self.ontology[proc][fieldname][proc_command_line]['last_seen'] = last_seen
            else:
                self.ontology[proc][fieldname][proc_command_line] = {'cnt': 1, 'last_seen': last_seen, 'first_seen' : last_seen}

            if len(self.ontology[proc][fieldname].keys()) > self.tfidf_corpus_limit:
                # Collect all malicious and benign examples so we can add this one to the corpus and rebuild corpus
                temp_df = self.command_line_examples_to_df(proc)

                tfidf_vectorizer = TfidfVectorizer(token_pattern=r'(?u)\b[\w\/-]+\b', max_df=1.0, min_df=.05)
                tfidf = tfidf_vectorizer.fit_transform(temp_df['proc_commandline'])
                self.ontology[proc]['tfidf'] = tfidf
                self.ontology[proc]['tfidf_vectorizer'] = tfidf_vectorizer
                self.ontology[proc]['tfidf_df'] = temp_df

        except Exception as e:
            print('Error saving {}: {}'.format(proc, e))


    def command_line_examples_to_df(self, proc):
        '''
        Gathers the command line examples and returns a dataframe
        :param proc: process name in ontology
        :return: dataframe of malicious and benign examples with labels
        '''
        examples = []
        if 'benign_command_line_examples' in self.ontology[proc].keys():
            benign_examples = [{'label': 'benign', 'proc_commandline': x} for x in
                               self.ontology[proc]['benign_command_line_examples'].keys()]
            examples += benign_examples
        if 'malicious_command_line_examples' in self.ontology[proc].keys():
            malicious_examples = [{'label': 'malicious', 'proc_commandline': x} for x in
                                  self.ontology[proc]['malicious_command_line_examples'].keys()]
            examples += malicious_examples
        df = pd.DataFrame(examples)
        return df


    def learn_from_known_proc_chain(self, hash_val, label, proc, proc_chain, timestamp=None):
        if timestamp is None:
            timestamp = datetime.now().date()
        transformed_chain = self.transform_proc_chain_to_known(proc_chain)
        proc = proc.strip().lower()
        match = self.ontology.get(proc, {})

        if len(match) > 0:
            # Count number of times this process name is encountered
            if 'cnt' in match.keys():
                match['cnt'] += 1
                match['last_seen'] = timestamp
            else:
                match['first_seen'] = timestamp
                match['last_seen'] = timestamp
                match['cnt'] = 1

            case_match = self.get_closest_matches_proc_chain(proc_chain, match, counter=True, timestamp=timestamp)

            # If we haven't seen anything like this example, let's save it
            max_score = case_match['verdict']['max_score']
            # we have something new to learn
            if max_score < .9:
                self.save_proc_chain_example(proc, transformed_chain, label, timestamp)
            else:
                # We know something about this
                if case_match['verdict']['confidence'] > .7:
                    # pretty sure I know what's going on here
                    label = case_match['verdict']['label']

        return label


    def get_known_proc(self, proc):
        proc = proc.strip().lower()
        return self.ontology.get(proc, {})

    def transform_command_line(self, cmd_line):
        cmd_line = cmd_line.lower()
        path_file_pattern = r'.*?([a-zA-Z]*?\:\\|\\\\|\.\/)([a-zA-Z_\-\s0-9\.\\]*?)([a-zA-Z0-9_\-]+?)(\.[a-zA-Z0-9]*).*?'
        transformed_cmd_line = cmd_line
        matches = re.match(path_file_pattern, cmd_line)
        if matches:
            source = matches.group(1)
            path = matches.group(2)
            base_filename = matches.group(3)
            ext = matches.group(4)

            if source == '\\\\':
                source = '\\\\'
            elif len(source) == 3 and ':' in source and '\\' in source:
                # capture as some drive letter
                source = 'X:\\'
            elif source == './':
                # capture as current working directory
                source = 'CWD'
            else:
                # take it as it is
                source = source
            if path != '':
                path = 'some_path'
            transformed_segment = '{}\\{}\\some_file{}'.format(source, path, ext)
            transformed_cmd_line = cmd_line.replace('{}{}{}{}'.format(matches.group(1), matches.group(2), matches.group(3), matches.group(4)), transformed_segment)

        # print('{}  ===>>> {}'.format(cmd_line, transformed_cmd_line))
        return transformed_cmd_line


    def learn_from_known_command_line(self, hash_val, label, proc, proc_cmd_line, timestamp=None):
        if len(proc_cmd_line) <= 0:
            # Nothing to learn from this command line
            return label

        if timestamp is None:
            timestamp = datetime.now().date()

        proc = proc.strip().lower()
        match = self.ontology.get(proc, {})

        if len(match) > 0:
            transformed_command_line = self.transform_command_line(proc_cmd_line)
            # transformed_command_line = proc_cmd_line
            case_match = self.get_closest_match_command_line(transformed_command_line, match, counter=True, timestamp=timestamp)

            # If we haven't seen anything like this example, let's save it
            max_score = case_match['verdict']['max_score']
            # we have something new to learn
            if max_score < .8:
                self.save_command_line_example(proc, transformed_command_line, label, timestamp)
            else:
                # We know something about this
                if case_match['verdict']['confidence'] > .7:
                    # pretty sure I know what's going on here
                    label = case_match['verdict']['label']

        return label


    def learn_from_known(self, sample):
        hash_val = sample.get('sha1', 'none')
        label = sample.get('label', 'unknown')
        proc = sample.get('proc_name', '')
        proc_chain = sample.get('proc_chain', '')
        proc_commandline = sample.get('proc_commandline', '')
        timestamp = sample.get('analysis_start_time', '')

        if isinstance(timestamp, str):
            try:
                timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").date()
            except Exception as e:
                print('Error parsing date: {}'.format(timestamp, e))
                timestamp = None

        # if the command line is empty
        proc_match = self.get_known_proc(proc)
        if proc_commandline == '' and len(proc_match) == 0:
            return

        if label == 'benign' or label == 'malicious':
            # For now, we only learn from known good or known bad for single examples
            # print("About to try to learn from {}".format(hash_val))
            self.learn_from_known_proc_chain(hash_val, label, proc, proc_chain, timestamp)
            self.learn_from_known_command_line(hash_val, label, proc, proc_commandline, timestamp)


    def score_unknown(self, sample):

        return None


    def load_ontology(self, filepath):
        with open(filepath) as ontology_file:
            for line in ontology_file:
                try:
                    self.ontology = json.loads(line)
                except Exception as e:
                    print("Error loading ontology: {}".format(e))

        for key, info in self.ontology.items():
            info['proc_name'] = key
            if 'mal_proc_chain_examples' not in info.keys():
                info['mal_proc_chain_examples'] = {}
            if 'ben_proc_chain_examples' not in info.keys():
                info['ben_proc_chain_examples'] = {}

    def transform_proc_chain_to_known(self, chain):
        elements = chain.split('=>')
        transformed_chain = []
        for element in elements:
            element = element.strip().lower()
            if element in self.ontology.keys():
                transformed_chain.append(element)
            else:
                try:
                    ext = ntpath.splitext(element)[1]
                except Exception as e:
                    print("error: {}".format(e))
                    ext = ''
                ext = "unknown_process{}".format(ext)
                transformed_chain.append(ext)
        return ' => '.join(transformed_chain)

    def save_current_ontology(self, filename):
        ontology_to_df = []

        for name, item in self.ontology.items():
            if 'tid' in item.keys() and 'examples' in item.keys():
                ontology_to_df.append(
                    {'name': name, 'tid': item['attack_ids'], 'examples': ', '.join(item['examples'])})

        df = pd.DataFrame(ontology_to_df)
        df.to_csv(filename, index=False, header=True, encoding='utf-8')

        everything = filename.replace('.csv', '_all.json')
        with open(everything, 'w') as outfile:
            json.dump(self.ontology, outfile)

def get_filename(filepath):
    filename_pattern = r'^(.*?)\\([^\\\\]*)$'
    m = re.search(filename_pattern, filepath, re.IGNORECASE)
    filename_hit = m.group(1) if m else ""
    if filename_hit:
        filename = m.group(2) if m.group(1) else ""
        filepath=''
        filepath = m.group(1) if m.group(1) else ""
    else:
        filename = ''
        filepath = ''
    return filename.lower(), filepath.lower().replace('\\\\', '\\')


def get_logs(log_directory):
    all_log_files = [join(log_directory, f) for f in listdir(log_directory) if isfile(join(log_directory, f)) and '.csv' in f]
    all_log_files.sort()
    return all_log_files

def clean_up_ha_log_file(df):
    # retrieve the records that are not analyzing urls
    df = df[df['isurlanalysis'] == False]
    columns_agent = ['analysis_start_time', 'sha1', 'threatlevel_human',
                     'proc_uid', 'proc_parentuid', 'proc_name', 'proc_commandline',
                     'proc_chain', 'proc_chain_len']
    df = df[columns_agent]
    df = df.fillna('')
    df.rename(columns={'threatlevel_human': 'label'}, inplace=True)
    df.loc[df['label'] == 'no specific threat', 'label'] = 'benign'

    return df

def process_ha_logs(log_directory, ontology_file):
    all_log_files = get_logs(log_directory)
    wayfinder = Wayfinder(ontology_file)

    # Process Malware Logs
    for today in all_log_files:
        print(today)
        df = pd.read_csv(today)
        df = clean_up_ha_log_file(df)
        df.apply(wayfinder.learn_from_known, axis=1)

    pickle.dump(wayfinder.ontology, open('./wayfinder_last_run.pkl', 'wb'))
    print('COMPLETE')

def train_summary_to_elastic_search():
    es = Elasticsearch()

    ontology_file = './lol_mitre_mapping_all.json'
    log_directory = './parsed/'
    all_log_files = wf.get_logs(log_directory)
    wayfinder = wf.Wayfinder(ontology_file)

    es.indices.delete(index='test-index', ignore=[400, 404])

    for today in all_log_files:
        filename_pattern = r'^.*?\/(\d{4}-\d{2}-\d{2})_.*$'
        m = re.search(filename_pattern, today, re.IGNORECASE)
        if m:
            df = pd.read_csv(today)
            df = wf.clean_up_ha_log_file(df)
            df.apply(wayfinder.learn_from_known, axis=1)

            date_str = m.group(1)
            logfile_timestamp = datetime.strptime(date_str, '%Y-%m-%d').date()
            print("{} : {}".format(today, logfile_timestamp))
            for key, data in wayfinder.ontology.items():
                first_seen_today = 0
                ever_seen = 0
                first_seen = data.get('first_seen', None)
                if first_seen is not None:
                    ever_seen = 1
                    if abs(first_seen - logfile_timestamp).days < 1:
                        first_seen_today = 1
                lol_bas = 0
                if 'LOLBAS' in data.get('references', ''):
                    lol_bas = 1
                doc = {'proc_name': data['proc_name'], 'cnt': data.get('cnt', 0), 'first_seen_today': first_seen_today,
                       'ever_seen': ever_seen,
                       'timestamp': logfile_timestamp, 'lol_bas': lol_bas}
                res = es.index(index="test-index", doc_type='learning_rate', body=doc)

    summary_data = []
    for key, data in wayfinder.ontology.items():

        set_malicious = set()
        set_benign = set()
        for proc_chain, metadata in data['ben_proc_chain_examples'].items():
            set_benign.add(proc_chain)
        for proc_chain, metadata in data['mal_proc_chain_examples'].items():
            set_malicious.add(proc_chain)

        all_proc_chains = set_malicious.union(set_benign)

        for proc_chain in all_proc_chains:
            benign_cnt = 0
            malicious_cnt = 0
            if proc_chain in data['ben_proc_chain_examples'].keys():
                benign_cnt = data['ben_proc_chain_examples'][proc_chain]['cnt']
            if proc_chain in data['mal_proc_chain_examples'].keys():
                malicious_cnt = data['mal_proc_chain_examples'][proc_chain]['cnt']

            entry = {}
            entry['proc'] = key
            entry['proc_chain'] = proc_chain
            entry['cnt_mal'] = malicious_cnt
            entry['cnt_ben'] = benign_cnt
            entry['cnt'] = malicious_cnt + benign_cnt
            summary_data.append(entry)

    df = pd.DataFrame(summary_data)
    df.to_csv('./proc_chain_summary.csv', index=False, header=True)


if __name__ == '__main__':
    ontology_file = './lol_mitre_mapping_all.json'
    log_directory = './parsed/'
    process_ha_logs(log_directory, ontology_file)
