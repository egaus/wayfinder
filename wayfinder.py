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
from scipy import stats
import sys
import numpy as np
import collections

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

        # Keep command line argument buffer
        self.command_line_historic_sample_max_buffer = 2000
        self.command_line_historic_sample = []

        # TF-IDF
        self.tfidf_corpus_limit = 10 # if we have 5 or more examples, we will use tfidf + cosine matching instead of Jaro

    def get_closest_matches_proc_chain(self, proc_chain, proc_match, counter=False, timestamp=None):
        '''
        Given a process executable name, find the process chain that most closely matches the given proc_chain.
        :param proc_chain: Process chain to match on
        :param proc_match: This is the short-term memory process entry for the binary name
        :param counter: If true and the proc_chain provided is already known, it will increment it's counter in memory
        :return: matches dictionary with closest match, score, and confidence.
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
            # if we get malicious and benign hits, it is inconclusive
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


    def jaccard_similarity(self, tags1, tags2):
        print('make this awesome')
        return 0.0


    def get_closest_match_tags(self, tags, proc_match, counter=False, timestamp=None):
        '''
        Given a process executable name, find the process chain that most closely matches the given proc_chain.
        :param proc_chain: Process chain to match on
        :param proc_match: This is the short-term memory process entry for the binary name
        :param counter: If true and the proc_chain provided is already known, it will increment it's counter in memory
        :return: matches dictionary with closest match, score, and confidence.
        '''
        matches = {}
        matches['malicious'] = {'max_score' : 0.0, 'closest_match' : ''}
        matches['benign'] = {'max_score' : 0.0, 'closest_match' : ''}
        matches['verdict'] = {'label' : 'inconclusive', 'confidence' : 100.0, 'max_score' : 0.0}

        if 'mal_tag_examples' in proc_match.keys():
            for example in proc_match['mal_tag_examples'].keys():
                score = self.jaccard_similarity(tags, example)
                if score > matches['malicious']['max_score']:
                    matches['malicious']['max_score'] = score
                    matches['malicious']['closest_match'] = example

        if 'ben_tag_examples' in proc_match.keys():
            for example in proc_match['ben_proc_chain_examples'].keys():
                score = self.jaccard_similarity(tags, example)
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
            closest = {'malicious' : None, 'benign' : None}
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
                                closest[this_label] = example
            if closest['malicious'] is not None and matches['malicious']['max_score'] > .8:
                print('save this')


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


    def save_command_line_example_tags(self, proc, proc_command_line, tags, label, last_seen=None):
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

            tag_list = list(tags)
            tag_list.sort()
            tag_key = '; '.join(tag_list)

            # Ensure 'ben_proc_chain_examples' and 'mal_proc_chain_examples' exsits as a key
            if fieldname not in self.ontology[proc].keys():
                self.ontology[proc][fieldname] = {}

            # Shouldn't happen, but confirm the proc_command_line isn't already saved
            if tag_key in self.ontology[proc][fieldname].keys():
                self.ontology[proc][fieldname][tag_key]['cnt'] += 1
                self.ontology[proc][fieldname][tag_key]['last_seen'] = last_seen
                self.ontology[proc][fieldname][tag_key]['last_seen'] = last_seen
                self.ontology[proc][fieldname][tag_key]['examples'].append(proc_command_line)
            else:
                self.ontology[proc][fieldname][tag_key] = {'cnt': 1, 'last_seen': last_seen, 'first_seen' : last_seen, 'examples' : collections.deque(maxlen=5)}
                self.ontology[proc][fieldname][tag_key]['examples'].append(proc_command_line)

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
        """
        Given a process name like 'netsh.exe', returns the ontology structure (short term and long term memory)
        :param proc: process name e.g. netsh.exe
        :return: dictonary structure from working memory
        """
        proc = proc.strip().lower()
        return self.ontology.get(proc, {})


    def get_entropy(self, text):
        """
        Helper function to return entropy calculation value
        :param text: string
        :return: entropy of the set of values.
        """
        if len(text) < 1:
            return 0
        myseries = pd.Series(list(text))
        probs = myseries.value_counts() / len(myseries)
        entropy = stats.entropy(probs)
        return entropy

    def get_distribution_thresholds(self, data, tag):
        """
        Given a numpy list of values, returns threshold ranges to use for tagging such that 'very_low' is bottom 10%
        of the data, 'low' is the bottom 10%-25% of the data, 'typical' is values in 25% - 75% of the data, 'high' is
        75% - 90% of the highest values, and 'very_high' is the top 90%.
        :param data:
        :param tag:
        :return:
        """
        local_copy = data.copy()
        local_copy.sort()
        num_values = len(local_copy)

        if num_values < 10:
            thresholds = {'normal': {'idx': int(num_values * .75),
                                     'less_than': np.inf,
                                     'greater_than': -np.inf},
                          'tag': tag}
        else:
            thresholds = {'very_low': {'idx': int(num_values * .1),
                                       'less_than': local_copy[int(num_values * .1)]},
                          'low': {'idx': int(num_values * .25),
                                  'less_than': local_copy[int(num_values * .25)],
                                  'greater_than': local_copy[int(num_values * .1)]},
                          'normal': {'idx': int(num_values * .75),
                                     'less_than': local_copy[int(num_values * .75)],
                                     'greater_than': local_copy[int(num_values * .25)]},
                          'high': {'idx': int(num_values * .9),
                                   'less_than': local_copy[int(num_values * .9)],
                                   'greater_than': local_copy[int(num_values * .7)]},
                          'very_high': {'idx': num_values,
                                        'greater_than': local_copy[int(num_values * .9)]},
                          'tag': tag}

        return thresholds


    def tag_thresholds(self, datapoint, thresholds):
        """
        Checks the datapoint against the thresholds and returns the appropriate tag
        :param thresholds:
        :return:
        """
        tag = thresholds.get('tag', '')
        for category, threshold_data in thresholds.items():
            if category != 'tag':
                less_than = threshold_data.get('less_than', np.inf)
                greater_than = threshold_data.get('greater_than', -np.inf)
                if datapoint > greater_than and datapoint < less_than:
                    return '{}_{}'.format(category, tag)

        return 'not_in_range'

    def get_command_line_arg(self, arg):
        # Learn command line args.  If it starts with a '^-[a-zA-Z0-9\-]*?' or a '^--[a-zA-Z0-9\-]*?' or a '^/[a-zA-Z0-9\-]*?' or is composed of just '^[a-zA-Z0-9\-]$'.  Split on ':' and '='.  Take first.
        # '^--[a-zA-Z0-9\-]*?'
        # '^[a-zA-Z0-9\-]$'
        argument_pattern = '^(-[a-zA-Z0-9\-]{1,100}|[a-zA-Z0-9\-]{1,100}|--[a-zA-Z0-9\-]{1,100})(|:[a-zA-Z0-9\.\-]*|=[a-zA-Z0-9\.\-]*)$'
        matches = re.match(argument_pattern, arg)
        if matches:
            arg = arg.split(':')[0]
            arg = arg.split('=')[0]
            return arg
        else:
            return ''

    def get_protocol(self, command_line):
        # Need to fix this regex, but this works for now
        proto_pattern = '.*?\W([a-zA-Z0-9]{3,5})://.*?'
        m = re.findall(proto_pattern, command_line, re.IGNORECASE)
        tags = set()
        for entry in m:
            tags.add("proto_{}".format(entry))

        # See if we can catch obfuscation on http or https in the first 2000 or fewer characters.  This is an expensive regex.
        filename_pattern = r'h.*t.*t.*p.*:'
        m = re.search(filename_pattern, command_line[0:min(2000, len(command_line))], re.IGNORECASE)
        if m:
            tags.add('proto_http(s)_obf')

        return tags


    def get_tags(self, command_line, match):
        """
        Processes the command line value to identify and extract knowledge tags and learn command line arguments for this tool.
        :param command_line: text string of the command line
        :return: a set() of tags and set() of arguments
        """
        tags = set()
        command_line = command_line.lower()
        proto_tags = self.get_protocol(command_line)
        proc_commandline_parsed = self.cmdline_split(command_line, platform=0)
        args = set()
        entropy = self.get_entropy(command_line)
        str_length = len(command_line)
        entropy_tag = self.tag_thresholds(entropy, self.ontology['meta']['thresholds']['entropy'])
        str_len_tag = self.tag_thresholds(str_length, self.ontology['meta']['thresholds']['string_len'])
        tags.add(entropy_tag)
        tags.add(str_len_tag)

        for arg in proc_commandline_parsed:
            dir_tags = self.get_tags_directory(arg)
            [tags.add(tag) for tag in dir_tags]
            cmd_arg = self.get_command_line_arg(arg)
            if cmd_arg != '':
                args.add(cmd_arg)
                # Factor in command line arguments learned
                if 'args' in match.keys():
                    arg_cnt = match['args'].get(arg, 0)
                    # if we have seen this a ten times or at least 5% of the time, let's add it to our known arguments
                    if (float(arg_cnt) / match['args_cnt'] > .05) or arg_cnt > 10:
                        tags.add("arg_{}".format(arg))
                else:
                    tags.add("arg_{}".format(arg))

            # File Extensions
            arg_no_quotes = arg.replace('"','').replace("'",'').strip()
            filename, directory, extension = get_filename(arg_no_quotes)
            if extension != '':
                tags.add('ext_{}'.format(extension.replace('.','')))

        return tags, args


    def get_tags_directory(self, path):
        """
        Given a directory path, returns tags for each of the common paths it matches.
        :param path: Windows directory path
        :return: list of tags
        """
        path = path.lower()
        common_dirs = {
            '%windir%': {'match_type': 'exact_match', 'match_value': r'\windows'},
            'scheduled_task': {'match_type': 'exact_match', 'match_value': r'\windows\tasks'},
            '%userprofile%': {'match_type': 'regex', 'match_value': r'.*?\w:\\users\\[0-9a-zA-Z]{1,100}.*?'},
            '%tmp%': {'match_type': 'regex',
                      'match_value': r'.*?\w:\\Users\\[0-9a-zA-Z]{1,100}\\AppData\\Local\\Temp.*?'},
            '%temp%': {'match_type': 'regex',
                       'match_value': r'.*?\w:\\Users\\[0-9a-zA-Z]{1,100}\\AppData\\Local\\Temp.*?'},
            '%systemroot%': {'match_type': 'exact_match', 'match_value': r'\windows'},
            '%public%': {'match_type': 'exact_match', 'match_value': r'\users\public'},
            '%programfiles%': {'match_type': 'exact_match', 'match_value': r'\program files'},
            '%localappdata%': {'match_type': 'regex',
                               'match_value': r'.*?\w?:?\\users\\[0-9a-zA-Z]{1,100}\\appdata\\local.*?'},
            '%commonprogramfiles%': {'match_type': 'exact_match', 'match_value': r'\program files\common files'},
            '%appdata%': {'match_type': 'regex',
                          'match_value': r'.*?\w?:?\\users\\[0-9a-zA-Z]{1,100}\\appdata\\roaming.*?'},
            '%allusersprofile%': {'match_type': 'exact_match', 'match_value': r'\programdata'}
        }

        tags = set()

        for key, value in common_dirs.items():
            if key in path:
                tags.add('dir_{}'.format(key))
            if value['match_type'] == 'exact_match':
                if value['match_value'] in path:
                    tags.add('dir_{}'.format(key))
            if value['match_type'] == 'regex':
                if re.match(value['match_value'], path):
                    tags.add('dir_{}'.format(key))

        return list(tags)


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


    def learn_from_known_command_line(self, hash_val, label, proc, proc_cmd_line, proc_chain, timestamp=None):
        try:
            parent_process = proc_chain.split('=>')[-2].strip()
        except:
            parent_process = 'none'

        if len(proc_cmd_line) <= 0:
            # Nothing to learn from this command line
            return label

        if timestamp is None:
            timestamp = datetime.now().date()

        proc = proc.strip().lower()
        match = self.ontology.get(proc, {})

        if len(match) > 0:
            tags, args = self.get_tags(proc_cmd_line, match)
            if parent_process != 'none':
                if parent_process not in self.ontology.keys():
                    # TODO: Change this to get the actual extension of the unknown parent, rather than assuming a .exe
                    parent_process = "unknown_process.exe"
                tags.add("parentprocess_{}".format(parent_process))

            if 'args' not in match.keys():
                match['args_cnt'] = 1
                match['args'] = {}
            for arg in args:
                if arg in match['args'].keys():
                    match['args'][arg] += 1
                else:
                    match['args'][arg] = 1
            match['args_cnt'] += 1

            case_match = self.get_closest_match_tags(tags, match, counter=False, timestamp=None)

            max_score = case_match['verdict']['max_score']
            self.save_command_line_example_tags(proc, proc_cmd_line, tags, label, last_seen=None)

        return label


    def cmdline_split(self, s, platform='this'):
        """Multi-platform variant of shlex.split() for command-line splitting.
        For use with subprocess, for argv injection etc. Using fast REGEX.

        platform: 'this' = auto from current platform;
                  1 = POSIX;
                  0 = Windows/CMD
                  (other values reserved)
        """
        # THANK YOU kxr, this was a great solution! https://stackoverflow.com/questions/33560364/python-windows-parsing-command-lines-with-shlex
        if platform == 'this':
            platform = (sys.platform != 'win32')
        if platform == 1:
            RE_CMD_LEX = r'''"((?:\\["\\]|[^"])*)"|'([^']*)'|(\\.)|(&&?|\|\|?|\d?\>|[<])|([^\s'"\\&|<>]+)|(\s+)|(.)'''
        elif platform == 0:
            RE_CMD_LEX = r'''"((?:""|\\["\\]|[^"])*)"?()|(\\\\(?=\\*")|\\")|(&&?|\|\|?|\d?>|[<])|([^\s"&|<>]+)|(\s+)|(.)'''
        else:
            raise AssertionError('unkown platform %r' % platform)

        args = []
        accu = None  # collects pieces of one arg
        for qs, qss, esc, pipe, word, white, fail in re.findall(RE_CMD_LEX, s):
            if word:
                pass  # most frequent
            elif esc:
                word = esc[1]
            elif white or pipe:
                if accu is not None:
                    args.append(accu)
                if pipe:
                    args.append(pipe)
                accu = None
                continue
            elif fail:
                raise ValueError("invalid or incomplete shell string")
            elif qs:
                word = qs.replace('\\"', '"').replace('\\\\', '\\')
                if platform == 0:
                    word = word.replace('""', '"')
            else:
                word = qss  # may be even empty; must be last

            accu = (accu or '') + word

        if accu is not None:
            args.append(accu)

        return args


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
            self.learn_from_known_command_line(hash_val, label, proc, proc_commandline, proc_chain, timestamp)


    def get_all_rules(self, proc_name):
        if proc_name not in self.ontology.keys():
            return {'benign': [], 'malicious': [], 'num_malicious': 0,
                     'num_benign': 0, 'num_total': 0}
        mal = {}
        ben = {}
        if 'malicious_command_line_examples' in self.ontology[proc_name].keys():
            mal = self.ontology[proc_name]['malicious_command_line_examples']
        if 'benign_command_line_examples' in self.ontology[proc_name].keys():
            ben = self.ontology[proc_name]['benign_command_line_examples']

        total_malicious = 0
        total_benign = 0
        all_rules = {}
        malicious_rules = []
        benign_rules = []

        for tag, malicious in self.ontology[proc_name]['malicious_command_line_examples'].items():
            rule = set([x.strip() for x in tag.split(';')])
            entry = {'rule': rule, 'cnt': malicious['cnt']}
            total_malicious += malicious['cnt']
            malicious_rules.append(entry)

        for tag, benign in self.ontology[proc_name]['benign_command_line_examples'].items():
            rule = set([x.strip() for x in tag.split(';')])
            entry = {'rule': rule, 'cnt': benign['cnt']}
            total_benign += benign['cnt']
            benign_rules.append(entry)

        total_examples = total_benign + total_malicious
        all_rules = {'benign': benign_rules, 'malicious': malicious_rules, 'num_malicious': total_malicious,
                     'num_benign': total_benign, 'num_total': total_examples}

        return all_rules


    def learn_from_unknown(self, sample):
        print("hi")
        return None

    def load_ontology(self, filepath):
        with open(filepath) as ontology_file:
            for line in ontology_file:
                try:
                    self.ontology = json.loads(line)
                except Exception as e:
                    print("Error loading ontology: {}".format(e))

        for key, info in self.ontology.items():
            if key != 'meta':
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
    filename_pattern = r'^(.*?)\\([^\\\\]*?)(|\.[^\\\\]{2,4})$'
    m = re.search(filename_pattern, filepath, re.IGNORECASE)
    filename_hit = m.group(1) if m else ""
    if filename_hit:
        extension_hit = m.group(3) if m else ""
        filename = m.group(2) if m.group(1) else ""
        filepath=''
        filepath = m.group(1) if m.group(1) else ""
        if extension_hit != '':
            filename = '{}{}'.format(filename, extension_hit)
    else:
        # Need to fix this regex, but this works for now
        filename_pattern = r'^(\.\\|\\\\|)([^\\]*?)(\.[^\\\\]{2,4})$'
        m = re.findall(filename_pattern, filepath, re.IGNORECASE)
        for entry in m:
            return entry[0], entry[1], entry[2]
        filename = ''
        filepath = ''
        extension_hit = ''
    return filename.lower(), filepath.lower().replace('\\\\', '\\'), extension_hit


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

def train_from_ha_logs(log_directory, wayfinder, verbose=False):
    all_log_files = get_logs(log_directory)

    # Process Malware Logs
    cnt = 0
    for today in all_log_files:
        cnt += 1
        if verbose:
            print(today)
        df = pd.read_csv(today)
        df = clean_up_ha_log_file(df)
        # Target specific exe
        # df_temp = df[df.proc_name.str.contains('mshta.exe')].copy()
        # if len(df_temp) > 0:
        #     df_temp.apply(wayfinder.learn_from_known, axis=1)
        if len(df) > 0:
            df.apply(wayfinder.learn_from_known, axis=1)
        pickle.dump(wayfinder.ontology, open('./savepoints/{}_wayfinder_last_run.pkl'.format(cnt), 'wb'))

    pickle.dump(wayfinder.ontology, open('./complete_wayfinder_last_run.pkl', 'wb'))


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
    ontology_file = './ontology_tmp.json'
    log_directory = './parsed/'
    wayfinder = Wayfinder(ontology_file)
    train_from_ha_logs(log_directory, wayfinder, verbose=True)
    print('done')
