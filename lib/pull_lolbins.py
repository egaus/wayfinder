from git import Repo
import shutil
import os
from glob import glob
import re
import logging
logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)

def git_project(dir_path, git_url):
    '''

    :param dir_path:
    :param git_url:
    :return:
    '''
    try:
        result = Repo.clone_from(git_url, dir_path)
    except Exception as e:
        logging.error("{} : {}".format(e, result))

def remove_directory(dir_path):
    '''
    Deletes a directory and subdirectory
    :param dir_path: path to delete
    :return: nothing
    '''
    try:
        shutil.rmtree(dir_path)
    except OSError as e:
        logging.error("Directory {} : {}".format(e.filename, e.strerror))


def identify_relevant_lolbin_files(dir_path):
    '''
    Determines which files in the directory are .md files to include in scope to parse.
    :param dir_path: path to cloned lolbin repo
    :return: list of lolbin .md files
    '''
    all_files = [y for x in os.walk(dir_path) for y in glob(os.path.join(x[0], '*.md'))]

    paths = ['OtherScripts',
    'OtherMSBinaries',
    'OSScripts',
    'OSLibraries',
    'OSBinaries']
    # Note: intentionally omitting "OtherBinaries" lolbins for the time being.

    lolbin_files = set()
    for filename in all_files:
        for path in paths:
            if path in filename:
                lolbin_files.add(filename)
    return lolbin_files


def retrieve_lolbins(dir_path, clear_cache = False):
    '''
    Optionally clears local lolbins cache and retrieves fresh data from the project and parses them into a dictionary
    :param dir_path: path to local cache directory
    :param clear_cache: if True, will delete the dir_path directory and pull down a fresh copy of the repo
    :return: list of dictionaries, each representing a lolbin
    '''
    if clear_cache:
        git_url = 'https://github.com/api0cradle/LOLBAS.git'
        remove_directory(dir_path)
        git_project(dir_path, git_url)

    lolbin_files = identify_relevant_lolbin_files(dir_path)

    lol_bins = []
    title_regex = re.compile("^##(.*)$", re.IGNORECASE)
    functions_regex = re.compile("Functions:(.*)$", re.IGNORECASE)

    for lol_file in lolbin_files:
        with open(lol_file) as fp:
            lol_bin = {'name' : '', 'functions' : [], 'examples': []}
            capture_examples = False
            examples_gathered = False
            functions_gathered = False
            for cnt, line in enumerate(fp):
                line = line.strip()
                if capture_examples:
                    if '```' in line:
                        capture_examples = False
                        examples_gathered = True
                    else:
                        if len(line) > 0:
                            lol_bin['examples'].append(line)

                # Capture Name
                m = title_regex.search(line)
                if m and lol_bin['name'] == '':
                    name = m.group(1)
                    lol_bin['name'] = name.strip().lower()

                # Capture Functions
                m = functions_regex.search(line)
                if m and len(lol_bin['functions']) == 0:
                    functions = m.group(1)
                    functions_parsed = functions.strip().split(',')
                    lol_bin['functions'] = [func.strip() for func in functions_parsed]
                    functions_gathered = True

                # Capture Examples
                if '```' in line and lol_bin['examples'] != '' and functions_gathered:
                    capture_examples = True

                if lol_bin['name'] != '' and len(lol_bin['functions']) > 0 and examples_gathered:
                    break
        lol_bin['link'] = 'https://github.com/api0cradle/LOLBAS/blob/master' + lol_file.replace(dir_path, '').replace('\\', '/')
        logging.info(lol_bin)

        lol_bins.append(lol_bin)

    return lol_bins


if __name__ == '__main__':
    dir_path = './lolbins'
    lolbins = retrieve_lolbins(dir_path)
    print("Retrieved lolbins and parsed {}".format(len(lolbins)))
