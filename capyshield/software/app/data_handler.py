import hashlib
import os
import json
import time
from software.tools.logger import logger
from software.config.shared_config import GeneralConfig as gc


def generateJson(honeypot_files_hash_list):
    """Função para gerar o JSON com as entradas de cada honeypot"""
    logger.debug("Generating JSON file")
    json_object = json.dumps(honeypot_files_hash_list, indent=4)

    if not os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
        os.makedirs(gc.PATH_TO_CONFIG_FOLDER)

    with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name), 'w') as json_file:
        json_file.write(json_object)


def deleteJson():
    """Função deletar o JSON com as entradas de cada honeypot"""
    logger.debug("Deleting JSON file")
    if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
        try:
            os.remove(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name))
        except FileNotFoundError:
            logger.error(f'Could not find {gc.json_honeypot_data_file_name} in {gc.PATH_TO_CONFIG_FOLDER}')
            quit()


def getJsonFileData(json_file):
    try:
        with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file)) as f:
            json_file_data = json.load(f)
        return json_file_data

    except FileNotFoundError:
        logger.error(f'Could not find {gc.json_honeypot_data_file_name} in {gc.PATH_TO_CONFIG_FOLDER}')
        quit()


def getHoneypotNamesFileData(json_file):
    try:
        honeypot_names_data = []
        with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file), "r") as names_file:
            for line in names_file:
                honeypot_names_data.append(line.rstrip())
            return honeypot_names_data

    except Exception as e:
        logger.error(e)


def generateHoneypotDataDict(honeypot_file):
    """Função para gerar uma hash para o arquivo de honeypot criado"""
    file_data = honeypot_file.read()
    readable_hash = hashlib.sha1(file_data).hexdigest()

    honeypot_file_hash_dict = {
        "absolute_path": honeypot_file.name,
        "hash": readable_hash
    }
    return honeypot_file_hash_dict


def generateHoneypotNamesList(honeypot_names_list):
    """Função para gerar o .txt com os nomes de cada honeypot"""
    logger.debug("Generating Honeypot names file")
    if not os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
        os.makedirs(gc.PATH_TO_CONFIG_FOLDER)

    with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'w') as names_file:
        if gc.random_honeypot_file_name:
            for name in honeypot_names_list:
                names_file.write(f"{name}\n")
        else:
            names_file.write(gc.honeypot_file_name)


def deleteHoneypotNamesList():
    """Função para deletar o arquivo com os nomes dos honeypots"""
    logger.debug("Deleting Honeypot names file")
    if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
        try:
            os.remove(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file))
        except FileNotFoundError:
            logger.error(f'Could not find {gc.honeypot_names_file} in {gc.PATH_TO_CONFIG_FOLDER}')


def updateHoneypotData(event_path, json_file_name, json_file_data, action):
    """"""
    start = time.perf_counter()
    if action == "delete":
        try:
            for i, obj in enumerate(json_file_data):
                if obj['absolute_path'] == event_path:
                    json_file_data.pop(i)

            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file_name), 'w') as f:
                f.write(json.dumps(json_file_data, indent=4))

            end = time.perf_counter()
            print(f"Updated JSON in {round(end - start, 3)}s")

            return json_file_data
        except Exception as e:
            print(e)
