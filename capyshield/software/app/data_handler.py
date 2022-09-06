import hashlib
import os
import json
import pathlib
import re
import time
from software.tools.logger import logger
from software.config.shared_config import GeneralConfig as gc


class DataCreator:
    def generateHoneypotsJson(honeypot_files_hash_list):
        """Função para gerar o JSON com as entradas de cada honeypot"""
        logger.debug("Generating JSON file")
        json_object = json.dumps(honeypot_files_hash_list, indent=4)

        if not os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            os.makedirs(gc.PATH_TO_CONFIG_FOLDER)

        with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name), 'w') as json_file:
            json_file.write(json_object)

    #

    def generateHoneypotNamesTxt(honeypot_names_list):
        """Função para gerar o .txt com os nomes de cada honeypot"""
        logger.debug("Generating Honeypot names file")
        if not os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            os.makedirs(gc.PATH_TO_CONFIG_FOLDER)

        with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'w') as names_file:
            for name in honeypot_names_list:
                names_file.write(f"{name}\n")

    #

    def generateHoneypotDataDict(honeypot_file):
        """Função para gerar uma hash para o arquivo de honeypot criado"""
        file_data = honeypot_file.read()
        readable_hash = hashlib.sha1(file_data).hexdigest()

        honeypot_file_hash_dict = {
            "absolute_path": honeypot_file.name,
            "hash": readable_hash
        }
        return honeypot_file_hash_dict


class DataRemover:
    def deleteHoneypotsJson():
        """Função deletar o JSON com as entradas de cada honeypot"""
        logger.debug("Deleting JSON file")
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            try:
                os.remove(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name))
            except FileNotFoundError:
                logger.error(f'Could not find {gc.json_honeypot_data_file_name} in {gc.PATH_TO_CONFIG_FOLDER}')
                quit()

    def deleteHoneypotNamesTxt():
        """Função para deletar o arquivo com os nomes dos honeypots"""
        logger.debug("Deleting Honeypot names file")
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            try:
                os.remove(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file))
            except FileNotFoundError:
                logger.error(f'Could not find {gc.honeypot_names_file} in {gc.PATH_TO_CONFIG_FOLDER}')

    #


class DataUpdater:
    def getJsonData(json_file):
        try:
            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file)) as f:
                json_file_data = json.load(f)
            return json_file_data

        except FileNotFoundError:
            logger.error(f'Could not find {gc.json_honeypot_data_file_name} in {gc.PATH_TO_CONFIG_FOLDER}')
            quit()

    #

    def getTxtData(json_file):
        try:
            honeypot_names_data = []
            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file), "r") as names_file:
                for line in names_file:
                    honeypot_names_data.append(line.rstrip())
                return honeypot_names_data

        except Exception as e:
            logger.error(e)

    #

    def updateCreate(honeypot_dicts, json_file_name):
        """"""
        start = time.perf_counter()
        try:
            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file_name), 'r') as f:
                data = json.load(f)

            for honeypot_dict in honeypot_dicts:
                data.append(honeypot_dict)

            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file_name), "w") as f:
                json.dump(data, f)

            if gc.random_honeypot_file_name:
                for honeypot_dict in honeypot_dicts:
                    honeypot_file_name = pathlib.Path(re.findall("([^\/]+$)", honeypot_dict['absolute_path'])[0])
                    DataUpdater.updateHoneypotNamesTxt([honeypot_file_name], 'create')

            end = time.perf_counter()
            logger.debug(f"Updated JSON for CREATE event in {round(end - start, 3)}s")

        except Exception as e:
            logger.error(e)

    #

    def updateDelete(event_paths, json_file_name, json_file_data):
        """"""
        start = time.perf_counter()
        names_to_delete = []

        try:
            new_json_file_data = []
            for i, element in enumerate(json_file_data):
                for path in event_paths:
                    if str(path) not in (element['absolute_path']):
                        new_json_file_data.append(element)
                    else:
                        names_to_delete.append(re.findall("([^\/]+$)", element['absolute_path'])[0])

            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file_name), 'w') as f:
                f.write(json.dumps(new_json_file_data, indent=4))

            end = time.perf_counter()
            logger.debug(f"Updated JSON for DELETE event in {round(end - start, 3)}s")

            if gc.random_honeypot_file_name:
                DataUpdater.updateHoneypotNamesTxt(names_to_delete, "delete")

        except Exception as e:
            logger.error(e)

    #

    def updateHoneypotNamesTxt(honeypot_names, action):
        if gc.random_honeypot_file_name:
            if action == "create":
                try:
                    with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'a') as f:
                        for honeypot_name in honeypot_names:
                            f.write(f"{honeypot_name}\n")
                except Exception as e:
                    logger.error(e)

            elif action == "delete":
                try:
                    new_name_list = []
                    has_delete_num = False

                    with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'r') as f:
                        names_in_file = [name.rstrip() for name in f]

                    with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'w') as f:
                        for name in names_in_file:
                            for honeypot_name in honeypot_names:
                                if name == honeypot_name:
                                    has_delete_num = True
                            if not has_delete_num:
                                new_name_list.append(name)
                            has_delete_num = False

                        for name in new_name_list:
                            f.write(f"{name}\n")

                except Exception as e:
                    logger.error(e)
        else:
            pass
