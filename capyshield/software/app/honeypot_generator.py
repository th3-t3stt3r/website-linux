import json
import os
import time
from software.app.audit import Audit
from software.tools.logger import logger
from software.tools.utils import returnPercentage, randomString
from software.config.shared_config import GeneralConfig as gc
from software.app.data_handler import generateJson, deleteJson, generateHoneypotNamesList, deleteHoneypotNamesList, generateHoneypotDataDict


def start():
    global hg
    hg = HoneypotGenerator()
    hg.run()


class HoneypotGenerator:
    """Classe do Gerador de Honeypots"""

    def __init__(self):
        if gc.honeypot_interval <= 1 and not gc.disable_honeypot_interval:
            logger.error('"Disable Honeyppot Interval" is off, Honeypot interval should be 2 or greater!')
            quit()

        if gc.honeypot_interval >= 2 and gc.disable_honeypot_interval:
            logger.error(f'"Disable Honeyppot Interval" is on, changing the "Honeypot Interval" from {gc.HONEYPOT_INTERVAL} to 1')
            gc.honeypot_interval = 1
            quit()

    #

    def __generateHoneypots(self):
        """Função para gerar os honeypots"""
        honeypots_dict_list = []
        honeypot_names_list = []
        total_created_count = 0

        Audit.createCustomRuleFile()

        start = time.perf_counter()
        for directory in gc.selected_directories:
            directory_count = 0

            for root in os.walk(directory):
                directory_count += 1

            logger.debug(f"Creating honeypots in {directory}")
            logger.debug(f"There are {directory_count} subdirectories inside {directory}")
            logger.debug(f"The honeypot creation interval is set to: {gc.honeypot_interval if not gc.disable_honeypot_interval else 'disabled'}")

            if directory_count == 0:
                directory_count = 1
            logger.debug(f"It will be created {round(directory_count / gc.honeypot_interval) if not gc.disable_honeypot_interval else directory_count} honeypots")

            percentage = 0.1
            created_count = 0
            directory_walk_count = 0
            for current_path, _, _ in os.walk(directory):
                if directory_walk_count % gc.honeypot_interval == 0 or created_count == 0 or gc.honeypot_interval == 1 and gc.disable_honeypot_interval:
                    try:
                        if os.access(current_path, os.W_OK):
                            if gc.random_honeypot_file_name:
                                gc.honeypot_file_name = ("." if gc.hidden_honeypot_file else "") + randomString("unique-name")

                            honeypot_names_list.append(gc.honeypot_file_name)

                            # Criar o honeypot
                            with open(os.path.join(current_path, gc.honeypot_file_name), 'w') as honeypot_file:
                                honeypot_file.write("THIS IS A PYTHON RANSOMWARE DETECTOR FILE! PLEASE! DO NOT MOVE, DELETE, RENAME OR MODIFY THIS FILE!\n")
                                honeypot_file.write(f"Unique string for this file: {randomString('unique-hash')}")

                            # Gerar a hash para o honeypot criado
                            with open(os.path.join(current_path, gc.honeypot_file_name), 'rb') as honeypot_file:
                                honeypots_dict_list.append(generateHoneypotDataDict(honeypot_file))

                            created_count += 1

                    except Exception as e:
                        logger.error(e)
                        continue

                directory_walk_count, percentage = returnPercentage(directory_count, directory_walk_count, percentage)

            logger.debug(f"Created a total of {round(created_count)} honeypots in {directory}")
            total_created_count = total_created_count + created_count

        end = time.perf_counter()
        logger.debug(f"Created honeypots in {round(end - start, 3)}s")

        if total_created_count == 0:
            logger.error("No honeypots were created in any directories. Quitting...")
            quit()

        Audit.createAuditRule(directory)
        Audit.loadRules()

        generateJson(honeypots_dict_list)

        if gc.random_honeypot_file_name:
            generateHoneypotNamesList(honeypot_names_list)
        else:
            generateHoneypotNamesList(gc.honeypot_file_name)

    #

    def __deleteHoneypots():
        """Função para deletar todos os honeypots"""
        try:
            json_paths_list = []
            json_file_path = os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_file_name)
            with open(os.path.join(json_file_path)) as tmp_json_file:
                json_file = json.load(tmp_json_file)
                for dict in json_file:
                    if dict['absolute_path']:
                        json_paths_list.append(dict['absolute_path'])
        except FileNotFoundError:
            logger.error(f'Could not find {gc.json_file_name} in {gc.PATH_TO_CONFIG_FOLDER}. Without this file is impossible to properly delete the honeypots')
            quit()

        start = time.perf_counter()
        for directory in gc.selected_directories:
            directory_count = 0
            for root in os.walk(directory):
                directory_count += 1

            percentage = 0.1
            deleted_count = 0
            directory_walk_count = 0

            logger.debug(f"Deleting honeypots in: {directory}")
            for current_path, _, files_in_current_path in os.walk(directory):
                try:
                    if os.access(current_path, os.W_OK):
                        for file in files_in_current_path:
                            file_absolute_path = os.path.join(current_path, file)
                            if file_absolute_path in json_paths_list:
                                os.remove(file_absolute_path)
                                deleted_count += 1
                        directory_walk_count, percentage = returnPercentage(directory_count, directory_walk_count, percentage)
                except Exception as e:
                    logger.error(e)
                    # logger.error(f'Found an error in {current_path}: {str(e.__class__.__name__)}')
                    continue
            if deleted_count == 0:
                logger.debug(f"No honeypots where found to be deleted")
            else:
                logger.debug(f"Deleted a total of {round(deleted_count)} honeypots in {directory}")

        end = time.perf_counter()
        logger.debug(f"Deleted honeypots in {round(end - start, 3)}s")

        # Deletar o arquivo e as regras de audit
        Audit.deleteCustomRuleFileAndRules(round(deleted_count))

        # Deletar o JSON das hashes
        deleteJson()
        deleteHoneypotNamesList()

    #

    def run(self):
        """Função para criar ou deletar os honeypots"""
        start = time.perf_counter()
        # CRIAR HONEYPOTS
        if not gc.delete_honeypots:
            self.__generateHoneypots()

        # DELETAR HONEYPOTS
        elif gc.delete_honeypots:
            self.__deleteHoneypots()
        end = time.perf_counter()
        logger.debug(f"{'Created' if not gc.delete_honeypots else 'Deleted'} honeypots and rules in {round(end - start, 3)}s")


# MAIN
if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
