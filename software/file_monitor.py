# TODO
# MONITORAR O TAMANHO DOS ARQUIVOS (SE VÁRIOS ARQUIVOS ESTÃO FICANDO MAIORES EM UM CURTO PERÍODO DE TEMPO)
# CHECAR OS BYTES MODIFICADOS PARA CHECAR SE ESTÃO CRIPTOGRAFADOS
# MONITORAR A QUANTIDADE DE MODIFICAÇÕES POR SEGUNDO NO TAMANHO DOS ARQUIVOS OU NOS HONEYPOTS
# MONITORAR SE ALGUM ARQUIVO MODIFICADO POSSUI UMA EXTENSÃO SUSPEITA/DESCONHECIDA
# ALGUMA FORMA DE REALIZAR BACKUP DOS ARQUIVOS/SISTEMA/REGISTRO ETC
# CRIAR NOVOS HONEYPOTS PARA NOVOS DIRETÓRIOS
# ATUALIZAR JSON QUANDO ARQUIVOS HONEYPOT SÃO MOVIDOS

import os
import re
import json
import logging
import hashlib
from os import name
from software.logger import logger
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from software.proc_killer import tryKillMaliciousProcess


# Classe FileSystemModifications, que herda a classe FileSystemEventHandler do watchdog
# event.src_path é basicamente o caminho que o handler retorna
class FileMonitor:
    def __init__(self, directory_list, honeypot_file_name, path_to_config_folder, json_file_name, honeypot_names_file, audit_obj, path_to_main_folder, audit_custom_rules_key, audit_custom_rules_shell_key):
        self.directory_list = directory_list
        self.honeypot_file_name = honeypot_file_name
        self.path_to_config_folder = path_to_config_folder
        self.json_file_name = json_file_name
        self.honeypot_names_file = honeypot_names_file
        self.audit_obj = audit_obj,
        self.path_to_main_folder = path_to_main_folder
        self.audit_custom_rules_key = audit_custom_rules_key
        self.audit_custom_rules_shell_key = audit_custom_rules_shell_key

    def isHonepot():
        re.findall("([^\/]+$)", event.src_path)[0] in honeypot_names_data

    class EventHandler(FileSystemEventHandler):
        def __init__(self, data):
            self.directory_list = data[0]
            self.honeypot_file_name = data[1]
            self.path_to_config_folder = data[2]
            self.json_file_name = data[3],
            self.audit_obj = data[4]
            self.path_to_main_folder = data[5]
            self.audit_custom_rules_key = data[6]
            self.audit_custom_rules_shell_key = data[7]
        
        # Monitorar modificações nos honeypots
        def on_modified(self, event):
            try:
                if isHoneypot:
                    if re.findall("([^\/]+$)", event.src_path)[0] in honeypot_names_data:
                        for dict in json_file_hashes:
                            if event.src_path == dict['absolute_path']:
                                with open(event.src_path, 'rb') as honeypot_file:
                                    file_data = honeypot_file.read()
                                    current_hash = hashlib.md5(file_data).hexdigest()
                                    if current_hash != dict['hash']:
                                        logger.warning(f"Honeypot in {event.src_path} was modified!")
                                        tryKillMaliciousProcess(self.path_to_main_folder, self.audit_custom_rules_key, self.audit_custom_rules_shell_key)
                else:

            except IndexError as e:
                pass

            except Exception as e:
                logger.error(e)
                pass

        # Monitorar caso algum diretório seja mudado de lugar, para atualizar o JSON dos honeypots
        def on_moved(self, event):
            logger.debug("Moved " + event.src_path)

        # Monitorar se algum diretório for deletado, para remover as entradas dos mesmos no JSON dos honeypots
        def on_deleted(self, event):
            try:
                if re.findall("([^\/]+$)", event.src_path)[0] in honeypot_names_data:
                    if not os.path.exists(event.src_path):
                        logger.warning(f"Honeypot in {event.src_path} was deleted!")
                        tryKillMaliciousProcess(self.path_to_main_folder, self.audit_custom_rules_key, self.audit_custom_rules_shell_key)

            except IndexError as e:
                pass

            except Exception as e:
                logger.error(e)
                pass

    def run(self):
        """Função para executar o file monitor"""
        global observers
        observers = []
        observer = Observer()
        event_handler = self.EventHandler([self.directory_list, self.honeypot_file_name, self.path_to_config_folder, self.json_file_name, self.audit_obj, self.path_to_main_folder, self.audit_custom_rules_key, self.audit_custom_rules_shell_key])

        for directory in self.directory_list:
            observer.schedule(event_handler, directory, recursive=True)
            observers.append(observer)

        observer.start()

        global json_file_hashes
        global honeypot_names_data
        honeypot_names_data = []
        json_file_path = os.path.join(self.path_to_config_folder, self.json_file_name)
        honeypot_names_path = os.path.join(self.path_to_config_folder, self.honeypot_names_file)
        if os.path.exists(self.path_to_config_folder):
            try:
                with open(json_file_path) as json_file:
                    json_file_hashes = json.load(json_file)
            except FileNotFoundError:
                logger.error(f'Could not find {self.json_file_name} in {self.path_to_config_folder}')
                quit()
            try:
                with open(honeypot_names_path, "r") as names_file:
                    for line in names_file:
                        honeypot_names_data.append(line.rstrip())
            except FileNotFoundError:
                logger.error(f'Could not find {names_file} in {self.path_to_config_folder}')
                quit()

        else:
            logger.error(f'Could not find {self.json_file_name} in {self.path_to_config_folder}')
            quit()

        logger.debug('File Monitor has started...')
        try:
            while True:
                continue
        except KeyboardInterrupt:
            for observer in observers:
                observer.unschedule_all()
                observer.stop()
                observer.join()


# MAIN
if __name__ == "__main__":
    pass
else:
    from software.logger import logger
    logging.getLogger("watchdog.observers.inotify_buffer").disabled = True
