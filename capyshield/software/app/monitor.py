# TODO
# MONITORAR O TAMANHO DOS ARQUIVOS (SE VÁRIOS ARQUIVOS ESTÃO FICANDO MAIORES EM UM CURTO PERÍODO DE TEMPO)
# CHECAR OS BYTES MODIFICADOS PARA CHECAR SE ESTÃO CRIPTOGRAFADOS
# MONITORAR A QUANTIDADE DE MODIFICAÇÕES POR SEGUNDO NO TAMANHO DOS ARQUIVOS OU NOS HONEYPOTS
# MONITORAR SE ALGUM ARQUIVO MODIFICADO POSSUI UMA EXTENSÃO SUSPEITA/DESCONHECIDA
# ALGUMA FORMA DE REALIZAR BACKUP DOS ARQUIVOS/SISTEMA/REGISTRO ETC
# CRIAR NOVOS HONEYPOTS PARA NOVOS DIRETÓRIOS
# ATUALIZAR JSON QUANDO ARQUIVOS HONEYPOT SÃO MOVIDOS

import os
import pathlib
import re
import json
import logging
import hashlib
from os import name
from software.tools.logger import logger
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from software.config.shared_config import GeneralConfig as gc
from software.app.proc_killer import tryKillMaliciousProcess


# Classe FileSystemModifications, que herda a classe FileSystemEventHandler do watchdog
# event.src_path é basicamente o caminho que o handler retorna
class FileMonitor:
    def run(self):
        """Função para executar o file monitor"""
        global observers
        observers = []
        observer = Observer()
        event_handler = self.EventHandler()

        for directory in gc.selected_directories:
            observer.schedule(event_handler, directory, recursive=True)
            observers.append(observer)

        observer.start()

        global json_file_hashes
        global honeypot_names_data
        honeypot_names_data = []
        json_file_path = os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_file_name)
        honeypot_names_path = os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file)
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            try:
                with open(json_file_path) as json_file:
                    json_file_hashes = json.load(json_file)
            except FileNotFoundError:
                logger.error(f'Could not find {gc.json_file_name} in {gc.PATH_TO_CONFIG_FOLDER}')
                quit()
            try:
                with open(honeypot_names_path, "r") as names_file:
                    for line in names_file:
                        honeypot_names_data.append(line.rstrip())
            except FileNotFoundError:
                logger.error(f'Could not find {names_file} in {gc.PATH_TO_CONFIG_FOLDER}')
                quit()

        else:
            logger.error(f'Could not find {gc.json_file_name} in {gc.PATH_TO_CONFIG_FOLDER}')
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

    def isHonepot(event_path):
        if re.findall("([^\/]+$)", event_path)[0] in honeypot_names_data:
            return True

    class EventHandler(FileSystemEventHandler):
        # Monitorar modificações nos honeypots
        def on_modified(self, event):
            try:
                if FileMonitor.isHonepot(event.src_path):
                    for dict in json_file_hashes:
                        if event.src_path == dict['absolute_path']:
                            with open(event.src_path, 'rb') as honeypot_file:
                                file_data = honeypot_file.read()
                                current_hash = hashlib.sha1(file_data).hexdigest()
                                if current_hash != dict['hash']:
                                    logger.warning(f"Honeypot in {event.src_path} was modified!")
                                    tryKillMaliciousProcess(event.src_path)
                else:
                    pass

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
                        tryKillMaliciousProcess(event.src_path)

            except IndexError as e:
                pass

            except Exception as e:
                logger.error(e)
                pass

        def on_created(self, event):
            try:
                file_ext = pathlib.Path(re.findall("([^\/]+$)", event.src_path)[0]).suffix
                if not file_ext in gc.file_ext_list:
                    logger.warning(f"Unknow file extension detected ({file_ext}) in {event.src_path}!")
                    try:
                        tryKillMaliciousProcess(event.src_path)
                    except:
                        pass
            except:
                pass


# MAIN
if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
    logging.getLogger("watchdog.observers.inotify_buffer").disabled = True
