# TODO
# MONITORAR O TAMANHO DOS ARQUIVOS (SE VÁRIOS ARQUIVOS ESTÃO FICANDO MAIORES EM UM CURTO PERÍODO DE TEMPO)
# CHECAR OS BYTES MODIFICADOS PARA CHECAR SE ESTÃO CRIPTOGRAFADOS
# MONITORAR A QUANTIDADE DE MODIFICAÇÕES POR SEGUNDO NO TAMANHO DOS ARQUIVOS OU NOS HONEYPOTS
# ALGUMA FORMA DE REALIZAR BACKUP DOS ARQUIVOS/SISTEMA/REGISTRO ETC

import os
import pathlib
import re
import logging
import hashlib
import time
from software.tools.logger import logger
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from software.config.shared_config import GeneralConfig as gc
from software.app.honeypot_generator import generateSingleHoneypot
from software.app.data_handler import DataUpdater
from software.app.proc_killer import ProcessKiller

# Classe FileSystemModifications, que herda a classe FileSystemEventHandler do watchdog
# event.src_path é basicamente o caminho que o handler retorna


def start():
    global fm
    fm = FileMonitor()
    fm.run()


class FileMonitor:
    """Classe do Monitor"""

    def __init__(self):
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            self.started = False
            self.start_protection_time = time.time()
            self.json_honeypot_data_file_data = DataUpdater.getJsonData(gc.json_honeypot_data_file_name)
            self.honeypot_names_file_data = DataUpdater.getTxtData(gc.honeypot_names_file)
            self.honeypots_to_delete = []
            self.honeypots_to_update = []
            self.honeypots_to_create = []
            self.has_delete_changes = False
            self.has_update_changes = False
            self.has_create_changes = False
        else:
            logger.error(f'Could not find {gc.json_file_name} in {gc.PATH_TO_CONFIG_FOLDER}')
            quit()

     #

    def run(self):
        """Função para executar o file monitor"""
        observers = []
        observer = Observer()
        event_handler = self.EventHandler()

        for directory in gc.selected_directories:
            observer.schedule(event_handler, directory, recursive=True)
            observers.append(observer)

        observer.start()

        try:
            current_time = time.time()
            while True:
                if not self.started:
                    if (time.time() - self.start_protection_time) > 5:
                        logger.debug('File Monitor has started')
                        logger.debug(f'Currently monitoring {len(gc.selected_directories)} directories')
                        self.started = True

                new_time = time.time() - current_time
                if new_time > gc.file_update_interval:
                    self.updateAllData()
                    self.checkForChangesAndUpdate()
                    current_time = time.time()

                continue

        except KeyboardInterrupt:
            logger.debug("Stopping File Monitor")
            for observer in observers:
                observer.unschedule_all()
                observer.stop()
                observer.join()
            logger.debug("Updating Honeypots JSON file before exit")
            self.checkForChangesAndUpdate()

    #

    def isHonepot(self, event_path):
        if re.findall("([^\/]+$)", event_path)[0] in self.honeypot_names_file_data:
            return True

    #

    def updateAllData(self):
        fm.json_honeypot_data_file_data = DataUpdater.getJsonData(gc.json_honeypot_data_file_name)
        fm.honeypot_names_file_data = DataUpdater.getTxtData(gc.honeypot_names_file)

    #

    def checkForChangesAndUpdate(self):
        if self.has_create_changes:
            DataUpdater.updateCreate(self.honeypots_to_create, fm.honeypots_to_update, fm.json_honeypot_data_file_data)
            self.updateAllData()
            self.has_create_changes = False
            self.honeypots_to_create = []

        if self.has_update_changes:
            DataUpdater.updateMoveOrRename(self.honeypots_to_update, fm.json_honeypot_data_file_data)
            self.updateAllData()
            self.has_update_changes = False
            self.honeypots_to_update = []

        if self.has_delete_changes:
            DataUpdater.updateDelete(self.honeypots_to_delete, fm.json_honeypot_data_file_data)
            self.updateAllData()
            self.has_delete_changes = False
            self.honeypots_to_delete = []

    class EventHandler(FileSystemEventHandler):
        """Classe com funções de event handler"""

        def __init__(self):
            self.unknow_extension_event_count = 0
            self.honeypot_deleted_event_count = 0
            self.folder_with_honeypots_deleted_event_count = 0
            self.honeypot_modified_event_count = 0
            self.create_current_time = time.time()
            self.delete_current_time = time.time()
            self.modify_current_time = time.time()
            self.ransom_create_check_time = time.time()
            self.ransom_delete_check_time = time.time()
            self.ransom_modify_check_time = time.time()
            self.check_ransom = False

        #

        def on_created(self, event):
            try:
                if os.path.isdir(event.src_path):
                    new_honeypot_dict = generateSingleHoneypot(event.src_path)
                    if new_honeypot_dict:
                        fm.honeypots_to_create.append(new_honeypot_dict)
                        fm.has_create_changes = True

                else:
                    has_know_ext = False
                    file_ext = pathlib.Path(re.findall("([^\/]+$)", event.src_path)[0]).suffix

                    if file_ext in gc.file_ext_list:
                        has_know_ext = True

                    if not has_know_ext and not file_ext == "":
                        new_time = time.time() - self.create_current_time
                        self.unknow_extension_event_count += 1

                        if new_time > 1:
                            logger.warning(f"Unknow file extension detected \"{file_ext}\" {'' if self.unknow_extension_event_count <= 1 else '(and ' + str(self.unknow_extension_event_count) + ' more)'}")

                            if self.unknow_extension_event_count > gc.unknow_extension_event_count_trigger or gc.immediate_mode:
                                self.check_ransom = True

                            self.create_current_time = time.time()
                            self.unknow_extension_event_count = 0

                        if self.check_ransom:
                            new_ransom_create_check_time = time.time() - self.ransom_create_check_time
                            if new_ransom_create_check_time > gc.check_ransom_time:
                                self.ransom_create_check_time = time.time()
                                ProcessKiller().tryKillMaliciousProcess()
                                self.check_ransom = False

            except:
                pass

        #

        # Monitorar modificações nos honeypots
        def on_modified(self, event):
            try:
                if fm.isHonepot(event.src_path):
                    for dict in fm.json_honeypot_data_file_data:
                        if event.src_path == dict['absolute_path']:
                            with open(event.src_path, 'rb') as honeypot_file:
                                file_data = honeypot_file.read()
                                current_hash = hashlib.sha1(file_data).hexdigest()

                                if current_hash != dict['hash']:
                                    new_time = time.time() - self.modify_current_time
                                    self.honeypot_modified_event_count += 1

                                    if new_time > 1:
                                        logger.warning(f"Honeypot was modified {'' if self.honeypot_modified_event_count <= 1 else '(and ' + str(self.honeypot_modified_event_count) + ' more)'}")

                                        if self.honeypot_modified_event_count > gc.honeypot_modified_event_count_trigger or gc.immediate_mode:
                                            self.check_ransom = True

                                        self.modify_current_time = time.time()
                                        self.unknow_extension_event_count = 0

                                    if self.check_ransom:
                                        new_ransom_modify_check_time = time.time() - self.ransom_modify_check_time
                                        if new_ransom_modify_check_time > gc.check_ransom_time:
                                            self.ransom_modify_check_time = time.time()
                                            ProcessKiller().tryKillMaliciousProcess()
                                            self.check_ransom = False

                else:
                    pass

            except IndexError as e:
                pass

            except Exception as e:
                logger.error(e)
                pass

        #

        # Monitorar caso algum diretório seja mudado de lugar, para atualizar o JSON dos honeypots
        def on_moved(self, event):
            try:
                if not os.path.isdir(event.dest_path):
                    if re.findall("([^\/]+$)", event.src_path)[0] in fm.honeypot_names_file_data and re.findall("([^\/]+$)", event.src_path)[0] in fm.honeypot_names_file_data:
                        update_honeypot_dict = {
                            "old_path": event.src_path,
                            "new_path": event.dest_path
                        }

                        fm.honeypots_to_update.append(update_honeypot_dict)
                        fm.has_update_changes = True

            except:
                pass
        #

        # Monitorar se algum diretório for deletado, para remover as entradas dos mesmos no JSON dos honeypots

        def on_deleted(self, event):
            try:
                if re.findall("([^\/]+$)", event.src_path)[0] in fm.honeypot_names_file_data:
                    if not os.path.exists(event.src_path):
                        new_time = time.time() - self.delete_current_time
                        self.honeypot_deleted_event_count += 1

                        fm.honeypots_to_delete.append(event.src_path)
                        fm.has_delete_changes = True

                        if new_time > 1:
                            logger.warning(f"Honeypot was deleted {'' if self.honeypot_deleted_event_count <= 1 else '(and ' + str(self.honeypot_deleted_event_count) + ' more)'}")

                            if self.honeypot_deleted_event_count > gc.honeypot_deleted_event_count_trigger or gc.immediate_mode:
                                self.check_ransom = True

                            self.delete_current_time = time.time()
                            self.honeypot_deleted_event_count = 0

                else:
                    if not os.path.exists(event.src_path):
                        new_time = time.time() - self.delete_current_time
                        honeypot_deleted = False

                        for element in fm.json_honeypot_data_file_data:
                            if event.src_path in element['absolute_path']:
                                honeypot_deleted = True
                                break
                            else:
                                continue

                        for element in fm.honeypots_to_create:
                            if event.src_path in element['absolute_path']:
                                honeypot_deleted = True
                                break
                            else:
                                continue

                        for element in fm.honeypots_to_update:
                            if event.src_path in element['new_path']:
                                honeypot_deleted = True
                                break
                            else:
                                continue

                        if honeypot_deleted:
                            self.folder_with_honeypots_deleted_event_count += 1

                            fm.honeypots_to_delete.append(event.src_path)
                            fm.has_delete_changes = True

                            if new_time > 1:
                                logger.debug(f"Folder with honeypots was deleted {'' if self.folder_with_honeypots_deleted_event_count <= 1 else '(and ' + str(self.folder_with_honeypots_deleted_event_count) + ' more)'}")

                            if self.folder_with_honeypots_deleted_event_count > gc.folder_with_honeypots_deleted_event_count_trigger or gc.immediate_mode:
                                self.check_ransom = True

                            self.delete_current_time = time.time()
                            self.folder_with_honeypots_deleted_event_count = 0

                if self.check_ransom:
                    new_ransom_delete_check_time = time.time() - self.ransom_delete_check_time
                    if new_ransom_delete_check_time > gc.check_ransom_time:
                        self.ransom_delete_check_time = time.time()
                        ProcessKiller().tryKillMaliciousProcess()
                        self.check_ransom = False

            except IndexError as e:
                pass

            except Exception as e:
                logger.error(e)
                pass


# MAIN
if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
    logging.getLogger("watchdog.observers.inotify_buffer").disabled = True
