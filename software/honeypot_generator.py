# TODO
# PRINTAR A QUANTIDADE DE DIRETÓRIOS EXISTENTES NO SISTEMA (COM BASE NOS DIRETÓRIOS PASSADOS) X
# INPUT DE QUAL INTERVALO DE DIRETÓRIOS SERÁ COLOCADO UM HONEYPOT X
# CRIAR NOVOS HONEYPOTS PARA NOVOS DIRETÓRIOS
# ATUALIZAR JSON E AS REGRAS QUANDO ARQUIVOS HONEYPOT SÃO MOVIDOS OU DELETADOS
# OPÇÃO DE GERAR ARQUIVOS OCULTOS OU NÃO PARA MAIOR SEGURANÇA
# FUNCIONALIDADE PARA GERAR HONEYPOT APENAS NO DIRETÓRIO ROOT E NO DIRETÓRIO TOPO DA ÁRVORE

import json
import random
import string
import os
import hashlib
import time
from software.audit import Audit
from software.logger import logger


class HoneypotGenerator:
    """Classe do Gerador de Honeypots"""

    def __init__(self, directory_list, honeypot_file_name, path_to_config_folder, json_file_name, honeypot_names_file, audit_obj, honeypot_interval=2, disable_honeypot_interval=False, random_honeypot_file_name=False, honeypot_file_extension=".txt", hidden_honeypot_file=True, delete=False):
        self.directory_list = directory_list
        self.honeypot_file_name = honeypot_file_name
        self.path_to_config_folder = path_to_config_folder
        self.json_file_name = json_file_name
        self.honeypot_names_file = honeypot_names_file
        self.audit_obj = audit_obj
        self.honeypot_interval = honeypot_interval
        self.disable_honeypot_interval = disable_honeypot_interval
        self.random_honeypot_file_name = random_honeypot_file_name
        self.hidden_honeypot_file = hidden_honeypot_file
        self.honeypot_file_extension = honeypot_file_extension
        self.delete = delete

        if honeypot_interval <= 1 and not disable_honeypot_interval:
            logger.error('"Disable Honeyppot Interval" is off, Honeypot interval should be 2 or greater!')
            quit()

        if honeypot_interval >= 2 and disable_honeypot_interval:
            logger.error(f'"Disable Honeyppot Interval" is on, changing the "Honeypot Interval" from {honeypot_interval} to 1')
            self.honeypot_interval = 1
            quit()

    def calcPercentage(self, directory_count, counter):
        """Função para calcular a regra de 3"""
        v1 = directory_count  # numero de 100%
        v2 = 100  # 100%
        v3 = counter  # número a descobrir a porcentagem
        return v3 * v2 / v1

    def returnPercentage(self, directory_count, counter, porcentage):
        """Função para retornar a porcentagem"""
        for i in range(100):
            counter = round(counter + 0.01, 2)
            if counter == round(directory_count * porcentage, 2):
                logger.debug(f"Working on {'deleting' if self.delete else 'creating'} honeypots: {round(self.calcPercentage(directory_count, counter))}%")
                porcentage = round(porcentage + 0.1, 2)
        return counter, porcentage

    def __randomString(self, action):
        """Função para gerar uma string única e aleatória que ficará dentro de cada honeypot"""
        if action == "unique-hash":
            characters = string.ascii_letters + string.digits + string.punctuation
            random_string = ''.join(random.choice(characters) for i in range(50))
            return random_string
        if action == "unique-name":
            characters = string.ascii_letters + string.digits
            random_string = ''.join(random.choice(characters) for i in range(25))
            return random_string + self.honeypot_file_extension

    def __generateHash(self, honeypot_file):
        """Função para gerar uma hash para o arquivo de honeypot criado"""
        file_data = honeypot_file.read()
        readable_hash = hashlib.md5(file_data).hexdigest()

        honeypot_file_hash_dict = {
            "absolute_path": honeypot_file.name,
            "hash": readable_hash
        }
        honeypot_files_hash_list.append(honeypot_file_hash_dict)

    def __generateHoneypots(self):
        """Função para gerar os honeypots"""
        global honeypot_files_hash_list
        global honeypot_names_list
        honeypot_files_hash_list = []
        honeypot_names_list = []
        total_created_count = 0

        self.audit_obj.createCustomRuleFile()
        start = time.perf_counter()
        for directory in self.directory_list:
            directory_count = 0
            for root in os.walk(directory):
                directory_count += 1

            logger.debug(f"Creating honeypots in {directory}")
            logger.debug(f"There are {directory_count} subdirectories inside {directory}")
            logger.debug(f"The honeypot creation interval is set to: {self.honeypot_interval if not self.disable_honeypot_interval else 'disabled'}")
            if directory_count == 0:
                directory_count = 1
            logger.debug(f"It will be created {round(directory_count / self.honeypot_interval) if not self.disable_honeypot_interval else directory_count} honeypots")
            percentage = 0.1
            created_count = 0
            directory_walk_count = 0
            for current_path, _, _ in os.walk(directory):
                if directory_walk_count % self.honeypot_interval == 0 or created_count == 0 or self.honeypot_interval == 1 and self.disable_honeypot_interval:
                    try:
                        if os.access(current_path, os.W_OK):
                            if self.random_honeypot_file_name:
                                self.honeypot_file_name = ("." if self.hidden_honeypot_file else "") + self.__randomString("unique-name")

                            honeypot_names_list.append(self.honeypot_file_name)

                            # Criar o honeypot
                            with open(os.path.join(current_path, self.honeypot_file_name), 'w') as honeypot_file:
                                honeypot_file.write("THIS IS A PYTHON RANSOMWARE DETECTOR FILE! PLEASE! DO NOT MOVE, DELETE, RENAME OR MODIFY THIS FILE!\n")
                                honeypot_file.write(f"Unique string for this file: {self.__randomString('unique-hash')}")

                            # Gerar a hash para o honeypot criado
                            with open(os.path.join(current_path, self.honeypot_file_name), 'rb') as honeypot_file:
                                self.__generateHash(honeypot_file)

                            # Criar a regra no audit
                            self.audit_obj.createAuditRule(os.path.join(current_path, self.honeypot_file_name))
                            created_count += 1

                    except Exception as e:
                        logger.error(e)
                        continue
                directory_walk_count, percentage = self.returnPercentage(directory_count, directory_walk_count, percentage)

            logger.debug(f"Created a total of {round(created_count)} honeypots in {directory}")
            total_created_count = total_created_count + created_count

        end = time.perf_counter()
        logger.debug(f"Created honeypots in {round(end - start, 3)}s")

        if total_created_count == 0:
            logger.error("No honeypots were created in any directories. Quitting...")
            quit()

        self.audit_obj.loadRules(round(created_count))

        # Gerar o JSON para os honeypot files criados e suas respectivas hashes
        self.__generateJson(honeypot_files_hash_list)

        if self.random_honeypot_file_name:
            self.__generateHoneypotNamesList(honeypot_names_list)
        else:
            self.__generateHoneypotNamesList(self.honeypot_file_name)

    def __generateJson(self, honeypot_files_hash_list):
        logger.debug("Generating JSON file")
        """Função para gerar o JSON com as entradas de cada honeypot"""
        json_object = json.dumps(honeypot_files_hash_list, indent=4)

        # Se a pasta config não existir, criar uma
        if not os.path.exists(self.path_to_config_folder):
            os.makedirs(self.path_to_config_folder)

        # Criar um novo .json com o objeto json criado
        with open(os.path.join(self.path_to_config_folder, self.json_file_name), 'w') as json_file:
            json_file.write(json_object)

    def __generateHoneypotNamesList(self, honeypot_names_list):
        logger.debug("Generating Honeypot names file")
        if not os.path.exists(self.path_to_config_folder):
            os.makedirs(self.path_to_config_folder)

        with open(os.path.join(self.path_to_config_folder, self.honeypot_names_file), 'w') as names_file:
            if self.random_honeypot_file_name:
                for name in honeypot_names_list:
                    names_file.write(f"{name}\n")
            else:
                names_file.write(self.honeypot_file_name)

    def __deleteHoneypotsAndRules(self):
        """Função para deletar todos os honeypots"""
        try:
            json_paths_list = []
            json_file_path = os.path.join(self.path_to_config_folder, self.json_file_name)
            with open(os.path.join(json_file_path)) as tmp_json_file:
                json_file = json.load(tmp_json_file)
                for dict in json_file:
                    if dict['absolute_path']:
                        json_paths_list.append(dict['absolute_path'])
        except FileNotFoundError:
            logger.error(f'Could not find {self.json_file_name} in {self.path_to_config_folder}. Without this file is impossible to properly delete the honeypots')
            quit()

        start = time.perf_counter()
        for directory in self.directory_list:
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
                        directory_walk_count, percentage = self.returnPercentage(directory_count, directory_walk_count, percentage)
                except Exception as e:
                    logger.error(e)
                    #logger.error(f'Found an error in {current_path}: {str(e.__class__.__name__)}')
                    continue
            if deleted_count == 0:
                logger.debug(f"No honeypots where found to be deleted")
            else:
                logger.debug(f"Deleted a total of {round(deleted_count)} honeypots in {directory}")

        end = time.perf_counter()
        logger.debug(f"Deleted honeypots in {round(end - start, 3)}s")

        # Deletar o arquivo e as regras de audit
        self.audit_obj.deleteCustomRuleFileAndRules(round(deleted_count))

        # Deletar o JSON das hashes
        self.__deleteJson()
        self.__deleteHoneypotNamesList()

    def __deleteJson(self):
        """Função deletar o JSON com as entradas de cada honeypot"""
        logger.debug("Deleting JSON file")
        if os.path.exists(self.path_to_config_folder):
            try:
                os.remove(os.path.join(self.path_to_config_folder, self.json_file_name))
            except FileNotFoundError:
                logger.error(f'Could not find {self.json_file_name} in {self.path_to_config_folder}')
                quit()

    def __deleteHoneypotNamesList(self):
        """Função para deletar o arquivo com os nomes dos honeypots"""
        logger.debug("Deleting Honeypot names file")
        if os.path.exists(self.path_to_config_folder):
            try:
                os.remove(os.path.join(self.path_to_config_folder, self.honeypot_names_file))
            except FileNotFoundError:
                logger.error(f'Could not find {self.honeypot_names_file} in {self.path_to_config_folder}')

    def updateJson(self):
        """Função para atualizar o JSON, modificando as entradas de cada honeypot afetado"""
        print("atualizar o json")

    def run(self):
        """Função para criar ou deletar os honeypots"""
        start = time.perf_counter()
        # CRIAR HONEYPOTS
        if not self.delete:
            self.__generateHoneypots()

        # DELETAR HONEYPOTS
        elif self.delete:
            self.__deleteHoneypotsAndRules()
        end = time.perf_counter()
        logger.debug(f"{'Created' if not self.delete else 'Deleted'} honeypots and rules in {round(end - start, 3)}s")


# MAIN
if __name__ == "__main__":
    pass
else:
    from software.logger import logger
