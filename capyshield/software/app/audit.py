# TODO
# Checar se o audit está instalado e ligado
# Ligar e configurar o audit
# As regras do AUDIT devem ser criadas/modificadas toda vez que:
# - Forem criados novos honeypots pela primeira vez
# - Um diretório for movido para outro lugar, atualizando o JSON e as regras consequentemente
# - Um diretório for deletado, atualizando o JSON e as regras consequentemente
# As regras do AUDIT devem ir para o arquivo de regras separado
# As regras devem conter a keyword "ransomware-detector-key"
# É necessário configurar o arquivo de log para que possa salvar os PIDs se um ransomware agir
# É necessário ter um caminho definido para o arquivo que conterá as regras personalizadas
import time
import re
import os
import subprocess
from time import sleep
from software.tools.logger import logger
from software.config.shared_config import GeneralConfig as gc


class Audit:
    """Classe do serviço de auditoria do Linux"""

    def setStatus(self, action):
        """Função para ligar ou desligar o serviço de auditoria"""
        print(gc.audit_custom_rules_file_name)
        output = subprocess.run(['service', 'auditd', 'status'],  capture_output=True, text=True)
        tries = 0
        if not "could not be found" in str(output):
            if action == "on":
                while True and tries < 5:
                    if re.findall("(?<=Active: )(.*?)(?=\ )", str(output))[0] == "active":
                        logger.debug("Auditd Service is currently active")
                        break
                    else:
                        logger.debug("Auditd Service is currently inactive")
                        logger.debug("Turning Auditd service on...")
                        subprocess.run(['service', 'auditd', 'start'])
                        sleep(3)
                        output = subprocess.run(['service', 'auditd', 'status'],  capture_output=True, text=True)
                        tries += 1
            elif action == "off":
                if re.findall("(?<=Active: )(.*?)(?=\ )", str(output))[0] == "inactive":
                    logger.error("Can't turn Auditd Service off. The service is already inactive")
                else:
                    logger.debug("Turning Auditd service off...")
                    subprocess.run(['service', 'auditd', 'stop'])
        else:
            logger.debug("Could not find Auditd service. Do you have Auditd installed?")

    #

    def createCustomRuleFile():
        """Função para criar o arquivo que terá as regras para cada honeypot"""
        subprocess.check_output([f"auditctl -D -k '{gc.audit_custom_rules_key}'"], shell=True, stderr=subprocess.DEVNULL)
        subprocess.check_output([f"auditctl -D -k '{gc.audit_custom_rules_shell_key}'"], shell=True, stderr=subprocess.DEVNULL)

        if os.path.exists(gc.PATH_TO_AUDIT_CUSTOM_RULE_FILE):
            os.remove(gc.PATH_TO_AUDIT_CUSTOM_RULE_FILE)

        with open(gc.PATH_TO_AUDIT_CUSTOM_RULE_FILE, "w") as custom_rule_file:
            custom_rule_file.write("-D\n")

    #

    def deleteCustomRuleFileAndRules(self):
        """Função para criar o arquivo que terá as regras para cada honeypot"""
        logger.debug("Deleting audit rules foreach honeypot file")
        rule_count = subprocess.check_output([f"sudo auditctl -l -k {gc.audit_custom_rules_key} | wc -l"], shell=True, stderr=subprocess.DEVNULL).decode()

        if os.path.exists(gc.PATH_TO_AUDIT_CUSTOM_RULE_FILE):
            os.remove(gc.PATH_TO_AUDIT_CUSTOM_RULE_FILE)
        else:
            logger.error("There is not custom rule file in the directory.")

        start = time.perf_counter()
        subprocess.check_output([f"auditctl -D"], shell=True, stderr=subprocess.DEVNULL)
        while int(rule_count) > 1:
            rule_count = subprocess.check_output([f"sudo auditctl -l -k {gc.audit_custom_rules_key} | wc -l"], shell=True, stderr=subprocess.DEVNULL).decode()
            sleep(1)

        end = time.perf_counter()

        initial_rule_count = subprocess.check_output([f"sudo auditctl -l -k {gc.audit_custom_rules_key} | wc -l"], shell=True, stderr=subprocess.DEVNULL).decode()
        logger.debug(f"Deleted a total of {str(initial_rule_count).strip()} audit rules in {round(end - start, 2)}s")

    #

    def createAuditRule(path_to_dir):
        """Função para criar uma regra de auditoria"""
        with open(gc.PATH_TO_AUDIT_CUSTOM_RULE_FILE, "a") as custom_rule_file:
            custom_rule_file.write(f'-w "{path_to_dir}" -p wa -k {gc.audit_custom_rules_key}\n')

    #

    def loadRules():
        """Função para carregar as regras personalizadas criadas"""
        start = time.perf_counter()
        logger.debug("Creating audit rules foreach honeypot file. This process may take a while")
        logger.debug(f"It will be created {len(gc.selected_directories)} audit rules")
        with open(gc.PATH_TO_AUDIT_CUSTOM_RULE_FILE) as custom_rule_file:
            for rule in custom_rule_file:
                subprocess.check_output([f"auditctl {rule.strip()}"], shell=True, stderr=subprocess.DEVNULL)

            subprocess.check_output([f"auditctl -a exit,always -F arch=b64 -S execve -F path=/bin/sh -k {gc.audit_custom_rules_shell_key}"], shell=True, stderr=subprocess.DEVNULL)

            rule_count = 0
            while int(rule_count) < int(len(gc.selected_directories)):
                rule_count = subprocess.check_output([f"sudo auditctl -l -k {gc.audit_custom_rules_key} | wc -l"], shell=True, stderr=subprocess.DEVNULL).decode()
                logger.debug(f"Loaded {str(rule_count).strip()} rules")
                sleep(1)

        end = time.perf_counter()
        logger.debug(f"Loaded a total of {int(rule_count)} audit rules in {round(end - start, 2)}s")


# MAIN
if __name__ == "__main__":
    pass
else:
    pass
