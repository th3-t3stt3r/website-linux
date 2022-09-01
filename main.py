# IMPORTS
import os
import psutil
import subprocess
from pyfiglet import Figlet
from colorama import init
from termcolor import colored
from software.honeypot_generator import HoneypotGenerator
from software.file_monitor import FileMonitor
from software.logger import logger
from software.audit import Audit

# CONSTANTS
# SOFTWARE
PID = os.getpid()
psutil.Process(PID).nice(19)
PATH_TO_MAIN_FOLDER = os.getcwd()
PATH_TO_SOFTWARE_FOLDER = os.path.join(PATH_TO_MAIN_FOLDER, "software")
PATH_TO_CONFIG_FOLDER = os.path.join(PATH_TO_SOFTWARE_FOLDER, "config")

# AUDIT
AUDIT_CUSTOM_RULES_FILE_NAME = "ransomware-detector.rules"
AUDIT_CUSTOM_RULES_KEY = "ransomware-detector-key"
AUDIT_CUSTOM_RULES_SHELL_KEY = "ransomware-detector-shell-key"
PATH_TO_AUDIT_CONFIG = subprocess.check_output(["find /etc audit/auditd.conf | grep audit/auditd.conf"], shell=True, stderr=subprocess.DEVNULL).decode()
PATH_TO_AUDIT = os.path.join(PATH_TO_AUDIT_CONFIG.rsplit('/', 1)[0])
PATH_TO_AUDIT_CUSTOM_RULE_FILE = os.path.join(PATH_TO_AUDIT, "rules.d", AUDIT_CUSTOM_RULES_FILE_NAME)

# VARIABLES
# PATHS TO MONITOR
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - FOR TEST
paths_to_monitor_or_generate_honeypot = [
    "/home/matheusheidemann/Documents/Github/Python-Ransomware-Detector/ransomware-test/encrypt-test"
]

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - FOR TEST


honeypot_file_name = ".r4n50mw4r3-d373c70r.txt"
json_file_name = "ransom-detector-hashes-list.json"
honeypot_names_file = "honeypot-names.txt"


# MAIN
init()
f = Figlet(font='slant')
print(colored(f.renderText('CapyShield'), 'red'))
print(colored('--- A Ransomware Detector by Bash Bunny Group ---\n\n', 'red'))
logger.debug("Starting Ransomware Detector")

# AUDIT CONFIG
audit = Audit(
    path_to_audit=PATH_TO_AUDIT,
    path_to_audit_custom_rule_file=PATH_TO_AUDIT_CUSTOM_RULE_FILE,
    path_to_audit_config=PATH_TO_AUDIT_CONFIG,
    audit_custom_rules_key=AUDIT_CUSTOM_RULES_KEY,
    audit_custom_rules_shell_key=AUDIT_CUSTOM_RULES_SHELL_KEY
)

audit.setStatus("on")

# HONEYPOT GENERATOR
honeypot_generator = HoneypotGenerator(
    directory_list=paths_to_monitor_or_generate_honeypot,
    honeypot_file_name=honeypot_file_name,
    path_to_config_folder=PATH_TO_CONFIG_FOLDER,
    json_file_name=json_file_name,
    honeypot_names_file=honeypot_names_file,
    audit_obj=audit,
    honeypot_interval=1,
    disable_honeypot_interval=True,
    random_honeypot_file_name=False,
    hidden_honeypot_file=True,
    honeypot_file_extension=".txt",
    delete=True
)
honeypot_generator.run()

# FILE MONITOR
if not honeypot_generator.delete:
    file_monitor = FileMonitor(
        directory_list=paths_to_monitor_or_generate_honeypot,
        honeypot_file_name=honeypot_file_name,
        path_to_config_folder=PATH_TO_CONFIG_FOLDER,
        json_file_name=json_file_name,
        honeypot_names_file=honeypot_names_file,
        audit_obj=audit,
        path_to_main_folder=PATH_TO_MAIN_FOLDER,
        audit_custom_rules_key=AUDIT_CUSTOM_RULES_KEY,
        audit_custom_rules_shell_key=AUDIT_CUSTOM_RULES_SHELL_KEY

    )
    file_monitor.run()
else:
    quit()

# FINISH
logger.debug("Quitting Ransomware Detector")
