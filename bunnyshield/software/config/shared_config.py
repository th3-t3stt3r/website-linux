# IMPORTS
import os
import subprocess
from dataclasses import dataclass


@dataclass
class GeneralConfig():
    PID = os.getpid()

    # NAMES
    audit_custom_rules_file_name = "bs.rules"
    audit_custom_rules_key = "bs-monitored-dir-change"
    audit_custom_rules_shell_key = "bs-shell-opened"
    audit_custom_rules_killed_key = "bs-killed"

    json_config_file_name = "bs-config.json"
    json_honeypot_data_file_name = "honeypot-paths-n-hashes.json"
    honeypot_names_file = "honeypot-names.txt"
    honeypot_interval_count_file_name = "honeypot_interval_count.txt"

    honeypot_file_name = "r4n50mw4r3-d373c70r.txt"
    honeypot_file_extension = ".txt"

    # GET STRINGS FROM FUNCS
    data_main_d = os.getcwd()
    data_software_d = os.path.join(data_main_d, "software")
    data_config_d = os.path.join(data_software_d, "config")
    data_audit_conf_d = subprocess.check_output(["find /etc audit/auditd.conf | grep audit/auditd.conf"], shell=True, stderr=subprocess.DEVNULL).decode()
    data_audit_d = os.path.join(data_audit_conf_d.rsplit('/', 1)[0])
    data_audit_custom_rule_f = os.path.join(data_audit_d, "rules.d", audit_custom_rules_file_name)
    data_file_ext_l = [line.rstrip() for line in open(os.path.join(data_main_d, "software/tools/file_extensions.txt"))]
    data_honeypot_interval_f = os.path.join(data_config_d, honeypot_interval_count_file_name)
    json_config_file_f = os.path.join(data_config_d, json_config_file_name)

    # PATHS
    PATH_TO_MAIN_FOLDER = data_main_d
    PATH_TO_SOFTWARE_FOLDER = data_software_d
    PATH_TO_CONFIG_FOLDER = data_config_d
    PATH_TO_AUDIT_CONFIG = data_audit_conf_d
    PATH_TO_AUDIT = data_audit_d
    PATH_TO_AUDIT_CUSTOM_RULE_FILE = data_audit_custom_rule_f
    PATH_TO_HONEYPOT_INTERVAL_COUNT_FILE = data_honeypot_interval_f
    PATH_TO_CONFIG_FILE = json_config_file_f

    # CONFIG
    random_honeypot_file_name = False
    hidden_honeypot_file = True
    honeypot_interval = 1
    disable_honeypot_interval = True
    delete_honeypots = False
    skip_to_monitor = False
    file_update_interval = 10

    # DYNAMIC CONFIG
    selected_directories = [
        "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test"
    ]
    file_ext_list = data_file_ext_l


if __name__ == "__main__":
    pass
else:
    pass
