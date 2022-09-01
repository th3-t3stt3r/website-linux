import os
import re
import time
import psutil
import subprocess
from signal import SIGKILL


def checkAndKillProcess(process):
    psutil.Process(process).status()
    os.system(process, SIGKILL)
    logger.critical(f"Proabable malicious process with PID {process}. Killing it...")
    end = time.perf_counter()
    logger.critical(f"Killed process with PID {process} in {round(end - start, 3)}s")


def tryKillMaliciousProcess(path_to_main_folder, audit_custom_rules_key, audit_custom_rules_shell_key):
    # METHOD 1
    global start
    start = time.perf_counter()
    ppid_pid_pattern = "(?<=pid=)(.*?)(?=\ )"
    try:
        last_honeypot_file_event = subprocess.check_output([f"ausearch -k {audit_custom_rules_key} | tail -n 100"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-1:]
        ppid_malicious = re.findall(ppid_pid_pattern, last_honeypot_file_event[0])[0]

        if ppid_malicious != '1':
            try:
                checkAndKillProcess(int(ppid_malicious))
            except:
                pass
    except:
        pass

    # METHOD 2
    malicious_process_list = []
    shell_events = subprocess.check_output([f"ausearch -l -k {audit_custom_rules_shell_key} | tail -n 100"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-1:]

    for event in reversed(shell_events):
        if not path_to_main_folder in re.findall('(?<=cwd=")(.*?)(?=\")', event)[0]:
            pid_malicious = re.findall(ppid_pid_pattern, event)[0]
            malicious_process_list.append(pid_malicious)

            try:
                ppid_malicious = subprocess.check_output([f"ps -o ppid= -p {pid_malicious}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip()
                malicious_process_list.append(ppid_malicious)
            except:
                pass

            for process in reversed(malicious_process_list):
                if process != '1':
                    try:
                        checkAndKillProcess(int(process))
                    except:
                        pass


if __name__ == "__main__":
    pass
else:
    from software.logger import logger
