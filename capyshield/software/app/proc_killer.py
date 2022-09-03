import os
import re
import time
import psutil
import subprocess
from signal import SIGKILL
from software.config.shared_config import GeneralConfig as gc


def checkAndKillProcess(process, method):
    psutil.Process(process).status()
    os.kill(process, SIGKILL)
    logger.critical(f"Proabable malicious process with PID {process}. Killing it...")
    end = time.perf_counter()
    logger.critical(f"Killed process with PID {process} in {round(end - start, 3)}s - [Method {method}]")


def tryKillMaliciousProcess(current_event_path):
    # METHOD 1
    global start
    start = time.perf_counter()
    ppid_pid_pattern = "(?<=pid=)(.*?)(?=\ )"
    audit_event_pattern = "(?<=----)(\n|.)*?(?=----|\s*$)"
    try:
        event_list = subprocess.check_output([f"ausearch -k {gc.audit_custom_rules_key} | tail -n 300"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")
        for event in event_list:
            if current_event_path in event:
                ppid_malicious = re.findall(ppid_pid_pattern, event_list[0])[0]

                if ppid_malicious != '1':
                    try:
                        checkAndKillProcess(int(ppid_malicious), '1')
                    except:
                        pass
    except:
        pass

    # METHOD 2
    malicious_process_list = []
    shell_events = subprocess.check_output([f"ausearch -l -k {gc.audit_custom_rules_shell_key} | tail -n 100"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-1:]

    for event in reversed(shell_events):
        if not gc.PATH_TO_MAIN_FOLDER in re.findall('(?<=cwd=")(.*?)(?=\")', event)[0]:
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
                        checkAndKillProcess(int(process), '2')
                    except:
                        pass


if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
