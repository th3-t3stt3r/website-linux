import os
import re
import time
import psutil
import subprocess
from signal import SIGKILL
from software.config.shared_config import GeneralConfig as gc
from software.tools.utils import isHexStr


def checkAndKillProcess(process, method):
    try:
        psutil.Process(process).status()
        print(process)
        os.kill(process, SIGKILL)
        logger.critical(f"Proabable malicious process with PID {process}. Killing it...")
        end = time.perf_counter()
        logger.critical(f"Killed process with PID {process} in {round(end - start, 3)}s - [Method {method}]")

    except psutil.NoSuchProcess as e:
        pass

    except Exception as e:
        logger.error(e)


def tryKillMaliciousProcess(current_event_path):
    # METHOD 1
    global start
    start = time.perf_counter()
    ppid_pid_pattern = "(?<=pid=)(.*?)(?=\ )"
    tty_pattern = "(?<=tty=)(.*?)(?=\ )"
    comm_pattern = '(?<=comm=")(.*?)(?=")'
    cwd_path_pattern = '(?<=cwd=")(.*?)(?=")'
    name_path_pattern = "(?<=name=)(.*?)(?=\ )"
    #audit_event_pattern = "(?<=----)(\n|.)*?(?=----|\s*$)"
    try:
        print(str(current_event_path))
        event_list = subprocess.check_output([f"ausearch -k {gc.audit_custom_rules_key} | tail -n 5000"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")
        for event in event_list:
            path_list = re.findall(name_path_pattern, event)
            for event_path in path_list:
                if isHexStr(event_path):
                    event_path = bytes.fromhex(event_path).decode("ascii")
                else:
                    event_path = event_path[1:-1]
                if str(current_event_path) in str(event_path):
                    if re.findall(tty_pattern, event)[0] != "(none)":
                        if re.findall(comm_pattern, event)[0] != "rm":
                            if re.findall(cwd_path_pattern, event)[0] != gc.PATH_TO_MAIN_FOLDER:
                                ppid_malicious = re.findall(ppid_pid_pattern, event)[0]
                                if ppid_malicious != '1' and ppid_malicious != gc.PID:
                                    checkAndKillProcess(int(ppid_malicious), '1')
    except Exception as e:
        print(e)
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
                if process != '1' and ppid_malicious != gc.PID:
                    checkAndKillProcess(int(process), '2')


if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
