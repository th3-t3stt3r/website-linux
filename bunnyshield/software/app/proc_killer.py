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
        os.kill(process, SIGKILL)
        logger.critical(f"Proabable malicious process with PID {process}. Killing it...")
        end = time.perf_counter()
        logger.critical(f"Killed process with PID {process} in {round(end - start, 3)}s - [Method {method}]")
        return True

    except Exception as e:
        return False


def tryKillMaliciousProcess(current_event_path):
    print("KILLINGGGGGGGGGG")
    # METHOD 1
    global start
    start = time.perf_counter()
    malicious_process_killed = False

    ppid_pid_pattern = "(?<=pid=)(.*?)(?=\ )"
    tty_pattern = "(?<=tty=)(.*?)(?=\ )"
    comm_pattern = '(?<=comm=")(.*?)(?=")'
    cwd_path_pattern = '(?<=cwd=")(.*?)(?=")'
    name_path_pattern = "(?<=name=)(.*?)(?=\ )"

    try:
        dir_changes_events = subprocess.check_output([f"ausearch -k {gc.audit_custom_rules_key} | tail -n {gc.max_tail_for_dir_changes_event}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")

        for event in dir_changes_events:
            try:
                if re.findall(tty_pattern, event)[0] != "(none)":
                    if re.findall(comm_pattern, event)[0] != "rm":
                        if re.findall(cwd_path_pattern, event)[0] != gc.PATH_TO_MAIN_FOLDER:
                            path_list = re.findall(name_path_pattern, event)

                            for event_path in path_list:
                                if isHexStr(event_path):
                                    event_path = bytes.fromhex(event_path).decode("ascii")
                                else:
                                    event_path = event_path[1:-1]

                                if str(current_event_path) in str(event_path):
                                    ppid_malicious = re.findall(ppid_pid_pattern, event)[0]
                                    if ppid_malicious != '1' and ppid_malicious != gc.PID:
                                        malicious_process_killed = checkAndKillProcess(int(ppid_malicious), '1')

            except Exception as e:
                pass

    except Exception as e:
        pass

    # METHOD 2
    if not malicious_process_killed:
        malicious_process_list = []
        shell_open_events = subprocess.check_output([f"ausearch -l -k {gc.audit_custom_rules_shell_key} | tail -n {gc.max_tail_for_shell_open_event}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-1:]

        for event in reversed(shell_open_events):
            try:
                if not gc.PATH_TO_MAIN_FOLDER in re.findall('(?<=cwd=")(.*?)(?=\")', event)[0]:
                    pid_malicious = re.findall(ppid_pid_pattern, event)[0]
                    malicious_process_list.append(pid_malicious)

                    try:
                        ppid_malicious = subprocess.check_output([f"ps -o ppid= -p {pid_malicious}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip()
                        malicious_process_list.append(ppid_malicious)

                        for process in reversed(malicious_process_list):
                            if process != '1' and ppid_malicious != gc.PID:
                                malicious_process_killed = checkAndKillProcess(int(process), '2')
                    except:
                        pass

            except Exception as e:
                pass


if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
