import os
import re
import time
import psutil
import subprocess
from signal import SIGKILL
from software.config.shared_config import GeneralConfig as gc


class ProcessKiller():
    def __init__(self):
        self.start = time.perf_counter()
        self.malicious_process_killed = False
        self.pid_pattern = "(?<=pid=)(.*?)(?=\ )"
        self.tty_pattern = "(?<=tty=)(.*?)(?=\ )"
        self.comm_pattern = '(?<=comm=")(.*?)(?=")'
        self.cwd_path_pattern = '(?<=cwd=")(.*?)(?=")'

    #

    def tryKillMaliciousProcess(self):
        try:
            if not self.malicious_process_killed:
                self.firstMethod()
        except:
            pass

        try:
            if not self.malicious_process_killed:
                self.secondMethod()
        except:
            pass
    #

    def firstMethod(self):
        dir_changes_events = subprocess.check_output([f"ausearch -k {gc.audit_custom_rules_key} | tail -n {gc.max_tail_for_dir_changes_event}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-10:]

        for event in dir_changes_events:
            try:
                if re.findall(self.tty_pattern, event)[0] != "(none)":
                    if re.findall(self.comm_pattern, event)[0] != "rm":
                        process_cwd = re.findall(self.cwd_path_pattern, event)[0]
                        if process_cwd != gc.PATH_TO_MAIN_FOLDER:
                            try:
                                for pid in re.findall(self.pid_pattern, event):
                                    if pid != '1' and pid != gc.PID:
                                        self.malicious_process_killed = self.checkAndKillProcess(int(pid), process_cwd, '1')

                            except:
                                pass

            except:
                pass
    #

    def secondMethod(self):
        shell_open_events = subprocess.check_output([f"ausearch -l -k {gc.audit_custom_rules_shell_key} | tail -n {gc.max_tail_for_shell_open_event}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-10:]

        for event in reversed(shell_open_events):
            try:
                process_cwd = re.findall(self.cwd_path_pattern, event)[0]
                if process_cwd != gc.PATH_TO_MAIN_FOLDER:
                    for pid in re.findall(self.pid_pattern, event):
                        try:
                            if pid != '1' and pid != gc.PID:
                                self.malicious_process_killed = self.checkAndKillProcess(int(pid), process_cwd, '2')

                        except:
                            pass

            except:
                pass
    #

    def checkAndKillProcess(self, pid, cwd, method):
        try:
            psutil.Process(pid).status()
            ppid = int(subprocess.check_output([f"ps -o ppid= -p {pid}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip())
            psutil.Process(ppid).status()

            os.kill(pid, SIGKILL)
            os.kill(ppid, SIGKILL)

            logger.critical(f"Ransomware process with PID {pid} and PPID {ppid}. Killing it...")
            end = time.perf_counter()
            logger.critical(f"Killed ransomware process with PID {pid} and PPID {ppid} in {round(end - self.start, 3)}s - [Method {method}]")
            logger.critical(f"Ransomware file working directory is {cwd}")

            return True

        except:
            return False


if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
