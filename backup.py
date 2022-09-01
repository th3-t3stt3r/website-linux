import os
import re
import time
import subprocess
import psutil
from signal import SIGKILL


def tryKillMaliciousProcess(path_to_main_folder, audit_custom_rules_key, audit_custom_rules_shell_key):
    # METHOD 1
    start = time.perf_counter()
    ppid_pid_pattern = "(?<=pid=)(.*?)(?=\ )"
    try:
        last_honeypot_file_event = subprocess.check_output([f"ausearch -k {audit_custom_rules_key} | tail -n 100"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-1:]
        ppid_malware, pid = re.findall(ppid_pid_pattern, last_honeypot_file_event[0])

        if ppid_malware != "1":
            try:
                print('55')
                logger.critical(f"Proabable malicious process with PPID {ppid_malware}. Killing it...")
                os.kill(int(ppid_malware), SIGKILL)
                end = time.perf_counter()
                logger.critical(f"Killed proabable malicious process with PPID {ppid_malware} in {round(end - start, 3)}s")
            except:
                pass
    except Exception as e:
        pass

    # METHOD 2
    try:
        shell_events = subprocess.check_output([f"ausearch -l -k {audit_custom_rules_shell_key} | tail -n 100"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-1:]
        malicious_process_list = []
        for event in reversed(shell_events):
            if not path_to_main_folder in re.findall('(?<=cwd=")(.*?)(?=\")', event)[0]:
                pid_malware = re.findall(ppid_pid_pattern, event)[0]
                malicious_process_list.append(pid_malware)

                try:
                    ppid_malware = subprocess.check_output([f"ps -o ppid= -p {pid_malware}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip()
                    malicious_process_list.append(ppid_malware)
                except subprocess.CalledProcessError:
                    ppid_malware = ""
                    pass

                for process in malicious_process_list:
                    try:
                        print('0')
                        print('0000')
                        if process != '1':
                            try:
                                try:
                                    psutil.Process(process).status()
                                    os.kill(int(process), SIGKILL)
                                    logger.critical(f"Proabable malicious process with PPID {process}. Killing it...")
                                    print('1')
                                except:
                                    pass
                                for i in range(1, 6):
                                    try:
                                        psutil.Process(process + i).status()
                                        os.kill(int(process + i), SIGKILL)
                                        logger.critical(f"Proabable malicious process with PPID {process + i}. Killing it...")
                                        print('2')
                                    except:
                                        pass
                                    try:
                                        psutil.Process(process - i).status()
                                        os.kill(int(process - i), SIGKILL)
                                        logger.critical(f"Proabable malicious process with PPID {process - i}. Killing it...")
                                        print('3')
                                    except:
                                        pass
                                end = time.perf_counter()
                                logger.critical(f"Killed proabable malicious process with PPID {process} in {round(end - start, 3)}s")
                            except:
                                pass
                    except:
                        pass
    except:
        pass


if __name__ == "__main__":
    pass
else:
    from software.logger import logger
