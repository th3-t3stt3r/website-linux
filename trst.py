import subprocess


def getAutorunProcesses():
    autorun_list = subprocess.check_output(["ls -1 /lib/systemd/system/*.service /etc/systemd/system/*.service"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().rsplit("\n")
    return autorun_list


print(getAutorunProcesses())
