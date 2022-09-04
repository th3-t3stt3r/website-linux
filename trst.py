import subprocess
import json
import time


def getAutorunProcesses():
    autorun_list = subprocess.check_output(["ls -1 /lib/systemd/system/*.service /etc/systemd/system/*.service"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().rsplit("\n")
    return autorun_list


def jsonTest():

    path = "/home/matheusheidemann/Documents/Github/Challenge/website-test/capyshield/software/config/capyshield-honeypot-hashes.json"
    event = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder47/subfolder12/.r4n50mw4r3-d373c70r.txt"
    start = time.perf_counter()

    with open(path, 'r', encoding='utf-8') as f:
        my_list = json.load(f)

        for idx, obj in enumerate(my_list):
            if obj['absolute_path'] == event:
                my_list.pop(idx)

    with open(path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(my_list, indent=4))
    end = time.perf_counter()
    print(f"Updated JSON in {round(end - start, 3)}s")


print(jsonTest())
