import string
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


def test():

    maior = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder61/subfolder44/SMM1xQuoeMQ4G1ZXHyh3waLgn.capybara"
    menor = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder61/subfolder44/"

    if menor in maior:
        print('Yes')


def is_hex_str(s):
    return set(s).issubset(string.hexdigits)


def hextotest():
    # string = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder2 (copy 3)/b/"
    # string_to_hex = string.encode('utf-8').hex()
    # print(string_to_hex)

    hexstring = "2F686F6D652F6D61746865757368656964656D616E6E2F446F63756D656E74732F4769746875622F4368616C6C656E67652F776562736974652D746573742F72616E736F6D776172652D746573742F656E63727970742D746573742F666F6C646572322028636F70792032292F622F"
    hexstring_to_text = bytes.fromhex(hexstring).decode("ascii")
    print(hexstring_to_text)


def timetest():
    # print(time.time())
    # time.sleep(60)
    # print(time.time())
    print(1662427530.9781222 - 1662427470.918513)


def removefirstandlast():
    event_path = '"/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder61/subfolder1/sIb5OCEvteLVUCsHKGOoFpIBV.capybara"'
    print(event_path[1:-1])


test()
