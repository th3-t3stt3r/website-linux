import re
import string
import subprocess
import json
import time
from typing import Set
import psutil


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


def isin():

    event_paths = ['/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/.r4n50mw4r3-d373c70r.txt']
    json_file_data = [{'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/.r4n50mw4r3-d373c70r.txt', 'hash': '0cce0aa5dea5f77c612441a71a79afc84aabd1dc'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder1/.r4n50mw4r3-d373c70r.txt', 'hash': '5f98460b7032815ce25e40c4088bbf8b7ac60314'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder1/subfolder1/.r4n50mw4r3-d373c70r.txt', 'hash': '00cd5c2b7d6b1a1831aeb6c10a9ee6c5c858f330'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder1/subfolder2/.r4n50mw4r3-d373c70r.txt', 'hash': '53090460002c8ce7371e3bf5ea89336da8069bc5'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder2/.r4n50mw4r3-d373c70r.txt', 'hash': '9f6c00cea0ddf50b962019b984f30082826b3219'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder2/subfolder1/.r4n50mw4r3-d373c70r.txt', 'hash': 'aea3d2729832692948fc62603e02e1245838c235'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder2/subfolder2/.r4n50mw4r3-d373c70r.txt', 'hash': 'c4aabdcc705b5ef5d648aac1a23fd40fc3e72f86'}]

    maior = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder61/subfolder44/SMM1xQuoeMQ4G1ZXHyh3waLgn.capybara"
    menor = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder61/subfolder44/"

    if menor in maior:
        print('Yes')

    for el in json_file_data:
        for p in event_paths:
            if p in el['absolute_path']:
                print("TRUE")


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


def checkio():
    psutil.Process(188842).io


def trydelete():
    new_json_file_data = []
    to_delete = []

    json_file_data = ["PATO", "CACHORRO", "IGUANA", "FOCA", "CAPIVARA"]
    event_paths = ["CACHORRO", "IGUANA"]

    for element in json_file_data:
        for event_path in event_paths:
            if event_path in element:
                if event_path not in to_delete:
                    to_delete.append(element)

    for element in json_file_data:
        if element not in to_delete:
            new_json_file_data.append(element)

    print(new_json_file_data)


trydelete()
