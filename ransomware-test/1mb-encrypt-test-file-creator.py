import os

folders_to_create = 3
files_to_create = 100
index = 1
dir = "/home/matheusheidemann/Documents/Github/Python-Ransomware-Detector/ransomware-test/encrypt-test"

if not os.path.exists(dir):
    os.mkdir(dir)

with open("/home/matheusheidemann/Documents/Github/Python-Ransomware-Detector/ransomware-test/1mb_template_file.txt", 'r') as file_bytes:
    file_data = file_bytes.read()


while index <= folders_to_create:
    cdir = f"{str(dir)}/folder{str(index)}"
    os.makedirs(cdir + "/files")
    index += 1

dirlist = []
for root, dir, file in os.walk(dir):
    if "encrypt-test" in root and "files" in root:
        dirlist.append(root)
print(dirlist)
index = 1

for dir in dirlist:
    print(dir)
    while index <= files_to_create:
        with open(dir + '/' + 'file' + str(index) + ".txt", 'w') as file:
            file.write(file_data)
            print(dir)
        index += 1
    index = 1
