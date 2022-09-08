import os
from time import perf_counter
import multiprocessing


class DirectoryCreator:
    def __init__(self, root_dir, folders_to_create, sub_folders_to_create, files_to_create, delete_only):
        self.root_dir = root_dir
        self.folders_to_create = folders_to_create
        self.sub_folders_to_create = sub_folders_to_create
        self.files_to_create = files_to_create
        self.delete_only = delete_only

    def createRootDirectory(self):
        if not os.path.exists(self.root_dir):
            print(f"Creating directory {self.root_dir}")
            os.mkdir(self.root_dir)

        elif os.path.exists(self.root_dir):
            print(f"Deleting directory {self.root_dir}")
            for current_path, folders_in_current_path, files_in_current_path in os.walk(self.root_dir, topdown=False):
                for file in files_in_current_path:
                    os.remove(os.path.join(current_path, file))
                for folder in folders_in_current_path:
                    os.rmdir(os.path.join(current_path, folder))
            os.rmdir(self.root_dir)

            if not self.delete_only:
                print(f"Creating directory {self.root_dir}")
                os.mkdir(self.root_dir)
            else:
                quit()

    def createFoldersAndSubfolders(self):
        index = 1
        index2 = 1
        print("Creating folders and subfolders")
        while index <= self.folders_to_create:
            os.makedirs(self.root_dir + f"/folder{str(index)}")
            while index2 <= self.sub_folders_to_create:
                os.makedirs(self.root_dir + f"/folder{str(index)}/subfolder{str(index2)}")
                index2 += 1
            index2 = 1
            index += 1

    def createDirectoryList(self):
        print("Creating absolute directory list")
        dirlist = []
        for current_path, _, _ in os.walk(self.root_dir):
            if "encrypt-test" in current_path and "folder" in current_path and "subfolder" in current_path:
                dirlist.append(current_path)
        return dirlist

    def createFiles(self, dirlist):
        index = 1
        dir_index = 0
        files_created = 0
        all_files_size = 0
        with open("/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/1kb_template_file.txt", 'r') as file_bytes:
            file_data = file_bytes.read()

        print("Creating files for each directory in list")
        for dir in dirlist:
            while index <= self.files_to_create:
                file_path = dir + '/' + 'file' + str(index) + ".txt"
                with open(file_path, 'w') as file:
                    file.write(file_data)
                all_files_size = all_files_size + int(os.stat(file_path).st_size)
                index += 1
                files_created += 1
            index = 1
            dir_index += 1

        print(f"Directories created: {dir_index}")
        print(f"All files inside total size: {all_files_size / 1000000}MB")

    def run(self):
        self.createRootDirectory()
        self.createFoldersAndSubfolders()
        dirlist = self.createDirectoryList()
        self.createFiles(dirlist)


if __name__ == "__main__":
    dc = DirectoryCreator(
        root_dir="/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/",
        folders_to_create=5,
        sub_folders_to_create=2000,
        files_to_create=10,
        delete_only=False
    )
    start = perf_counter()
    dc.run()
    end = perf_counter()
    print(f"Finished in {round(end - start,3)}s")
    quit()
    proc = multiprocessing.Process(target=dc.run())  # instantiating without any argument
    proc.start()
    proc.join()
