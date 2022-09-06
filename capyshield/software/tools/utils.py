import hashlib
import json
import os
import random
import string
from software.tools.logger import logger
from software.config.shared_config import GeneralConfig as gc


def calcPercentage(directory_count, counter):
    """Função para calcular a regra de 3"""
    v1 = directory_count  # numero de 100%
    v2 = 100  # 100%
    v3 = counter  # número a descobrir a porcentagem
    return v3 * v2 / v1


def returnPercentage(directory_count, counter, porcentage):
    """Função para retornar a porcentagem"""
    for i in range(100):
        counter = round(counter + 0.01, 2)
        if counter == round(directory_count * porcentage, 2):
            logger.debug(f"Working on {'deleting' if gc.delete_honeypots else 'creating'} honeypots: {round(calcPercentage(directory_count, counter))}%")
            porcentage = round(porcentage + 0.1, 2)
    return counter, porcentage


def randomString(action):
    """Função para gerar uma string única e aleatória que ficará dentro de cada honeypot"""
    if action == "unique-hash":
        characters = string.ascii_letters + string.digits + string.punctuation
        random_string = ''.join(random.choice(characters) for i in range(50))
        return random_string
    if action == "unique-name":
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters) for i in range(25))
        return random_string + gc.honeypot_file_extension


def isHexStr(s):
    return set(s).issubset(string.hexdigits)
