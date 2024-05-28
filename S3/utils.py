import unicodedata, sys, os

from collections import Counter
from typing import Final, Dict, List
from string import ascii_uppercase, ascii_lowercase

ALPHABET_UPPER: Final[str] = ascii_uppercase
ALPHABET_LOWER: Final[str] = ascii_lowercase
ALPHABET_SIZE: Final[int] = 26
BASE: Final[int] = ord('A')

LETTER_FREQUENCY_PT: Dict[str, float] = {
    'a': 14.63, 'b':  1.04, 'c':  3.88,
    'd':  4.99, 'e': 12.57, 'f':  1.02,
    'g':  1.30, 'h':  1.28, 'i':  6.18,
    'j':  0.40, 'k':  0.02, 'l':  2.78,
    'm':  4.74, 'n':  5.05, 'o': 10.73,
    'p':  2.52, 'q':  1.20, 'r':  6.53,
    's':  7.81, 't':  4.34, 'u':  4.63,
    'v':  1.67, 'w':  0.01, 'x':  0.21,
    'y':  0.01, 'z':  0.47
}


def preprocess_message(message: str) -> str:
    """Converte letras para maiúsculas, 'filtra' todos os outros caracteres e remove acentos."""
    normalized_message = ''.join(c.upper() for c in message if c.isalpha())
    normalized_message = unicodedata.normalize('NFD', normalized_message)
    return ''.join(c for c in normalized_message if not unicodedata.combining(c))


def calculate_score(text: str, 
                    letter_freq: Dict[str, float] = LETTER_FREQUENCY_PT,
                    alphabet: str = ALPHABET_LOWER) -> float:
    """Retorna a média dos scores de cada letra : (sum_{i=1}^{26} |fe - fi|) / 26"""
    assert len(text) > 0
    text = text.lower()
    counter = Counter(text)
    return sum(
        [abs((counter.get(letter, 0) * 100 / len(text)) - letter_freq[letter]) for letter in alphabet]
    ) / len(alphabet)


def check_words(text: str, word_list: List[str]) -> bool:
    """Verifica se uma das palavras da lista está presente num texto"""
    text = text.upper()
    for word in word_list:
        if word.upper() in text:
            return True
    return False


def read_file_as_bytes(file_path: str) -> bytes:
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, 'rb') as file:
        byte_list = file.read()
    return byte_list


def write_bytes_to_file(file_path: str, byte_list: bytes):
    with open(file_path, 'wb') as file:
        file.write(byte_list)
