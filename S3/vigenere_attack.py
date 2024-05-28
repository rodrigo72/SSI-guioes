import sys

from cesar import cesar
from math import inf
from typing import Tuple
from utils import calculate_score, check_words, ALPHABET_UPPER


def vigenere_attack(cryptogram: str, key_size: int) -> Tuple[str, str]:
    """
    Ataca uma cifra de Vigenère encontrando a chave que minimiza o score do texto decifrado.

    Args:
        cryptogram (str): O criptograma a ser decifrado.
        key_size (int): O tamanho da chave utilizada.

    Returns:
        Tuple[str, str]: Uma tupla contendo a chave decifrada e o texto decifrado.
    """
    lowest_scores = [inf] * key_size
    chosen_keyword = [''] * key_size
    decyphered_text = [''] * len(cryptogram)
    
    for idx in range(key_size):
        result_str = cryptogram[idx::key_size]
        decyphered_part = ''
        
        for key in ALPHABET_UPPER:
            current_text = cesar('dec', key, result_str)
            current_score = calculate_score(current_text)
            
            if current_score < lowest_scores[idx]:
                lowest_scores[idx] = current_score
                chosen_keyword[idx] = key
                decyphered_part = current_text
                
        decyphered_text[idx::key_size] = decyphered_part
                
    return ''.join(chosen_keyword), ''.join(decyphered_text)


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 vigenere_attack.py keysize cryptogram word1 [word2 ...]")
        sys.exit(1)

    key_size = int(sys.argv[1])
    cryptogram = sys.argv[2]
    words = sys.argv[3:]
    
    chosen_key, decyphered_text = vigenere_attack(cryptogram, key_size)
    if check_words(decyphered_text, words):
        print(chosen_key)
        print(decyphered_text)


if __name__ == "__main__":
    main()
