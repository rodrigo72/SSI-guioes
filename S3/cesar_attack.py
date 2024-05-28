import sys, cesar

from math import inf
from typing import Tuple
from utils import calculate_score, check_words, ALPHABET_UPPER, BASE


def cesar_attack(text: str) -> Tuple[str, str]:
    """
    Ataca a um cifra de César encontrando a chave que minimiza o score do texto decifrado.

    Args:
        text (str): O texto criptografado com uma cifra de César.

    Returns:
        Tuple[str, str]: Um tuplo que contém texto decifrado e a chave escolhida para o decifrar.
    """
    
    lowest_score = inf
    chosen_key = ''
    decyphered_text = ''
    
    for key in ALPHABET_UPPER:
        current_text = cesar.cesar('dec', key, text)
        current_score = calculate_score(current_text)
        
        if current_score < lowest_score:
            lowest_score = current_score
            chosen_key = key
            decyphered_text = current_text
    
    return chosen_key, decyphered_text


def find_word(text: str, word: str) -> str:
    """
    Esta função não foi pedida, mas apeteceu-me faze-la.
    Útil caso se saiba da existência de uma palavra no criptograma.
    """
    word = word.upper()
    text = text.upper()
    len_word = len(word)    
    
    for i, i_char in enumerate(text):
        idx = 0
        shift = ord(i_char) - ord(word[idx])
        for j, j_char in enumerate(text[i:]):
            if j == len_word - 1:
                return chr(shift + BASE)
            elif j < len_word and ord(word[idx]) != ord(j_char) - shift:
                break
            else:
                idx += 1
            
    return ''
        

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 cesar_attack.py cryptogram word1 [word2 ...]")
        sys.exit(1)

    cryptogram = sys.argv[1]
    words = sys.argv[2:]
    
    chosen_key, decyphered_text = cesar_attack(cryptogram)
    if check_words(decyphered_text, words):
        print(chosen_key)
        print(decyphered_text)


if __name__ == "__main__":
    main()
