import sys
from utils import ALPHABET_UPPER, ALPHABET_SIZE, BASE, preprocess_message


def vigenere(mode: str, keyword: str, message: str) -> str:
    """
    Retorna a mensagem criptografada ou descriptografada, dependendo do modo especificado.

    Args:
        mode: indica se a função deve criptografar ou descriptografar a mensagem utilizando a cifra de Vigenère.
        keyword: chave utilizada na cifra de Vigenère.
        message: mensagem a ser criptografada ou descriptografada.
            
    Note: No ataque vamos considerar um tamanho da chave conhecido
            - pesquisar acerca do caso em que não se sabe o tamanho da chave

    [Verificação](https://cryptii.com/pipes/vigenere-cipher)
    [Visualização](https://youtu.be/rccRQcyKB5g?si=UMLCAKBgeUWRDTfP)
    """
    
    assert keyword.isupper()
    assert message.isupper()
    
    result = ''
    keyword_length = len(keyword)
            
    for i, char in enumerate(message):
        if char.isalpha():
            ord_key = ord(keyword[i % keyword_length])
            if mode == 'enc':
                index = ALPHABET_UPPER.index(char) + (ord_key - BASE)
            elif mode == 'dec':
                index = ALPHABET_UPPER.index(char) - (ord_key - BASE)
            result += ALPHABET_UPPER[index % ALPHABET_SIZE]
        else:
            result += char

    return result


def main():
    if len(sys.argv) != 4:
        print("Usage: python vigenere.py [enc|dec] keyword message")
        sys.exit(1)

    mode = sys.argv[1]
    secret_key = preprocess_message(sys.argv[2])
    message = preprocess_message(sys.argv[3])

    if mode not in ['enc', 'dec']:
        print("Mode must be 'enc' for encoding or 'dec' for decoding.")
        sys.exit(1)
        
    if len(secret_key) == 0:
        print("Invalid key")
        sys.exit(1)
    elif len(message) == 0:
        print("Invalid message")
        sys.exit(1)

    result = vigenere(mode, secret_key, message)
    print(result)
    

if __name__ == "__main__":
    main()
