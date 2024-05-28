import sys
from utils import ALPHABET_UPPER, ALPHABET_SIZE, BASE, preprocess_message


def cesar(mode: str, secret_key: chr, message: str) -> str:
    """
    Retorna a mensagem criptografada ou descriptografada, dependendo do modo especificado.

    Args:
        mode: indica se a função deve criptografar ou descriptografar a mensagem.
        secret_key: chave secreta utilizada na cifra de César.
        message: mensagem a ser criptografada ou descriptografada.
        
    [Verificação](https://cryptii.com/pipes/caesar-cipher)
    """
    
    assert secret_key.isupper()
    assert message.isupper()
    
    result = ''
        
    shift_values = {'enc': ord(secret_key) - BASE, 'dec': -(ord(secret_key) - BASE)}
    shift = shift_values.get(mode)
    if shift is None:
        return None
        
    for char in message:
        if char.isalpha():
            result += ALPHABET_UPPER[(ALPHABET_UPPER.index(char) + shift) % ALPHABET_SIZE]
        else:
            result += char
    
    return result


def main():
    if len(sys.argv) != 4:
        print("Usage: python cesar.py [enc|dec] key message")
        sys.exit(1)

    mode = sys.argv[1]
    secret_key = preprocess_message(sys.argv[2])
    message = preprocess_message(sys.argv[3])

    if mode not in ['enc', 'dec']:
        print("Mode must be 'enc' for encoding or 'dec' for decoding.")
        sys.exit(1)
        
    if len(secret_key) != 1:
        print("Invalid key")
        sys.exit(1)
    elif len(message) == 0:
        print("Invalid message")
        sys.exit(1)

    result = cesar(mode, secret_key, message)
    print(result)


if __name__ == "__main__":
    main()
