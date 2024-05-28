import sys
import os
from utils import write_bytes_to_file, read_file_as_bytes


def otp(key: bytes, message: bytes) -> bytes:
    """
    Aplica a cifra One-Time Pad (OTP) a uma mensagem utilizando uma chave dada.

    Args:
        key (bytes): A chave de encriptação, deve ter comprimento igual ou superior à mensagem.
        message (bytes): A mensagem em texto simples a ser encriptada.

    Returns:
        bytes: A mensagem encriptada.

    Raises:
        AssertionError: Se o comprimento da chave for inferior ao comprimento da mensagem.

    Note:
        A encriptação OTP requer que a chave tenha comprimento igual ou superior à mensagem.
        A função aplica a operação XOR a cada byte da chave com o byte correspondente da mensagem.
        O resultado é devolvido como um objeto bytes.
    """

    assert len(key) >= len(message)
    result = [b1 ^ b2 for b1, b2 in zip(key, message)]
    return bytes(result)


def generate_random_bytes(n_bytes: int) -> bytes:
    return os.urandom(n_bytes)


def aux_enc_dec(key_file: str, message_file: str, mode: str):
    key_file = sys.argv[2]
    message_file = sys.argv[3]

    if not os.path.isfile(key_file):
        print(f"Error: Key file '{key_file}' not found.")
        sys.exit(1)
    if not os.path.isfile(message_file):
        print(f"Error: Message file '{message_file}' not found.")
        sys.exit(1)

    key = read_file_as_bytes(key_file)
    message = read_file_as_bytes(message_file)

    if len(message) > len(key):
        print(f"Error: Lengths of key and message must be the same ({len(key)};{len(message)})")
        sys.exit(1)

    if mode == 'enc':
        result = otp(key, message)
        write_bytes_to_file(message_file + '.enc', result)
    else:
        result = otp(key, message)
        write_bytes_to_file(message_file + '.dec', result)


def main():
    if len(sys.argv) != 4:
        print("Usage:  python otp.py [enc|dec] key_filename message_filename",
              "\n\tpython otp.py setup n_bytes key_filename")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'setup':
        random_bytes = generate_random_bytes(int(sys.argv[2]))
        write_bytes_to_file(sys.argv[3], random_bytes)
    elif mode in ['enc', 'dec']:
        aux_enc_dec(sys.argv[2], sys.argv[3], mode)
    else:
        print("Mode must be 'setup' for generating a key file or 'enc'/'dec' for encoding/decoding.")
        sys.exit(1)


if __name__ == "__main__":
    main()
