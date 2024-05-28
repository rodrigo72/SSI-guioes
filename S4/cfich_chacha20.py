import sys, os
from utils import write_bytes_to_file, read_file_as_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def generate_random_bytes(n_bytes: int) -> bytes:
    return os.urandom(n_bytes)


def encrypt_file(filename: str, text: bytes, key: bytes):
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(text) + encryptor.finalize()
    
    write_bytes_to_file(filename + ".enc", nonce + ciphertext)


def decrypt_file(filename: str, text: bytes, key: bytes):
    nonce = text[:16]
    ciphertext = text[16:]

    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    write_bytes_to_file(filename + ".dec", plaintext)


def main():
    if len(sys.argv) < 3:
        print("Usage:", 
              "\n\tpython cfich_chacha20.py [enc|dec] <fich> <fkey>",
              "\n\tpython cfich_chacha20.py setup <fkey>")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'setup':
        random_bytes = generate_random_bytes(32)
        write_bytes_to_file(sys.argv[2], random_bytes)
    elif mode == 'enc':
        text = read_file_as_bytes(sys.argv[2])
        key = read_file_as_bytes(sys.argv[3])
        encrypt_file(sys.argv[2], text, key)
    elif mode == 'dec':
        text = read_file_as_bytes(sys.argv[2])
        key = read_file_as_bytes(sys.argv[3])
        decrypt_file(sys.argv[2], text, key)
    else:
        print("Mode must be 'setup' for generating a key file or 'enc'/'dec' for encoding/decoding.")
        sys.exit(1)
    
    
if __name__ == "__main__":
    main()