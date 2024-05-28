import sys, os
from utils import write_bytes_to_file, read_file_as_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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
    if len(sys.argv) < 2:
        print("Usage:", 
              "\n\tpython cfich_chacha20.py [enc|dec] <fich>")
        sys.exit(1)

    mode = sys.argv[1]
    password = input("Enter password: ").encode('utf-8')
    text = read_file_as_bytes(sys.argv[2])

    if mode == 'enc': 
        salt = os.urandom(16);
        write_bytes_to_file('salt', salt);

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        
        key = kdf.derive(password);
        write_bytes_to_file("pbenc.key", key)
        encrypt_file(sys.argv[2], text, key)
        
    elif mode == 'dec':
        salt = read_file_as_bytes('salt')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        
        key = read_file_as_bytes("pbenc.key")
        kdf.verify(password, key)
        decrypt_file(sys.argv[2], text, key)
    else:
        print("Mode must be 'setup' for generating a key file or 'enc'/'dec' for encoding/decoding.")
        sys.exit(1)    
    
    
if __name__ == "__main__":
    main()