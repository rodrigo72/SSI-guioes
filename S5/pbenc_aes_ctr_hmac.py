import sys, os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils import write_bytes_to_file, read_file_as_bytes


def encrypt_file(filename: str, text: bytes, password: bytes):
    
    salt = os.urandom(16);
    write_bytes_to_file('salt', salt);

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=480000,
    )
    
    key = kdf.derive(password);
    write_bytes_to_file("pbenc.key", key)
        
    nonce = os.urandom(16)
    algorithm = algorithms.AES(key[:32])
    cipher = Cipher(algorithm, modes.CTR(nonce))
    encryptor = cipher.encryptor()
    
    ciphertext = nonce + (encryptor.update(text) + encryptor.finalize())
    
    h = hmac.HMAC(key[32:], hashes.SHA256())
    h.update(ciphertext)
    signature = h.finalize()
    
    write_bytes_to_file(filename + ".enc", ciphertext + signature)


def decrypt_file(filename: str, text: bytes, password: bytes):
        
    salt = read_file_as_bytes('salt')
    key = read_file_as_bytes("pbenc.key")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=480000,
    )
    
    kdf.verify(password, key)

    nonce = text[:16]
    ciphertext = text[:-32]
    signature = text[-32:]
    
    h = hmac.HMAC(key[32:], hashes.SHA256())
    h.update(ciphertext)
    h.verify(signature)
    
    algorithm = algorithms.AES(key[:32])
    cipher = Cipher(algorithm, modes.CTR(nonce))
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

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
        encrypt_file(sys.argv[2], text, password)
    elif mode == 'dec':
        decrypt_file(sys.argv[2], text, password)
    else:
        print("Mode must be 'setup' for generating a key file or 'enc'/'dec' for encoding/decoding.")
        sys.exit(1)    
    
    
if __name__ == "__main__":
    main()
