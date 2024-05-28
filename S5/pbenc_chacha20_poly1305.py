import os, sys
from utils import write_bytes_to_file, read_file_as_bytes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

"""
Provide both confidentiality and integrity
"""


def encrypt_file(filename: str, text: bytes, password: bytes):
    key = ChaCha20Poly1305.generate_key()
    write_bytes_to_file('poly1305.key', key)
    
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, text, password)
    
    write_bytes_to_file(filename + ".enc", nonce + ct)



def decrypt_file(filename: str, text: bytes, password: bytes):
    nonce = text[:12]
    ct = text[12:]

    key = read_file_as_bytes('poly1305.key')
    chacha = ChaCha20Poly1305(key)
    decrypted = chacha.decrypt(nonce, ct, password)    

    write_bytes_to_file(filename + ".dec", decrypted)


def main():
    if len(sys.argv) < 2:
        print("Usage:", 
              "\n\tpython pbenc_chacha20_poly1305.py [enc|dec] <fich>")
        sys.exit(1)

    mode = sys.argv[1]
    password = input("Enter password: ").encode('utf-8')
    text = read_file_as_bytes(sys.argv[2])

    if mode == 'enc': 
        encrypt_file(sys.argv[2], text, password)
    elif mode == 'dec':
        decrypt_file(sys.argv[2], text, password)
    else:
        print("Mode must be 'enc'/'dec' for encoding/decoding.")
        sys.exit(1)    
    
    
if __name__ == "__main__":
    main()
