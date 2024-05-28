import sys, os
from utils import read_file_as_bytes, write_bytes_to_file

NONCE_LENGTH = 16


def main():
    if len(sys.argv) != 5:
        print("Usage:", 
              "\n\tpython chacha20_int_attck.py <fctxt> <pos> <ptxAtPos> <newPtxtAtPos>")
        sys.exit(1)
    
    filename = sys.argv[1]
    encrypted_file = read_file_as_bytes(filename)
    pos = int(sys.argv[2]) + NONCE_LENGTH
    text = sys.argv[3].encode('utf-8')
    new_text = sys.argv[4].encode('utf-8')
    
    if (len(text) != len(new_text)):
        print('<ptxAtPos> and  <newPtxtAtPos> must have equal length')
        sys.exit(1)
    
    encrypted_text = encrypted_file[pos : pos + len(text)]

    """
            text xor key = encrypted_text
            text xor (text xor key) = text xor encrypted_text
            (text xor text) xor key = text xor encrypted_text
            key = text xor encrypted_text
    """
    
    key = bytes([b1 ^ b2 for b1, b2 in zip(text, encrypted_text)])
    new_encrypted_text = bytes([b1 ^ b2 for b1, b2 in zip(new_text, key)])
    
    new_encrypted_file = encrypted_file[:pos] + new_encrypted_text + encrypted_file[pos + len(new_encrypted_text):]
    write_bytes_to_file(filename + ".attck", new_encrypted_file)
        
    
if __name__ == "__main__":
    main()