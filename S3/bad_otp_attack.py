import sys, random
from utils import read_file_as_bytes, check_words
from typing import List, Final

MAX_ADDITIONAL_KEY_LENGTH: Final[int] = 30


def bad_otp_attack(file: bytes, words: List[str]):
    
    for inc in range(0, MAX_ADDITIONAL_KEY_LENGTH):
        for i in range(256):
            for j in range(256):
                
                seed_input = bytes([i, j])
                random.seed(seed_input)
                key = random.randbytes(len(file) + inc)

                result = [b1 ^ b2 for b1, b2 in zip(key, file)]
            
                try:        
                    result_str = bytes(result).decode('utf-8')
                except:
                    continue        
                    
                if check_words(result_str, words):
                    return result_str
    
    return None


def main():
    if len(sys.argv) < 3:
        print("Usage:  python bad_otp_attack.py filename word1 [word2 ...]")
        sys.exit(1)

    filename = sys.argv[1]
    words = sys.argv[2:]
    
    file = read_file_as_bytes(filename)
    
    result = bad_otp_attack(file, words)
    if result != None:
        print(result)


if __name__ == '__main__':
    main()