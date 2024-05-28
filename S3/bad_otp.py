import sys, random
from otp import aux_enc_dec
from utils import write_bytes_to_file


def bad_prng(n):
    """ an INSECURE pseudo-random number generator """
    random.seed(random.randbytes(2))
    return random.randbytes(n)


def main():
    if len(sys.argv) != 4:
        print("Usage:  python otp.py [enc|dec] key_filename message_filename",
              "\n\tpython otp.py setup n_bytes key_filename")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'setup':
        random_bytes = bad_prng(int(sys.argv[2]))
        write_bytes_to_file(sys.argv[3], random_bytes)
    elif mode in ['enc', 'dec']:
        aux_enc_dec(sys.argv[2], sys.argv[3], mode)
    else:
        print("Mode must be 'setup' for generating a key file or 'enc'/'dec' for encoding/decoding.")
        sys.exit(1)


if __name__ == '__main__':
    main()
