import sys, os


def read_file_as_bytes(file_path: str) -> bytes:
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, 'rb') as file:
        byte_list = file.read()
    return byte_list


def write_bytes_to_file(file_path: str, byte_list: bytes):
    with open(file_path, 'wb') as file:
        file.write(byte_list)