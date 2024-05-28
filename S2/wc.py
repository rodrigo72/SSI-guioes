import sys

def wc(filename):
    with open(filename, 'rb') as file:
        content = file.read()
        line_count = content.count(b'\n')
        word_count = len(content.split())
        char_count = len(content)
    
    print(f" {line_count} {word_count} {char_count} {filename}")


def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    filename = sys.argv[1]
    wc(filename)


if __name__ == "__main__":
    main()
