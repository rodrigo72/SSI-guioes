# Respostas das Questões

## Q2

> Qual o impacto de se considerar um *NONCE* fixo (e.g. tudo 0)? Que implicações terá essa prática na segurança da cifra?

Considerar um NONCE fixo, como um valor de todos os bits igual a zero, pode comprometer seriamente a segurança da cifra. Isso pode levar à reutilização do NONCE, vazamento de informações, vulnerabilidade a ataques criptográficos e comprometimento da confidencialidade dos dados cifrados. Isso permite que um atacante aplique um ataque de repetição, onde o mesmo texto cifrado é retransmitido.


## Q3

> Qual o impacto de utilizar o programa chacha20_int_attck.py nos criptogramas produzidos pelos programas cfich_aes_cbc.py e cfich_aes_ctr.py? Comente/justifique a resposta.

O programa `chacha20_int_attck.py` é projetado para realizar um ataque de integridade em arquivos criptografados usando o algoritmo `ChaCha20`. Ele explora a propriedade do algoritmo `ChaCha20` em que o texto cifrado pode ser manipulado sem a necessidade da chave de criptografia, apenas conhecendo parte do texto original e sua posição no arquivo.

Os programas `cfich_aes_cbc.py` e `cfich_aes_ctr.py`, por outro lado, utilizam os modos de operação `CBC (Cipher Block Chaining)` e `CTR (Counter)`, respectivamente, do algoritmo AES para criptografar arquivos. Esses modos de operação têm propriedades diferentes em comparação com o `ChaCha20`, e o ataque proposto pelo `chacha20_int_attck.py` não seria aplicável a eles da mesma maneira.


# Relatório do Guião da Semana 4

## Utils

Contém algumas constantes (alfabeto, frequências das letras da língua portuguesa, letra de base para as cifras, etc.), e funções genéricas/ utilizadas por mais do que um ficheiro, como:
- `read_file_as_bytes`;
- `write_bytes_to_file`;

## cfich_chacha20.py

- encrypt_file: Recebe o nome do arquivo, o texto a ser criptografado e a chave de criptografia. Gera um nonce aleatório, inicializa um objeto Cipher com o algoritmo ChaCha20 e o nonce gerado, cifra o texto usando o encryptor do objeto Cipher e escreve o nonce concatenado com o texto cifrado em um novo arquivo com a extensão ".enc".
    
- decrypt_file: Recebe o nome do arquivo, o texto cifrado e a chave de descriptografia. Extrai o nonce e o texto cifrado do texto fornecido, inicializa um objeto Cipher com o algoritmo ChaCha20 e o nonce extraído, decifra o texto usando o decryptor do objeto Cipher e escreve o texto decifrado em um novo arquivo com a extensão ".dec".

A função main determina o modo de operação de acordo com uma das seguintes opções:

- No modo 'setup', gera uma chave de criptografia aleatória e a escreve em um arquivo especificado.
    
- No modo 'enc' (criptografia), lê o texto do arquivo e a chave de criptografia de arquivos especificados, e então chama a função encrypt_file.
    
- No modo 'dec' (descriptografia), lê o texto cifrado do arquivo e a chave de descriptografia de arquivos especificados, e então chama a função decrypt_file.


## chacha20_int_attck.py

O arquivo criptografado é lido como uma sequência de bytes. A posição em que a alteração será feita é ajustada para levar em conta o comprimento do nonce.

Depois, se não existir nenhum erro, calcula a chave utilizada para criptografar o texto original. Isso é feito através de um XOR entre o texto original e o texto cifrado na posição especificada. Como o XOR é reversível, isso nos dá a chave utilizada na cifração.

Com a chave calculada, o script realiza um XOR entre o novo texto e a chave para obter o novo texto cifrado.

O novo texto cifrado é substituído na posição especificada no arquivo original. O arquivo resultante é então gravado em disco com uma extensão adicional ".attck" para indicar que foi alvo de um ataque de integridade.


## pbenc_chacha20.py

- encrypt_file: Esta função recebe o nome do arquivo, o texto a ser criptografado e a chave de criptografia. Ele gera um nonce aleatório, inicializa um objeto Cipher com o algoritmo ChaCha20 e o nonce fornecido, e então cifra o texto usando o encryptor do objeto Cipher. Por fim, ele escreve o nonce concatenado com o texto cifrado em um novo arquivo com a extensão ".enc".
    
- decrypt_file: Esta função recebe o nome do arquivo, o texto cifrado e a chave de descriptografia. Ela extrai o nonce e o texto cifrado do texto fornecido, inicializa um objeto Cipher com o algoritmo ChaCha20 e o nonce extraído, e então decifra o texto usando o decryptor do objeto Cipher. Por fim, ele escreve o texto decifrado em um novo arquivo com a extensão ".dec".

A função main trata de realizar as seguintes operações:

- Para enc (criptografia), ele gera um *salt* (um valor aleatório usado como entrada para o processo de derivação de chave PBKDF2), cria uma chave derivada da senha usando PBKDF2, cifra o arquivo usando essa chave e escreve o *salt* e a chave em arquivos separados.

- Para dec (descriptografia), ele lê o *salt* do arquivo, gera a chave derivada da senha usando o mesmo processo, verifica se a chave coincide com a chave armazenada anteriormente, e depois decifra o arquivo usando a chave recuperada.
