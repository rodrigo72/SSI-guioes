# Respostas das Questões

## Q1

> Qual o impacto de executar o programa chacha20_int_attck.py sobre um criptograma produzido por pbenc_chacha20_poly1305.py? Justifique.

Não é possível atacar com sucesso um criptograma produzido por `pbenc_chacha20_poly1305.py` com `chacha20_int_attck.py`, visto que oferece integridade e confidencialidade (combinação de ChaCha20 e [Poly1305](https://en.wikipedia.org/wiki/Poly1305)).

![alt text](image-5.png)
![alt text](image-6.png)
## Q2

> Qual o motivo da sugestão de usar m2 com mais de 16 byte? Será possível contornar essa limitação?

Primeiramente, é necessário perceber como funciona o `symmetric padding` utilizado:

> [PKCS7](https://cryptography.io/en/latest/hazmat/primitives/padding/) padding works by appending N bytes with the value of chr(N), where N is the number of bytes required to make the final block of data the same size as the block size. 

Portanto, o padding é feito com N bytes com o valor `char(N)`, e não apenas `0`, o que faz com que a operação XOR entre o padding e a tag seja também significativa.

Exemplo de um caso simples:

![alt text](image.png)

```python
padder = padding.PKCS7(128).padder()
padded_m1 = padder.update(m1) + padder.finalize()

padder = padding.PKCS7(128).padder()
padded_m2 = padder.update(m2) + padder.finalize()

new_m2 = bytes(x ^ y for x, y in zip(padded_m2[:16], tag1)) + m2[16:]

m3 = padded_m1 + new_m2
```

No entanto, desta forma o comprimento de `m3` aumenta para um múltiplo de 16, o que faz com que a função `cbcmac_verify` adicione mais 16 bytes de padding, acabando por diferir com `m2` e portanto resultará em `False`:

![alt text](image-1.png)

Caso se impeça que essa adição de padding aconteça, já retornará `True`.

```python
def cbcmac_verify(tag, m_bytes, k):
    # padder = padding.PKCS7(128).padder()
    # padded_m = padder.update(m_bytes) + padder.finalize()
    iv = bytearray(16)
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(m_bytes) + encryptor.finalize()
    newtag = ct[-16:]
    return tag == newtag
```

![alt text](image-2.png)

Apesar disso, reconhecemos que esta não é melhor forma de contornar a limitação - é muito provável que exista uma melhor.

# Relatório do Guião da Semana 5

## Ataque CBC-MAC

Lógica utilizada para o ataque ao CBC-MAC:

![alt text](image-3.png)

![alt text](image-4.png)

Primeiramente, é preciso ter um MAC `t` para uma mensagem `m`, e um MAC `t'` para uma mensagem `m'`. Depois, faz-se uma concatenação de `m` (com padding) com o XOR entre o primeiro bloco de `m'` e a tag `t`, e, finalmente, com o resto de `m'`. A tag `t'` seŕa válida para o resultado dessa concatenação.

## Encrypt-then-MAC

Solicitamos mais bytes à KDF utilizada para derivar a chave:

```python
h = hmac.HMAC(key[32:], hashes.SHA256())
...
algorithm = algorithms.AES(key[:32])
```

Os primeiros 16 bytes do ciphertext são o nonce, os restantes são o texto encriptado, exceto os últimos 32 que são a *signature* (verificada pelo HMAC).

(O HMAC recebe o nonce e o texto encriptado juntos, mas a cifra AES no modo CTR recebe esses dois separadamente).
