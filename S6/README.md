# Relatório do Guião da Semana 6

## PROG: Client_sec.py e Server_sec.py

> Pretende-se modificar os programas fornecidos por forma a protegeram a comunicação entre Cliente/Servidor. Para isso deverá fazer uso de uma cifra autenticada como as utilizadas no último guião (e.g. AES-GCM).

O server e o cliente têm de ter conhecimento de uma chave combinada de modo a conseguirem comunicar com mensagens cifradas. Para além disso, têm de enviar também o nonce criado, para além da mensagem cifrada:

```py
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, msg, password)
writer.write(nonce + ct)
```

## PROG: Client_dh.py e Server_dh.py

> Pretende-se adaptar os programas realizados no ponto anterior para que a chave por eles utilizada resulte da execução do protocolo de acordo de chaves Diffie-Hellman.

Para isso, foi necessário alterar os programas de modo a que fosse efetuado um "handshake inicial" em qua cada um partilha a sua chave pública.
E assim cada um fica com mesma shared key: `shared_key = private_key.exchange(peer_public_key)`. (p e g são fixos).
O segredo criptográfico utilizado para cifrar e decifrar é derivado a partir dessa shared key `key = hkdf.derive(shared_key)`.

As public keys têm de ser serializadas (para `bytes`) antes de serem enviadas, e têm de ser deserializadas, quando recebidas, para os tipos de objetos correspondentes. Assim, utilizamos o enconding `PEM`: `pem = public_key.public_bytes( encoding=serialization.Encoding.PEM, ...)`, e para deconding utilizamos a função `load_pem_public_key(...)`.