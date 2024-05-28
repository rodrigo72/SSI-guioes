# Respostas das Questões


## Q1

> Como pode verificar que as chaves fornecidas nos ficheiros mencionados (por exemplo, em MSG_SERVER.key e MSG_SERVER.crt) constituem de facto um par de chaves RSA válido?

Contéudo:
- `openssl rsa -text -noout -in MSG_SERVER.key` com a password '1234'

![alt text](image-1.png)

- `openssl x509 -text -noout -in MSG_SERVER.crt`

![alt text](image.png)

Para verificar que um par de chaves RSA é válido (*private key matches with public key in the certificate*), é preciso comparar o *modulus* da chave pública no certificado com o da chave privada.

`openssl rsa -modulus -noout -in MSG_SERVER.key | openssl md5`
![alt text](image-2.png)

Verificar consistência e validade da chave privada:
`openssl rsa -check -noout -in MSG_SERVER.key`
![alt text](image-3.png)

`openssl x509 -modulus -noout -in MSG_SERVER.crt | openssl md5`
![alt text](image-4.png)

Ou:
```bash
openssl x509 -noout -modulus -in MSG_SERVER.crt > crt-mod.txt
openssl rsa -noout -modulus -in MSG_SERVER.key > key-mod.txt
diff3 crt-mod.txt key-mod.txt
```

## Q2

> Visualize o conteúdo dos certificados fornecidos, e refira quais dos campos lhe parecem que devam ser objecto de atenção no procedimento de verificação.

![alt text](image-5.png)

# Relatório do Guião da Semana 7

![alt text](image-6.png)

Notes:
- Pode-se confiar na chave pública do Server, por exemplo, pois esta está no certificado enviado que é comprovado por uma _trusted third party_, CA.
- Caso, por exemplo, a chave pública do servidor (DL) for modificada no caminho, esta não será igual à que está na assinatura e, portanto, não será possível validar a assinatura.
- Assim, para além de um _intruder_ nunca conseguir saber qual é a chave partilhada, também não conseguirá realizar ataques de man-in-the-middle.