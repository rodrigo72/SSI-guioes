# Respostas das Questões

## Q1

> Consegue observar diferenças no comportamento dos programas otp.py e bad_otp.py? Se sim, quais?

A diferença entre os dois programas está no modo de gerar uma sequência de bytes aleatórios.

O `otp.py` utiliza `return os.urandom(n_bytes)`, enquanto que o `bad_otp.py` utiliza `random.seed(random.randbytes(2)); random.randbytes(n)` &mdash; $2^{16} = 65536$ combinações possíveis. Eventualmente, para um $n$ grande, poderá haver repetições na sequência de bytes gerados.



## Q2

> O ataque realizado no ponto anterior não entra em contradição com o resultado que estabelece a "segurança absoluta" da cifra one-time pad? Justifique.

Em teoria o OTP é seguro (possui "segurança absoluta"), no entanto, surgem problemas de segurança quando a geração da chave não é verdadeiramente aleatória.

Neste caso, sabendo a seed e método de geração utilizado, é possível, através de um certo número de iterações &mdash; dependente do tamanho da seed &mdash; decifrar a mensagem. Para além disso, também não assegura integrididade.


# Relatório do Guião da Semana 3

## Utils

Contém algumas constantes (alfabeto, frequências das letras da língua portuguesa, letra de base para as cifras, etc.), e funções genéricas/ utilizadas por mais do que um ficheiro, como:
- `read_file_as_bytes`;
- `write_bytes_to_file`;
- `check_words` - verifica se uma das palavras da lista está presente num texto;
- `calculate_score` - Retorna a média dos scores de cada letra;
- `preprocess_message` - converte letras para maiúsculas, 'filtra' todos os outros caracteres e remove acentos.

## César

Nesta cifra, cada letra avança, circularmente, um certo número de vezes no alfabeto. A chave é dada pela letra para qual uma letra `BASE` avança quando cifrada. ([Website utilizado para verificação](https://cryptii.com/pipes/caesar-cipher)).


No ataque, tentamos decifrar um texto com todas a letras do alfabeto, e, para cada uma, é dado um score que verifica se as frequências das letras do texto decifrado estão próximas das frequências "tabeladas" através do cálculo $(\sum_{i=1}^{26} |f_{e} - f_{i}|) / 26$.

Também foi feita uma função que tenta encontrar a chave usada para cifrar um texto, caso se saiba da existência de uma palavra nesse texto (não foi pedida no guião).


## Vigenère

A lógica é semelhante à utilizada na cifra de César, mas utiliza uma *keyword*/ sequência de letras em vez de apenas uma letra como chave. Por exemplo, caso `len(texto) == 10` e `len(chave) == 3`, as posições 0, 3, 6 e 9 do texto serão cifradas com a letra na posição 0 da chave.

- [Verificação](https://cryptii.com/pipes/vigenere-cipher)
- [Visualização](https://youtu.be/rccRQcyKB5g?si=UMLCAKBgeUWRDTfP)

No ataque, encontra-se uma cifra que minimiza o score do texto decifrado. Para isso, é utilizada a mesma lógica do ataque da cifra de césar, mas por intervalos de posições, `cryptogram[idx::key_size]` &mdash; tendo em conta que se sabe o tamanho da chave.


## OTP

A encriptação OTP requer que a chave tenha comprimento igual ou superior à mensagem de modo a aplicar a operação XOR a cada byte da chave com o byte correspondente da mensagem, `[b1 ^ b2 for b1, b2 in zip(key, message)]`.

O programa `bad_otp.py` utiliza "an INSECURE pseudo-random number generator".

No ataque ao `bad_otp`, são percorridas todas as seeds (65536) até se verificar `check_words(result_str, words)`. (Caso essas iterações não consigam decifrar, estas serão executadas novamente com um incremento no tamanho da chave &mdash; assume-se que pode ser maior do que o tamanho da mensagem).