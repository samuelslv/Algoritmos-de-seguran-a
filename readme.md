# Algortimos de Criptografia
## Trabalho 01 – Implementação: Algortimos de Criptografia
Este projeto visa desenvolver um programa que permite operações criptográficas com mensagens em texto. As 
operações implementadas devem ser compatíveis entre os programas e a ferramenta online CyberChef
(https://gchq.github.io/CyberChef/), de modo que é possível cifrar em um programa e decifrar em outro. O 
programa deve permitir realizar a cifragem e decifragem usando o AES e manipular assinaturas digitais usando o 
RSA. Para viabilizar o uso de assinatura digitais é necessário permitir a criação de pares de chaves, salvando-as em 
arquivos no formato PEM.

## Funções implementadas:

### • Cifragem/Decifragem AES

Entrada: chave + arquivo em claro (ou criptografado) + Vetor de Inicialização (IV)

Saída: arquivo criptografado (ou em claro)

Parâmetros a serem configurados pelo usuário: Tamanho da Chave, Modo de Operação (ECB ou CBC), 
Padrões de entradas/saída (Hexadecimal ou Base64) e Padrões da Chave/IV (HEX ou UTF8)

### • Geração de chaves compatível com o padrão openssl

Entrada: tamanho da chave (1024 ou 2048)

Saída: arquivos com as chaves

Obs.: a chave privada não precisa ter senha

Trecho da chaves (modo texto) 

-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkMqJJLrxXQz9e
.... trecho omitido
dFrNqgwYq00n53+f5V6sKNEhKWXN7a0OJm9yrc4YXXuyKKgzXPh5Rff7droj/xUF

-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY----- dFrNqgwYq00n53+f5V6sKNEhKWXN7a0OJm9yrc4YXXuyKKgzXPh5Rff7droj/xUF 
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkMqJJLrxXQz9e 
.... trecho omitido
r6oMx21wkOgY3P1WFb9dvuBxK+/EUn/Jri7dsLfBv/eS2fUZBsmGyfqwSdJNYwNP

-----END PUBLIC KEY-----

### • Assinatura RSA

Entrada: arquivo chave privada + arquivo em claro

Saída: arquivo com a assinatura

Parâmetro: Versão do SHA-2 (256, 384 ou 512)

Padrões de entradas/saída (Hexadecimal ou Base64)


### • Verificação de Assinatura RSA

Entrada: arquivo chave pública + arquivo em claro + arquivo com a assinatura

Saída: Assinatura válida ou inválida

Parâmetro: Versão do SHA-2 (256, 384 ou 512)