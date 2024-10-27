from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Função para criptografar
def aes_cifrar(key, iv, input_file, output_file, key_format, iv_format, key_size, mode_OP, output_format):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Converter a chave para bytes de acordo com o formato selecionado
    if key_format.lower() == "hex":
        key = bytes.fromhex(key)  # Convertendo HEX para bytes
    else:
        key = key.encode('utf-8')  # Convertendo UTF-8 para bytes
    
    if iv_format.lower() == "hex":
        iv = bytes.fromhex(iv)
    else:
        iv = iv.encode('utf-8')

    if key_size == 128:
        key = key[:16]
    elif key_size == 192:
        key = key[:24]
    elif key_size == 256:
        key = key[:32]

    if mode_OP == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode_OP == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    if output_format == "base64":
        ciphertext = base64.b64encode(ciphertext)
    elif output_format == "hex":
        ciphertext = ciphertext.hex().encode('utf-8')

    with open(output_file, 'wb') as f:
        f.write(ciphertext)

    print(f"Arquivo {input_file} criptografado como {output_file}")

# Função para descriptografar
def aes_decifrar(key, iv, input_file, output_file, key_format, iv_format, key_size, mode_OP, input_format):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    # Converter a chave para bytes de acordo com o formato selecionado
    if key_format.lower() == "hex":
        key = bytes.fromhex(key)  # Convertendo HEX para bytes
    else:
        key = key.encode('utf-8')  # Convertendo UTF-8 para bytes
    
    if iv_format.lower() == "hex":
        iv = bytes.fromhex(iv)
    else:
        iv = iv.encode('utf-8')

    if key_size == 128:
        key = key[:16]
    elif key_size == 192:
        key = key[:24]
    elif key_size == 256:
        key = key[:32]

    if input_format == "base64":
        ciphertext = base64.b64decode(ciphertext)
    elif input_format == "hex":
        ciphertext = bytes.fromhex(ciphertext.decode('utf-8'))

    if mode_OP == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode_OP == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"Arquivo {input_file} descriptografado como {output_file}")
