from AES import aes_encrypt

# Função para validar se a chave está em formato hexadecimal
def validate_hex_key(key):
    try:
        bytes.fromhex(key)  # Tenta converter a chave de hexadecimal para bytes
        return True
    except ValueError:
        return False

# Configurar parâmetros
key = '546869734973413136427974654b6579'  # Chave válida em hexadecimal (128 bits)

iv = '1234567890abcdef1234567890abcdef'  # IV válido em hexadecimal (16 bytes)

input_file = 'arquivo_claro.txt'
output_file = 'arquivo_criptografado.aes'

# Verificar se a chave está em formato hexadecimal
if validate_hex_key(key):
    print("Chave válida.")
else:
    print("Chave inválida. Verifique o formato.")

# Chamar a função de criptografia
aes_encrypt(
    key=key, 
    iv=iv, 
    input_file=input_file, 
    output_file=output_file, 
    key_format="hex",  # Indica que a chave está em hexadecimal
    iv_format="hex",  # Indica que o IV está em hexadecimal
    key_size=128,  # Tamanho da chave de 128 bits
    mode="CBC",  # Modo de operação CBC
    output_format="hex"  # Saída em formato hexadecimal
)
