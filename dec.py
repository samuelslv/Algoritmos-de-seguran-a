# Importar as funções do arquivo aes_cipher.py
from AES import aes_decrypt

# Configurar parâmetros
key = '546869734973413136427974654b6579'  # Mesma chave usada na criptografia
iv = '1234567890abcdef1234567890abcdef'  # Mesmo IV usado na criptografia

input_file = 'arquivo_criptografado.aes'
output_file = 'arquivo_decifrado.txt'

# Chamar a função de descriptografia
aes_decrypt(
    key=key, 
    iv=iv, 
    input_file=input_file, 
    output_file=output_file, 
    key_format="hex", 
    iv_format="hex",  #utf8
    key_size=128, 
    mode="CBC", 
    input_format="hex"
)

"""AES_Encrypt({'option':'Hex','string':'1111111111222222222233333333331'},{'option':'Hex','string':'123456789012345678901234567890123'},'CBC','Raw','Hex',{'option':'Hex','string':''})
AES_Decrypt({'option':'Hex','string':'1111111111222222222233333333331'},{'option':'Hex','string':'123456789012345678901234567890123'},'CBC','Hex','Raw',{'option':'Hex','string':''},{'option':'Hex','string':''})
"""