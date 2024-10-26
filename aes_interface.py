import tkinter as tk
from tkinter import filedialog, messagebox
from AES import aes_encrypt, aes_decrypt

# Função para selecionar arquivo
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        input_file_entry.delete(0, tk.END)
        input_file_entry.insert(0, file_path)

# Função para escolher onde salvar o arquivo de saída
def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".aes")
    if file_path:
        output_file_entry.delete(0, tk.END)
        output_file_entry.insert(0, file_path)

# Função para validar se a chave e o IV estão no formato adequado
def validate_key_iv_format(key, iv, key_format, iv_format):
    try:
        if key_format == "hex":
            bytes.fromhex(key)  # Verifica se a chave é HEX válida
        if iv_format == "hex":
            bytes.fromhex(iv)  # Verifica se o IV é HEX válido
        return True
    except ValueError as e:
        return False

# Função para criptografar
def encrypt_file():
    key1 = key_entry.get()
    key_mode1 = mode_key.get()
    iv1 = iv_entry.get()
    iv_mode1 = mode_iv.get()
    input_file1 = input_file_entry.get()
    output_file1 = output_file_entry.get()
    mode1 = mode_var.get()
    entradasaida1 = entradasaida.get()
    tamanho_key1 = int(tamanho_chave.get())

    # Validações básicas
    if not key1 or not iv1 or not input_file1 or not output_file1:
        messagebox.showerror("Erro", "Todos os campos são obrigatórios.")
        return

    # Validações de tamanho de chave
    key_lengths = {128: 32, 192: 48, 256: 64}
    required_key_length = key_lengths.get(tamanho_key1)

    if len(key1) != required_key_length:
        messagebox.showerror("Erro", f"A chave precisa ter {
                             required_key_length} caracteres.")
        return

    # Validação do formato da chave e IV
    if not validate_key_iv_format(key1, iv1, key_mode1, iv_mode1):
        messagebox.showerror(
            "Erro", "Formato de chave ou IV inválido para o tipo selecionado.")
        return

    try:
        aes_encrypt(
            key=key1,
            iv=iv1,
            input_file=input_file1,
            output_file=output_file1,
            key_format=key_mode1,
            iv_format=iv_mode1,
            key_size=tamanho_key1,
            mode_OP=mode1,
            output_format=entradasaida1)
        messagebox.showinfo("Sucesso", "Arquivo criptografado com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", str(e))

# Função para descriptografar
def decrypt_file():
    key1 = key_entry.get()
    key_mode1 = mode_key.get()
    iv1 = iv_entry.get()
    iv_mode1 = mode_iv.get()
    input_file1 = input_file_entry.get()
    output_file1 = output_file_entry.get()
    mode1 = mode_var.get()
    entradasaida1 = entradasaida.get()
    tamanho_key1 = int(tamanho_chave.get())

    # Validações básicas
    if not key1 or not iv1 or not input_file1 or not output_file1:
        messagebox.showerror("Erro", "Todos os campos são obrigatórios.")
        return

    # Validações de tamanho de chave
    key_lengths = {128: 32, 192: 48, 256: 64}
    required_key_length = key_lengths.get(tamanho_key1)

    if len(key1) != required_key_length:
        messagebox.showerror("Erro", f"A chave precisa ter {
                             required_key_length} caracteres.")
        return

    # Validação do formato da chave e IV
    if not validate_key_iv_format(key1, iv1, key_mode1, iv_mode1):
        messagebox.showerror(
            "Erro", "Formato de chave ou IV inválido para o tipo selecionado.")
        return

    try:
        aes_decrypt(
            key=key1,
            iv=iv1,
            input_file=input_file1,
            output_file=output_file1,
            key_format=key_mode1,
            iv_format=iv_mode1,
            key_size=tamanho_key1,
            mode_OP=mode1,
            input_format=entradasaida1
        )
        messagebox.showinfo("Sucesso", "Arquivo descriptografado com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", str(e))

# Criando a interface com Tkinter
root = tk.Tk()
root.title("Cifragem/Decifragem AES ")
root.title("Cifragem/Decifragem AES ")

# Campos de entrada
tk.Label(root, text="Chave:").grid(row=0, column=0, padx=10, pady=5)
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=0, column=1, padx=10, pady=5)

mode_key = tk.StringVar(value="hex")
tk.Radiobutton(root, text="HEX", variable=mode_key, value="hex").grid(
    row=0, column=2, sticky=tk.W, padx=10)
tk.Radiobutton(root, text="UTF8", variable=mode_key,
               value="utf-8").grid(row=0, column=2, padx=80, sticky=tk.W)


tk.Label(root, text="Vetor de inicialização:").grid(
    row=1, column=0, padx=10, pady=5)
iv_entry = tk.Entry(root, width=50)
iv_entry.grid(row=1, column=1, padx=10, pady=5)

mode_iv = tk.StringVar(value="hex")
tk.Radiobutton(root, text="HEX", variable=mode_iv, value="hex").grid(
    row=1, column=2, sticky=tk.W, padx=10)
tk.Radiobutton(root, text="UTF8", variable=mode_iv,
               value="utf-8").grid(row=1, column=2, padx=80, sticky=tk.W)

tk.Label(root, text="Arquivo de entrada:").grid(
    row=2, column=0, padx=10, pady=5)
input_file_entry = tk.Entry(root, width=50)
input_file_entry.grid(row=2, column=1, padx=10, pady=5)
tk.Button(root, text="Selecionar arquivo", command=select_file).grid(
    row=2, column=2, padx=5, pady=5)

tk.Label(root, text="Arquivo de saída:").grid(row=3, column=0, padx=10, pady=5)
output_file_entry = tk.Entry(root, width=50)
output_file_entry.grid(row=3, column=1, padx=10, pady=5)
tk.Button(root, text="Salvar como", command=save_file).grid(
    row=3, column=2, padx=10, pady=5)

# Modo de operação (ECB/CBC)
tk.Label(root, text="Modo de operação:").grid(row=4, column=0, padx=10, pady=5)
mode_var = tk.StringVar(value="CBC")
tk.Radiobutton(root, text="CBC", variable=mode_var, value="CBC").grid(
    row=4, column=1, sticky=tk.W, padx=10)
tk.Radiobutton(root, text="ECB", variable=mode_var, value="ECB").grid(
    row=4, column=1, padx=80, sticky=tk.W)

# Modo de entrada/saida
tk.Label(root, text="Entrada (descripto)/Saída (cripto):").grid(row=5,
                                                                column=0, padx=10, pady=5)
entradasaida = tk.StringVar(value="null")
tk.Radiobutton(root, text="HEX", variable=entradasaida, value="hex").grid(
    row=5, column=1, sticky=tk.W, padx=10)
tk.Radiobutton(root, text="BASE64", variable=entradasaida,
               value="base64").grid(row=5, column=1, padx=80, sticky=tk.W)


# Tamanho da chave
tk.Label(root, text="Tamanho da chave:").grid(row=7, column=0, padx=10, pady=5)
tamanho_chave = tk.StringVar(value="128")
tk.Radiobutton(root, text="128", variable=tamanho_chave, value="128").grid(
    row=7, column=1, sticky=tk.W, padx=10)
tk.Radiobutton(root, text="192", variable=tamanho_chave, value="192").grid(
    row=7, column=1, padx=80, sticky=tk.W)
tk.Radiobutton(root, text="256", variable=tamanho_chave, value="256").grid(
    row=7, column=1, padx=150, sticky=tk.W)

# Botões de criptografar e descriptografar
tk.Button(root, text="Criptografar", command=encrypt_file).grid(
    row=8, column=0, padx=10, pady=20)
tk.Button(root, text="Descriptografar", command=decrypt_file).grid(
    row=8, column=1, padx=10, pady=20)

root.mainloop()
