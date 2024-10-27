import tkinter as tk
from tkinter import filedialog, messagebox
from AES import aes_cifrar, aes_decifrar

# Função para selecionar arquivo
def selecionar_arquivo():
    caminho_arquivo = filedialog.askopenfilename()
    if caminho_arquivo:
        entrada_arquivo_label.delete(0, tk.END)
        entrada_arquivo_label.insert(0, caminho_arquivo)

# Função para escolher onde salvar o arquivo de saída
def salvar_arquivo():
    caminho_arquivo = filedialog.asksaveasfilename(defaultextension=".aes")
    if caminho_arquivo:
        saida_arquivo_label.delete(0, tk.END)
        saida_arquivo_label.insert(0, caminho_arquivo)

# Função para validar se a chave e o IV estão no formato adequado
def validar_chave_iv_formatoo(chave, iv, chave_formato, iv_formato):
    try:
        if chave_formato == "hex":
            bytes.fromhex(chave)  # Verifica se a chave é HEX válida
        if iv_formato == "hex":
            bytes.fromhex(iv)  # Verifica se o IV é HEX válido
        return True
    except ValueError as e:
        return False

# Função para criptografar
def cifrar():
    chave = chave_entry.get()
    chave_mode = modo_chave.get()
    iv = iv_label.get()
    iv_modo = mode_iv.get()
    entrada_arquivo = entrada_arquivo_label.get()
    saida_aruivo = saida_arquivo_label.get()
    mode = mode_var.get()
    entrada_saida = entrada_saida.get()
    tamanho_chave = int(tamanho_chave.get())

    # Validações básicas
    if not chave or not iv or not entrada_arquivo or not saida_aruivo:
        messagebox.showerror("Erro", "Todos os campos são obrigatórios.")
        return

    # Validações de tamanho de chave
    chave_tamanho = {128: 32, 192: 48, 256: 64}
    tamanho_chave_requerido = chave_tamanho.get(tamanho_chave)

    if len(chave) != tamanho_chave_requerido:
        messagebox.showerror("Erro", f"A chave precisa ter {
                             tamanho_chave_requerido} caracteres.")
        return

    # Validação do formato da chave e IV
    if not validar_chave_iv_formatoo(chave, iv, chave_mode, iv_modo):
        messagebox.showerror(
            "Erro", "Formato de chave ou IV inválido para o tipo selecionado.")
        return

    try:
        aes_cifrar(
            chave=chave,
            iv=iv,
            entrada_arquivo=entrada_arquivo,
            saida_aruivo=saida_aruivo,
            chave_formato=chave_mode,
            iv_formato=iv_modo,
            chave_size=tamanho_chave,
            mode_OP=mode,
            output_format=entrada_saida)
        messagebox.showinfo("Sucesso", "Arquivo criptografado com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", str(e))

# Função para descriptografar
def decifrar():
    chave = chave_entry.get()
    chave_mode = modo_chave.get()
    iv = iv_label.get()
    iv_modo = mode_iv.get()
    entrada_arquivo = entrada_arquivo_label.get()
    saida_arquivo = saida_arquivo_label.get()
    modo = mode_var.get()
    entrada_saida = entrada_saida.get()
    tamanho_chave1 = int(tamanho_chave.get())

    # Validações básicas
    if not chave or not iv or not entrada_arquivo or not saida_arquivo:
        messagebox.showerror("Erro", "Todos os campos são obrigatórios.")
        return

    # Validações de tamanho de chave
    chave_tamanho = {128: 32, 192: 48, 256: 64}
    tamanho_chave_requerido = chave_tamanho.get(tamanho_chave1)

    if len(chave) != tamanho_chave_requerido:
        messagebox.showerror("Erro", f"A chave precisa ter {
                             tamanho_chave_requerido} caracteres.")
        return

    # Validação do formato da chave e IV
    if not validar_chave_iv_formatoo(chave, iv, chave_mode, iv_modo):
        messagebox.showerror(
            "Erro", "Formato de chave ou IV inválido para o tipo selecionado.")
        return

    try:
        aes_decifrar(
            chave=chave,
            iv=iv,
            entrada_arquivo=entrada_arquivo,
            saida_aruivo=saida_arquivo,
            chave_formato=chave_mode,
            iv_formato=iv_modo,
            chave_size=tamanho_chave1,
            mode_OP=modo,
            input_format=entrada_saida
        )
        messagebox.showinfo("Sucesso", "Arquivo descriptografado com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", str(e))

# Criando a interface com Tkinter
root = tk.Tk()
root.title("Cifragem/Decifragem AES ")

# Campos de entrada
tk.Label(root, text="Chave:").grid(row=0, column=0, padx=10, pady=5)
chave_entry = tk.Entry(root, width=50)
chave_entry.grid(row=0, column=1, padx=10, pady=5)

modo_chave = tk.StringVar(value="hex")
tk.Radiobutton(root, text="HEX", variable=modo_chave, value="hex").grid(
    row=0, column=2, sticky=tk.W, padx=10)
tk.Radiobutton(root, text="UTF8", variable=modo_chave,
               value="utf-8").grid(row=0, column=2, padx=80, sticky=tk.W)


tk.Label(root, text="Vetor de inicialização:").grid(
    row=1, column=0, padx=10, pady=5)
iv_label = tk.Entry(root, width=50)
iv_label.grid(row=1, column=1, padx=10, pady=5)

mode_iv = tk.StringVar(value="hex")
tk.Radiobutton(root, text="HEX", variable=mode_iv, value="hex").grid(
    row=1, column=2, sticky=tk.W, padx=10)
tk.Radiobutton(root, text="UTF8", variable=mode_iv,
               value="utf-8").grid(row=1, column=2, padx=80, sticky=tk.W)

tk.Label(root, text="Arquivo de entrada:").grid(
    row=2, column=0, padx=10, pady=5)
entrada_arquivo_label = tk.Entry(root, width=50)
entrada_arquivo_label.grid(row=2, column=1, padx=10, pady=5)
tk.Button(root, text="Selecionar arquivo", command=selecionar_arquivo).grid(
    row=2, column=2, padx=5, pady=5)

tk.Label(root, text="Arquivo de saída:").grid(row=3, column=0, padx=10, pady=5)
saida_arquivo_label = tk.Entry(root, width=50)
saida_arquivo_label.grid(row=3, column=1, padx=10, pady=5)
tk.Button(root, text="Salvar como", command=salvar_arquivo).grid(
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
entrada_saida = tk.StringVar(value="null")
tk.Radiobutton(root, text="HEX", variable=entrada_saida, value="hex").grid(
    row=5, column=1, sticky=tk.W, padx=10)
tk.Radiobutton(root, text="BASE64", variable=entrada_saida,
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
tk.Button(root, text="Criptografar", command=cifrar).grid(
    row=8, column=0, padx=10, pady=20)
tk.Button(root, text="Descriptografar", command=decifrar).grid(
    row=8, column=1, padx=10, pady=20)

root.mainloop()
