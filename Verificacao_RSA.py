import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA384, SHA512


def selecionar_arquivo(opcao):
    caminho_arquivo = filedialog.askopenfilename()
    if caminho_arquivo and opcao == "1":
        chave_publica_label.delete(0, tk.END)
        chave_publica_label.insert(0, caminho_arquivo)
    elif caminho_arquivo and opcao == "2":
        arquivo_claro_label.delete(0, tk.END)
        arquivo_claro_label.insert(0, caminho_arquivo)
    elif caminho_arquivo and opcao == "3":
        arquivo_assinado_label.delete(0, tk.END)
        arquivo_assinado_label.insert(0, caminho_arquivo)


def verificar_assinatura():
    chave_publica = chave_publica_label.get()
    arquivo_claro = arquivo_claro_label.get()
    arquivo_assinado = arquivo_assinado_label.get()
    versao_hash = versao_hash_label.get()

    if not chave_publica or not arquivo_claro or not arquivo_assinado:
        messagebox.showerror("Erro", "Todos os campos são obrigatórios.")
        return

    try:
        with open(chave_publica, 'rb') as f:
            public_key = RSA.import_key(f.read())

        with open(arquivo_claro, 'rb') as f:
            message = f.read()

        with open(arquivo_assinado, 'rb') as f:
            signature = f.read()

        if versao_hash == "SHA256":
            hash_obj = SHA256.new(message)
        elif versao_hash == "SHA384":
            hash_obj = SHA384.new(message)
        else:  # SHA512
            hash_obj = SHA512.new(message)

        pkcs1_15.new(public_key).verify(hash_obj, signature)
        messagebox.showinfo("Verificação", "Assinatura válida.")
    except (ValueError, TypeError):
        messagebox.showerror("Verificação", "Assinatura inválida.")
    except Exception as e:
        messagebox.showerror("Erro", str(e))


# Criando a interface para Verificação
root = tk.Tk()
root.title("Verificação RSA")

tk.Label(root, text="Arquivo chave pública:").grid(
    row=0, column=0, padx=10, pady=5)
chave_publica_label = tk.Entry(root, width=50)
chave_publica_label.grid(row=0, column=1, padx=10, pady=5)
tk.Button(root, text="Selecionar arquivo", command=lambda: selecionar_arquivo(
    "1")).grid(row=0, column=2, padx=5, pady=5)


tk.Label(root, text="Arquivo em claro:").grid(row=1, column=0, padx=10, pady=5)
arquivo_claro_label = tk.Entry(root, width=50)
arquivo_claro_label.grid(row=1, column=1, padx=10, pady=5)
tk.Button(root, text="Selecionar arquivo", command=lambda: selecionar_arquivo(
    "2")).grid(row=1, column=2, padx=5, pady=5)

tk.Label(root, text="Arquivo com assinatura:").grid(
    row=2, column=0, padx=10, pady=5)
arquivo_assinado_label = tk.Entry(root, width=50)
arquivo_assinado_label.grid(row=2, column=1, padx=10, pady=5)
tk.Button(root, text="Selecionar arquivo", command=lambda: selecionar_arquivo(
    "3")).grid(row=2, column=2, padx=5, pady=5)

# Modo de hash
tk.Label(root, text="Versão do SHA-2:").grid(row=3, column=0, padx=10, pady=5)
versao_hash_label = tk.StringVar(value="SHA256")
tk.Radiobutton(root, text="SHA256", variable=versao_hash_label,
               value="SHA256").grid(row=3, column=1, sticky=tk.W)
tk.Radiobutton(root, text="SHA384", variable=versao_hash_label, value="SHA384").grid(
    row=3, column=1, padx=80, sticky=tk.W)
tk.Radiobutton(root, text="SHA512", variable=versao_hash_label, value="SHA512").grid(
    row=3, column=1, padx=150, sticky=tk.W)

# Botão de verificar
tk.Button(root, text="Verificar", command=verificar_assinatura).grid(
    row=4, column=1, padx=10, pady=20)

root.mainloop()
