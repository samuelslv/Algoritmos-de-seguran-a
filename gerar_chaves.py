import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA

# Função para geração de chaves
def generate_keys():
    key_size = int(key_size_var.get())
    
    # Gera as chaves com o tamanho selecionado
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Salva as chaves no local
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)

    messagebox.showinfo("Sucesso", "As chaves foram geradas e salvas no local!")

# Criando a interface com Tkinter
root = tk.Tk()
root.title("Geração de Chaves RSA")

# Opções de tamanho de chave
tk.Label(root, text="Escolha o tamanho da chave:").grid(row=0, column=0, padx=10, pady=10)
key_size_var = tk.StringVar(value="1024")
tk.Radiobutton(root, text="1024 bits", variable=key_size_var, value="1024").grid(row=1, column=0, padx=10, sticky="w")
tk.Radiobutton(root, text="2048 bits", variable=key_size_var, value="2048").grid(row=2, column=0, padx=10, sticky="w")

# Botão para gerar chaves
tk.Button(root, text="Gerar Chaves", command=generate_keys).grid(row=3, column=0, pady=20)

root.mainloop()
