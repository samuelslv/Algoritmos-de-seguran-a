import tkinter as tk
from tkinter import messagebox
import AES
import aes_interface

def open_aes_interface():
    # Coloque aqui o código da interface de Cifragem e Decifragem AES
    


def open_key_generation_interface():
    # Coloque aqui o código da interface para Geração de Chaves RSA
    messagebox.showinfo("Geração de Chaves", "Abrindo interface de Geração de Chaves RSA")

def open_rsa_sign_interface():
    # Coloque aqui o código da interface de Assinatura RSA
    messagebox.showinfo("Assinatura RSA", "Abrindo interface de Assinatura RSA")

def open_rsa_verification_interface():
    # Coloque aqui o código da interface de Verificação RSA
    messagebox.showinfo("Verificação RSA", "Abrindo interface de Verificação RSA")

# Função principal da interface de menu
def main_menu():
    root = tk.Tk()
    root.title("Menu Principal - Escolha a Função")
    root.geometry("300x250")

    # Botão para Cifragem e Decifragem AES
    tk.Button(root, text="1 - Cifragem e Decifragem AES", command=open_aes_interface, width=25, height=2).pack(pady=10)

    # Botão para Geração de Chaves RSA
    tk.Button(root, text="2 - Geração de Chaves RSA", command=open_key_generation_interface, width=25, height=2).pack(pady=10)

    # Botão para Assinatura RSA
    tk.Button(root, text="3 - Assinatura RSA", command=open_rsa_sign_interface, width=25, height=2).pack(pady=10)

    # Botão para Verificação RSA
    tk.Button(root, text="4 - Verificação RSA", command=open_rsa_verification_interface, width=25, height=2).pack(pady=10)

    root.mainloop()

# Inicializa o menu principal
main_menu()
