import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import DES
import base64

def caesar_cipher_encrypt(plain_text, shift):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            encrypted_text += chr((ord(char) + shift - shift_amount) % 26 + shift_amount)
        else:
            encrypted_text += char
    return encrypted_text

def rail_fence_cipher_encrypt(plain_text, rails):
    if rails == 1:
        return plain_text
    fence = [[] for _ in range(rails)]
    rail = 0
    var = 1
    for char in plain_text:
        fence[rail].append(char)
        rail += var
        if rail == 0 or rail == rails - 1:
            var = -var
    return ''.join([''.join(row) for row in fence])

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def des_encrypt(plain_text, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded_text = pad(plain_text)
    encrypted_text = des.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted_text).decode('utf-8')

def encrypt():
    plain_text = entry_plain_text.get("1.0", tk.END).strip()
    shift = int(entry_shift.get())
    key = entry_key.get()
    if not plain_text:
        messagebox.showerror("Input Error", "Plain text cannot be empty.")
        return
    if not key or len(key) != 8:
        messagebox.showerror("Input Error", "DES key must be exactly 8 characters long.")
        return

    cipher_type = cipher_var.get()
    if cipher_type == "Caesar Cipher":
        encrypted_text = caesar_cipher_encrypt(plain_text, shift)
    elif cipher_type == "Rail Fence Cipher":
        encrypted_text = rail_fence_cipher_encrypt(plain_text, shift)
    elif cipher_type == "DES Encryption":
        encrypted_text = des_encrypt(plain_text, key)
    else:
        messagebox.showerror("Cipher Error", "Unknown cipher type selected.")
        return

    entry_encrypted_text.config(state=tk.NORMAL)
    entry_encrypted_text.delete("1.0", tk.END)
    entry_encrypted_text.insert(tk.END, encrypted_text)
    entry_encrypted_text.config(state=tk.DISABLED)

# GUI setup
root = tk.Tk()
root.title("Encryption Application")
root.geometry("600x500")
root.configure(bg="#f0f0f0")

style = ttk.Style()
style.configure("TLabel", font=("Helvetica", 12), background="#f0f0f0")
style.configure("TButton", font=("Helvetica", 12), padding=10)
style.configure("TEntry", font=("Helvetica", 12), padding=10)
style.configure("TCombobox", font=("Helvetica", 12), padding=10)

tk.Label(root, text="Plain Text:", font=("Helvetica", 14, "bold"), bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=10, sticky="e")
entry_plain_text = tk.Text(root, width=50, height=5, font=("Helvetica", 12))
entry_plain_text.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Shift/Rails:", font=("Helvetica", 14, "bold"), bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=10, sticky="e")
entry_shift = ttk.Entry(root, width=10, font=("Helvetica", 12))
entry_shift.grid(row=1, column=1, padx=10, pady=10, sticky="w")

tk.Label(root, text="DES Key (8 chars):", font=("Helvetica", 14, "bold"), bg="#f0f0f0").grid(row=2, column=0, padx=10, pady=10, sticky="e")
entry_key = ttk.Entry(root, width=20, font=("Helvetica", 12))
entry_key.grid(row=2, column=1, padx=10, pady=10, sticky="w")

tk.Label(root, text="Select Cipher:", font=("Helvetica", 14, "bold"), bg="#f0f0f0").grid(row=3, column=0, padx=10, pady=10, sticky="e")
cipher_var = tk.StringVar()
cipher_var.set("Caesar Cipher")
cipher_menu = ttk.Combobox(root, textvariable=cipher_var, values=["Caesar Cipher", "Rail Fence Cipher", "DES Encryption"], state="readonly")
cipher_menu.grid(row=3, column=1, padx=10, pady=10, sticky="w")

encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=4, column=1, padx=10, pady=10, sticky="w")

tk.Label(root, text="Encrypted Text:", font=("Helvetica", 14, "bold"), bg="#f0f0f0").grid(row=5, column=0, padx=10, pady=10, sticky="e")
entry_encrypted_text = tk.Text(root, width=50, height=5, font=("Helvetica", 12), state=tk.DISABLED)
entry_encrypted_text.grid(row=5, column=1, padx=10, pady=10)

root.mainloop()
