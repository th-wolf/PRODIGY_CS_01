import tkinter as tk
from tkinter import filedialog, messagebox
import os

# Caesar Cipher Functions
def caesar_cipher(text, shift, encrypt=True):
    result = ""
    if not encrypt:
        shift = -shift
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr(((ord(char.lower()) - ord('a') + shift_amount) % 26) + ord('a'))
            result += new_char.upper() if char.isupper() else new_char
        else:
            result += char
    return result

# File Operations
def process_file(encrypt=True):
    file_path = filedialog.askopenfilename(title="Select a File")
    if not file_path:
        return

    shift = shift_var.get()
    if not shift.isdigit():
        messagebox.showerror("Invalid Input", "Shift value must be a number.")
        return

    shift = int(shift)
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    processed_content = caesar_cipher(content, shift, encrypt)

    # Save File
    output_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                               filetypes=[("Text files", "*.txt")],
                                               title="Save File As")
    if output_path:
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(processed_content)
        messagebox.showinfo("Success", f"File {'encrypted' if encrypt else 'decrypted'} successfully!")

# GUI Design
root = tk.Tk()
root.title("Caesar Cipher - File Encryption/Decryption")
root.geometry("500x400")
root.configure(bg="#141414")  # Netflix Black

# Header
header_label = tk.Label(root, text="Caesar Cipher Tool", font=("Arial", 18, "bold"), fg="#E50914", bg="#141414")
header_label.pack(pady=20)

# Shift Key Input
shift_label = tk.Label(root, text="Enter Shift Key:", font=("Arial", 12), fg="white", bg="#141414")
shift_label.pack()
shift_var = tk.StringVar()
shift_entry = tk.Entry(root, textvariable=shift_var, font=("Arial", 12), bg="#222222", fg="white", insertbackground="white")
shift_entry.pack(pady=5)

# Buttons
encrypt_btn = tk.Button(root, text="Encrypt File", font=("Arial", 12, "bold"), bg="#E50914", fg="white",
                         padx=10, pady=5, command=lambda: process_file(encrypt=True))
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(root, text="Decrypt File", font=("Arial", 12, "bold"), bg="#E50914", fg="white",
                         padx=10, pady=5, command=lambda: process_file(encrypt=False))
decrypt_btn.pack(pady=10)

# Run the App
root.mainloop()
