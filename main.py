import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.fernet import Fernet


class FileEncryptorDecryptor:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryptor/Decryptor")

        self.encrypt_btn = tk.Button(master, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_btn.pack(pady=10)

        self.decrypt_btn = tk.Button(master, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_btn.pack(pady=10)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        password = simpledialog.askstring("Password", "Enter password:", show='*')
        if not password:
            return
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        with open(file_path, 'wb') as file:
            file.write(encrypted_data)
        with open(f"{file_path}.key", 'wb') as key_file:
            key_file.write(cipher_suite.encrypt(password.encode()))
        messagebox.showinfo("Success", "File encrypted successfully")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        key_file_path = filedialog.askopenfilename(title="Select key file")
        if not key_file_path:
            return
        password = simpledialog.askstring("Password", "Enter password:", show='*')
        if not password:
            return
        with open(key_file_path, 'rb') as key_file:
            encrypted_key = key_file.read()
        cipher_suite = Fernet(Fernet.generate_key())
        try:
            key = cipher_suite.decrypt(encrypted_key).decode()
            if key != password:
                raise ValueError("Incorrect password")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            return
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        cipher_suite = Fernet(key.encode())
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            return
        with open(file_path, 'wb') as file:
            file.write(decrypted_data)
        messagebox.showinfo("Success", "File decrypted successfully")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorDecryptor(root)
    root.mainloop()
