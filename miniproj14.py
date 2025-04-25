import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel
import customtkinter as ctk
import random
import winsound
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad, unpad  

# Initialize customtkinter
ctk.set_appearance_mode("System")  
ctk.set_default_color_theme("blue")

class EncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Encryption")
        self.geometry("500x500")
        self.configure(bg="#2E2E2E")
        
        self.label = ctk.CTkLabel(self, text="File Encryption & Decryption", font=("Arial", 20))
        self.label.pack(pady=20)
        
        self.encrypt_button = ctk.CTkButton(self, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack(pady=10)
        
        self.decrypt_button = ctk.CTkButton(self, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=10)
        
        self.self_destruct_var = tk.BooleanVar(value=True)  
        self.self_destruct_checkbox = ctk.CTkCheckBox(self, text="Enable Self-Destruction", variable=self.self_destruct_var)
        self.self_destruct_checkbox.pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="", font=("Arial", 14), text_color="white")
        self.status_label.pack(pady=10)
    
    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        file_hash = hashlib.sha3_512(data).hexdigest()

        enc_file_path = file_path + ".enc"
        with open(enc_file_path, 'wb') as f:
            f.write(iv + encrypted_data)
        
        with open(file_path + ".key", 'wb') as f:
            f.write(key)
        
        with open(file_path + ".hash", 'w') as f:
            f.write(file_hash)

        self_destruct_status = "1" if self.self_destruct_var.get() else "0"
        with open(file_path + ".destruct", 'w') as f:
            f.write(self_destruct_status)

        self.status_label.configure(text="File Encrypted Successfully!", text_color="green")
        messagebox.showinfo("Success", f"File Encrypted and Saved as: {enc_file_path}")
    
    def decrypt_file(self):
        enc_file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not enc_file_path:
            return
        
        key_file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
        if not key_file_path:
            return
        
        hash_file_path = enc_file_path.replace(".enc", ".hash")
        destruct_file_path = enc_file_path.replace(".enc", ".destruct")

        if not os.path.exists(hash_file_path):
            self.trigger_warnings()
            self.self_destruct(enc_file_path, key_file_path, hash_file_path, destruct_file_path)
            return

        with open(destruct_file_path, 'r') as f:
            self_destruct_enabled = f.read().strip() == "1"

        with open(key_file_path, 'rb') as f:
            key = f.read()
        
        with open(enc_file_path, 'rb') as f:
            iv = f.read(16)
            encrypted_data = f.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        try:
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        except ValueError:
            self.trigger_warnings()
            if self_destruct_enabled:
                self.self_destruct(enc_file_path, key_file_path, hash_file_path, destruct_file_path)
            return
        
        computed_hash = hashlib.sha3_512(decrypted_data).hexdigest()
        with open(hash_file_path, 'r') as f:
            stored_hash = f.read()
        
        if computed_hash != stored_hash:
            self.trigger_warnings()
            if self_destruct_enabled:
                self.self_destruct(enc_file_path, key_file_path, hash_file_path, destruct_file_path)
            return
        
        original_extension = enc_file_path.split('.')[-2]
        original_file_path = enc_file_path.replace(".enc", f"_decrypted.{original_extension}")
        
        with open(original_file_path, 'wb') as f:
            f.write(decrypted_data)
        
        self.status_label.configure(text="File Decrypted Successfully!", text_color="green")
        messagebox.showinfo("Success", f"File Decrypted and Saved as: {original_file_path}")

    def self_destruct(self, enc_file, key_file, hash_file, destruct_file):
        files_to_delete = [enc_file, key_file, hash_file, destruct_file]
        for file in files_to_delete:
            try:
                if os.path.exists(file):
                    os.chmod(file, 0o777)  
                    os.remove(file)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {file}: {e}")
        
        messagebox.showinfo("🔥 Self-Destruction", "🚀 Tampered files have been permanently destroyed!")

    def trigger_warnings(self):
        warning_messages = [
            "⚠️ CRITICAL ERROR: FILE BREACH DETECTED!",
            "⚠️ SYSTEM ALERT: INTRUSION DETECTED!",
            "⚠️ WARNING: ENCRYPTION FAILURE!",
            "⚠️ ALERT: UNAUTHORIZED ACCESS!",
            "⚠️ SECURITY BREACH: FILE COMPROMISED!",
            "⚠️ THREAT DETECTED: EMERGENCY MODE!",
            "⚠️ SYSTEM ALERT: MALICIOUS ACTIVITY DETECTED!",
            "⚠️ ALERT: FILE CORRUPTION DETECTED!",
            "⚠️ CRITICAL FAILURE: SYSTEM AT RISK!",
            "⚠️ WARNING: IMMEDIATE ACTION REQUIRED!",
            "⚠️ DANGER: FILE WILL BE DESTROYED!",
            "🚨 FINAL WARNING: SYSTEM LOCKDOWN IMMINENT!"
        ]

        popups = []

        def show_warning(index):
            if index >= len(warning_messages):
                return  

            popup = Toplevel(self)
            popup.geometry(f"450x250+{random.randint(100, 1200)}+{random.randint(100, 700)}")
            popup.title("⚠️ SECURITY WARNING!")
            popup.configure(bg="black")

            label = tk.Label(popup, text=warning_messages[index], font=("Arial", 18, "bold"), fg="red", bg="black", wraplength=400)
            label.pack(expand=True, padx=20, pady=20)

            popups.append(popup)

            frequency = 800 + (index * 50)  # Increase sound frequency
            winsound.Beep(frequency, 300)  # Play warning sound

            self.after(500, lambda: show_warning(index + 1))  
            self.after(1000, popup.destroy)

        show_warning(0)  

if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
