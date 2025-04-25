# 🔐 Self-Defending File Encryption System

A Python-based GUI tool that securely encrypts and decrypts files using AES encryption. It features an **optional self-destruction mode** that detects tampering and automatically deletes all traces of the file — complete with multiple warning popups and sound effects to deter intruders.

---

## 🧠 Features

- ✅ AES-256 file encryption and decryption
- 🔐 Optional *self-destruct mode* for tamper response
- 🧮 SHA3-512 integrity checks to ensure data isn't altered
- 🚨 12 automatic warning popups before deletion
- 🔊 Scary sound effects on tampering
- 💻 Clean and modern `customtkinter` GUI

---

## 📁 File Types Supported

- `.txt`, `.pdf`, `.png`, `.jpg`, `.docx` and any generic binary files

---

## 💻 Technologies Used

- Python 3.x
- `customtkinter` for UI
- `pycryptodome` for AES encryption
- `hashlib` for integrity
- `playsound` for warning effects

---

## 🚀 How to Run

```bash
pip install -r requirements.txt
python encryption_gui.py
