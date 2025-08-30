# # 🔐 FileCrypt – File & Secret Manager CLI

A simple command-line tool to **encrypt/decrypt files from a URL** and manage **encrypted secrets (like a mini secret manager)** using a password.  
It works like a secure `.env` vault but also supports file encryption.

---

## ✨ Features

- Encrypt any file from a given **URL** with a password.
- Decrypt encrypted files from a URL with the same password.
- Store **key=value secrets** securely (encrypted JSON).
- Retrieve secrets by name.
- List all stored secrets.
- Cross-platform (Linux, macOS, Windows).

---

## ⚙️ Setup

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/filecrypt.git
cd filecrypt
```

### 2. Create a Virtual Environment (optional but recommended)
```bash
python3 -m venv venv
source venv/bin/activate   # Linux / macOS
venv\Scripts\activate      # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

Create a `requirements.txt` with:
```
cryptography
requests
```

### 4. Make Script Executable (Linux/macOS)
```bash
chmod +x filecrypt.py
```

---

## 🚀 Usage

### 🔐 File Encryption / Decryption

#### Encrypt a file from URL
```bash
./filecrypt.py file encrypt https://example.com/mydoc.pdf
```
- Prompts for a password.
- Saves `mydoc.pdf.enc`.

#### Decrypt an encrypted file from URL
```bash
./filecrypt.py file decrypt https://example.com/mydoc.pdf.enc
```
- Prompts for a password.
- Saves `mydoc.pdf.dec`.

---

### 🗝️ Secret Manager

#### Add a secret
```bash
./filecrypt.py secret add --name API_KEY --value mysecretvalue
```

#### Get a secret
```bash
./filecrypt.py secret get --name API_KEY
```

#### List stored secrets
```bash
./filecrypt.py secret list
```

Secrets are stored securely inside `secrets.enc` (encrypted JSON).

---

## 🔧 Example Workflow

```bash
# Store an API key 
./filecrypt.py secret add --name API_KEY --value 12345abcd

# Store a database password
./filecrypt.py secret add --name DB_PASSWORD --value mypassword

# Retrieve API_KEY
./filecrypt.py secret get --name API_KEY

# List all secret names
./filecrypt.py secret list
```

---

## 🔒 Security Notes
<!-- <!--  -->
- Password is never stored — you must enter it each time.
- Encryption uses **AES-128 (Fernet)** via the Python `cryptography` library.
- Losing your password = permanent loss of data (no backdoors).

---

## 📜 License -->



MIT License – feel free to use and modify.
