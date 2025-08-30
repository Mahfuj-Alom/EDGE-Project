#!/usr/bin/env python3
import argparse
import requests
import os
import base64
import hashlib
import json
from cryptography.fernet import Fernet
from getpass import getpass

SECRETS_FILE = "secrets.enc"

def password_to_key(password: str) -> bytes:
    """Convert password to a Fernet key using SHA256 hash."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def download_file(url: str, output_path: str):
    """Download file from URL."""
    import requests
    response = requests.get(url, stream=True)
    response.raise_for_status()
    with open(output_path, "wb") as f:
        for chunk in response.iter_content(1024):
            f.write(chunk)

def encrypt_file(file_path: str, password: str):
    """Encrypt a file with password."""
    key = password_to_key(password)
    fernet = Fernet(key)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)
    enc_path = file_path + ".enc"

    with open(enc_path, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ File encrypted and saved as {enc_path}")

def decrypt_file(file_path: str, password: str):
    """Decrypt a file with password."""
    key = password_to_key(password)
    fernet = Fernet(key)

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("❌ Wrong password or corrupted file!")
        return None

    dec_path = file_path.replace(".enc", ".dec", 1)
    with open(dec_path, "wb") as f:
        f.write(decrypted_data)

    print(f"✅ File decrypted and saved as {dec_path}")
    return dec_path

# ---------------- Secret Manager ---------------- #

def load_secrets(password: str) -> dict:
    """Load and decrypt secrets file."""
    if not os.path.exists(SECRETS_FILE):
        return {}
    key = password_to_key(password)
    fernet = Fernet(key)

    with open(SECRETS_FILE, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted = fernet.decrypt(encrypted_data).decode()
        return json.loads(decrypted)
    except Exception:
        print("❌ Wrong password or corrupted secrets file!")
        return {}

def save_secrets(secrets: dict, password: str):
    """Encrypt and save secrets file."""
    key = password_to_key(password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json.dumps(secrets).encode())

    with open(SECRETS_FILE, "wb") as f:
        f.write(encrypted_data)

def add_secret(name: str, value: str, password: str):
    secrets = load_secrets(password)
    secrets[name] = value
    save_secrets(secrets, password)
    print(f"✅ Secret '{name}' stored securely")

def get_secret(name: str, password: str):
    secrets = load_secrets(password)
    if name in secrets:
        print(f"{name}={secrets[name]}")
    else:
        print(f"❌ Secret '{name}' not found")

def list_secrets(password: str):
    secrets = load_secrets(password)
    if secrets:
        print("🔑 Stored secrets:")
        for k in secrets:
            print(f"- {k}")
    else:
        print("⚠️ No secrets stored yet.")

# ---------------- CLI ---------------- #

def main():
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt files and manage secrets")
    subparsers = parser.add_subparsers(dest="command")

    # File encryption
    file_parser = subparsers.add_parser("file", help="Encrypt/Decrypt a file from URL")
    file_parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode")
    file_parser.add_argument("url", help="File URL")

    # Secret manager
    secret_parser = subparsers.add_parser("secret", help="Manage secrets")
    secret_parser.add_argument("action", choices=["add", "get", "list"], help="Secret action")
    secret_parser.add_argument("--name", help="Secret name")
    secret_parser.add_argument("--value", help="Secret value (for add)")

    args = parser.parse_args()
    password = getpass("Enter password: ")

    if args.command == "file":
        local_file = os.path.basename(args.url)
        print(f"⬇️ Downloading {args.url} ...")
        download_file(args.url, local_file)

        if args.mode == "encrypt":
            encrypt_file(local_file, password)
        elif args.mode == "decrypt":
            decrypt_file(local_file, password)

    elif args.command == "secret":
        if args.action == "add":
            if not args.name or not args.value:
                print("❌ You must provide --name and --value for adding a secret")
                return
            add_secret(args.name, args.value, password)
        elif args.action == "get":
            if not args.name:
                print("❌ You must provide --name to get a secret")
                return
            get_secret(args.name, password)
        elif args.action == "list":
            list_secrets(password)

if __name__ == "__main__":
    main()
