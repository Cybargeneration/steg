import os
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from getpass import getpass
import base64

# Generate a key from a password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt the file
def encrypt_file(file_path, password):
    # Generate a unique salt for this file
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)

    # Read the file content
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Encrypt the file data
    encrypted_data = fernet.encrypt(file_data)

    # Save the encrypted file with salt
    encrypted_file_path = file_path + ".locked"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(salt + encrypted_data)  # Save salt at the start

    print(f"[+] File '{file_path}' has been encrypted as '{encrypted_file_path}'")
    os.remove(file_path)  # Remove the original file

# Decrypt the file
def decrypt_file(file_path, password):
    with open(file_path, "rb") as encrypted_file:
        # Extract salt and encrypted data
        salt = encrypted_file.read(16)
        encrypted_data = encrypted_file.read()

    key = generate_key(password, salt)
    fernet = Fernet(key)

    # Decrypt the data
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("[-] Incorrect password or file is corrupted.")
        sys.exit(1)

    # Save the decrypted file
    original_file_path = file_path.replace(".locked", "")
    with open(original_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"[+] File '{file_path}' has been decrypted as '{original_file_path}'")
    os.remove(file_path)  # Remove the encrypted file

# Main function
def main():
    action = input("Do you want to lock (encrypt) or unlock (decrypt) a file? (lock/unlock): ").strip().lower()
    if action not in ["lock", "unlock"]:
        print("[-] Invalid action. Use 'lock' to encrypt or 'unlock' to decrypt.")
        sys.exit(1)

    file_path = input("Enter the file path: ").strip()
    if not os.path.exists(file_path):
        print("[-] File not found.")
        sys.exit(1)

    password = getpass("Enter the password: ")

    if action == "lock":
        encrypt_file(file_path, password)
    elif action == "unlock":
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()

