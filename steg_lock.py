import os
import sys
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from getpass import getpass

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

# Function to embed a message in the file content
def embed_message(file_data, message):
    encoded_message = message.encode() + b"ENDMSG"  # Use ENDMSG as a delimiter
    return encoded_message + file_data  # Embed at the start of the file

# Function to extract the embedded message from the file content
def extract_message(file_data):
    delimiter = b"ENDMSG"
    delimiter_index = file_data.find(delimiter)
    if delimiter_index == -1:
        return None, file_data
    embedded_message = file_data[:delimiter_index].decode()
    original_file_data = file_data[delimiter_index + len(delimiter):]
    return embedded_message, original_file_data

# Encrypt the file with embedded message
def encrypt_file(file_path, password, message):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        file_data = file.read()

    # Embed the secret message
    file_data_with_message = embed_message(file_data, message)

    # Encrypt the data
    encrypted_data = fernet.encrypt(file_data_with_message)

    # Save the encrypted file with salt at the start
    encrypted_file_path = file_path + ".locked"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(salt + encrypted_data)

    print(f"[+] File '{file_path}' has been encrypted as '{encrypted_file_path}'")
    os.remove(file_path)  # Optionally delete the original file

# Decrypt the file and extract the hidden message
def decrypt_file(file_path, password):
    with open(file_path, "rb") as encrypted_file:
        salt = encrypted_file.read(16)  # Extract the salt
        encrypted_data = encrypted_file.read()  # Read the encrypted data

    key = generate_key(password, salt)
    fernet = Fernet(key)

    try:
        # Decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("[-] Incorrect password or file is corrupted.")
        sys.exit(1)

    # Extract the embedded message
    message, original_file_data = extract_message(decrypted_data)

    # Save the decrypted file
    original_file_path = file_path.replace(".locked", "")
    with open(original_file_path, "wb") as decrypted_file:
        decrypted_file.write(original_file_data)

    print(f"[+] File '{file_path}' has been decrypted as '{original_file_path}'")
    if message:
        print(f"[+] Hidden message: {message}")
    else:
        print("[-] No hidden message found.")

    os.remove(file_path)  # Optionally delete the encrypted file

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
        message = input("Enter the message to hide in the file: ").strip()
        encrypt_file(file_path, password, message)
    elif action == "unlock":
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()

