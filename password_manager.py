import json
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets

# Generate a key from a password
def generate_key(password):
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key), salt

# Encrypt a message
def encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).decode()

# Decrypt a message
def decrypt(token, key):
    token = base64.urlsafe_b64decode(token.encode())
    iv = token[:16]
    ciphertext = token[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# Generate a strong password
def generate_password(length=16):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Password manager class
class PasswordManager:
    def __init__(self, master_password):
        self.key, self.salt = generate_key(master_password)
        self.data = {}
        self.load_data()

    def load_data(self):
        if os.path.exists("passwords.json"):
            with open("passwords.json", "r") as file:
                encrypted_data = json.load(file)
                self.data = json.loads(decrypt(encrypted_data["data"], base64.urlsafe_b64decode(encrypted_data["key"])))

    def save_data(self):
        encrypted_data = {
            "data": encrypt(json.dumps(self.data), base64.urlsafe_b64decode(self.key)),
            "key": base64.urlsafe_b64encode(self.key).decode()
        }
        with open("passwords.json", "w") as file:
            json.dump(encrypted_data, file)

    def add_password(self, category, name, password):
        if category not in self.data:
            self.data[category] = {}
        self.data[category][name] = password
        self.save_data()

    def get_password(self, category, name):
        return self.data.get(category, {}).get(name, None)

if __name__ == "__main__":
    master_password = input("Enter the master password: ")
    manager = PasswordManager(master_password)

    while True:
        print("\n1. Add Password\n2. Get Password\n3. Generate Password\n4. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            category = input("Enter the category: ")
            name = input("Enter the name: ")
            password = input("Enter the password: ")
            manager.add_password(category, name, password)
            print("Password added successfully!")

        elif choice == '2':
            category = input("Enter the category: ")
            name = input("Enter the name: ")
            password = manager.get_password(category, name)
            if password:
                print(f"The password for {name} in {category} is: {password}")
            else:
                print("Password not found!")

        elif choice == '3':
            length = int(input("Enter the desired length of the password: "))
            password = generate_password(length)
            print(f"Generated password: {password}")

        elif choice == '4':
            break

        else:
            print("Invalid choice. Please try again.")
