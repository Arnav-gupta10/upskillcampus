import json
import hashlib
import getpass
import os
import pyperclip
import sys
from cryptography.fernet import Fernet


def hash_password(password: str) -> str:
    """Hashes the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()


def generate_key() -> bytes:
    """Generates a new Fernet key."""
    return Fernet.generate_key()


def initialize_cipher(key: bytes) -> Fernet:
    """Initializes Fernet cipher with a key."""
    return Fernet(key)


def encrypt_password(cipher: Fernet, password: str) -> str:
    """Encrypts the password using Fernet."""
    return cipher.encrypt(password.encode()).decode()


def decrypt_password(cipher: Fernet, encrypted_password: str) -> str:
    """Decrypts the password using Fernet."""
    return cipher.decrypt(encrypted_password.encode()).decode()


def load_encryption_key(key_filename='encryption_key.key') -> Fernet:
    """Loads or generates and stores the encryption key."""
    if os.path.exists(key_filename):
        with open(key_filename, 'rb') as file:
            key = file.read()
    else:
        key = generate_key()
        with open(key_filename, 'wb') as file:
            file.write(key)
    return initialize_cipher(key)


def register(username: str, master_password: str):
    """Registers a new user."""
    file_name = 'user_data.json'

    if os.path.exists(file_name) and os.path.getsize(file_name) != 0:
        print("\n[-] A user is already registered.")
        return

    user_data = {
        'username': username,
        'master_password': hash_password(master_password)
    }

    with open(file_name, 'w') as file:
        json.dump(user_data, file)
    print("\n[+] Registration successful!\n")


def login(username: str, password: str) -> bool:
    """Logs in the user by validating credentials."""
    try:
        with open('user_data.json', 'r') as file:
            user_data = json.load(file)

        if (hash_password(password) == user_data.get('master_password')
                and username == user_data.get('username')):
            print("\n[+] Login successful!\n")
            return True
        else:
            print("\n[-] Invalid credentials!\n")
            return False

    except (FileNotFoundError, json.JSONDecodeError):
        print("\n[-] No user registered yet.\n")
        return False


def view_websites():
    """Displays all saved website entries."""
    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
            if not data:
                print("\n[-] No passwords saved yet.\n")
                return
            print("\nSaved Websites:\n" + "\n".join(f"- {entry['website']}" for entry in data) + "\n")
    except (FileNotFoundError, json.JSONDecodeError):
        print("\n[-] No password data found.\n")


def add_password(website: str, password: str, cipher: Fernet):
    """Adds an encrypted password for a website."""
    data = []

    if os.path.exists('passwords.json'):
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

    encrypted_password = encrypt_password(cipher, password)
    password_entry = {'website': website, 'password': encrypted_password}
    data.append(password_entry)

    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)


def get_password(website: str, cipher: Fernet) -> str | None:
    """Retrieves the decrypted password for a website."""
    if not os.path.exists('passwords.json'):
        return None

    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
        for entry in data:
            if entry['website'].lower() == website.lower():
                return decrypt_password(cipher, entry['password'])
    except json.JSONDecodeError:
        return None
    return None


# ---------- Program Execution Starts Here ----------
cipher = load_encryption_key()

while True:
    print("1. Register")
    print("2. Login")
    print("3. Quit")
    choice = input("Enter your choice: ").strip()

    if choice == '1':
        if os.path.exists('user_data.json') and os.path.getsize('user_data.json') != 0:
            print("\n[-] A user already exists.")
            continue
        username = input("Enter username: ").strip()
        master_password = getpass.getpass("Enter master password: ")
        register(username, master_password)

    elif choice == '2':
        if not os.path.exists('user_data.json'):
            print("\n[-] Please register first.\n")
            continue
        username = input("Enter username: ").strip()
        master_password = getpass.getpass("Enter master password: ")
        if not login(username, master_password):
            continue

        while True:
            print("\n1. Add Password")
            print("2. Get Password")
            print("3. View Websites")
            print("4. Logout")

            sub_choice = input("Enter your choice: ").strip()

            if sub_choice == '1':
                website = input("Enter website: ").strip()
                password = getpass.getpass("Enter password: ").strip()
                add_password(website, password, cipher)
                print("\n[+] Password saved!\n")

            elif sub_choice == '2':
                website = input("Enter website to retrieve: ").strip()
                password = get_password(website, cipher)
                if password:
                    pyperclip.copy(password)
                    print(f"\n[+] Password for {website}: {password}\n[+] Copied to clipboard.\n")
                else:
                    print("\n[-] No password found for this website.\n")

            elif sub_choice == '3':
                view_websites()

            elif sub_choice == '4':
                print("\n[+] Logged out.\n")
                break

            else:
                print("\n[-] Invalid choice!\n")

    elif choice == '3':
        print("\n[+] Exiting Password Manager. Bye!\n")
        break

    else:
        print("\n[-] Invalid main menu choice!\n")
