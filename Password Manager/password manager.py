import sqlite3
import os
import base64
import hashlib
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

DB_FILE = "passwords.db"
CONFIG_FILE = "config.bin"

def get_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "rb") as f:
        return f.read()

def set_config(data):
    with open(CONFIG_FILE, "wb") as f:
        f.write(data)

def hash_master_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 390000)

def setup_master_password():
    print("=== Set up your master password ===")
    while True:
        pw1 = getpass("Enter a new master password: ")
        pw2 = getpass("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match. Try again.")
        elif not pw1.strip():
            print("Password cannot be empty.")
        else:
            break
    salt = os.urandom(16)
    pw_hash = hash_master_password(pw1, salt)
    set_config(salt + pw_hash)
    print("Master password set successfully.")
    return pw1, salt

def verify_master_password():
    config = get_config()
    if not config or len(config) != 48:
        return setup_master_password()
    salt = config[:16]
    stored_hash = config[16:]
    for _ in range(3):
        pw = getpass("Enter your master password: ")
        if hash_master_password(pw, salt) == stored_hash:
            print("Login successful.")
            return pw, salt
        else:
            print("Incorrect master password.")
    print("Too many failed attempts. Exiting.")
    exit(1)

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def add_password(service, username, password, fernet):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    encrypted_password = fernet.encrypt(password.encode()).decode()
    c.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
              (service, username, encrypted_password))
    conn.commit()
    conn.close()
    print("Password added securely!")

def get_passwords(fernet):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, service, username, password FROM passwords")
    rows = c.fetchall()
    conn.close()
    if not rows:
        print("No passwords stored.")
        return []
    print("\nStored passwords:")
    for row in rows:
        id, service, username, encrypted_password = row
        try:
            password = fernet.decrypt(encrypted_password.encode()).decode()
        except Exception:
            password = "<decryption failed>"
        print(f"ID: {id}\nService: {service}\nUsername: {username}\nPassword: {password}\n")
    return rows

def delete_password(fernet):
    rows = get_passwords(fernet)
    if not rows:
        return
    try:
        del_id = int(input("Enter the ID of the password to delete: "))
    except ValueError:
        print("Invalid ID.")
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE id = ?", (del_id,))
    conn.commit()
    conn.close()
    print("Password deleted (if ID was valid).")

def change_master_password(master_password, salt, fernet):
    # Verify current master password before allowing change
    print("\n--- Change Master Password ---")
    for attempt in range(3):
        current_pw = getpass("Enter your current master password: ")
        if hash_master_password(current_pw, salt) == hash_master_password(master_password, salt):
            break
        else:
            print("Incorrect password.")
    else:
        print("Too many failed attempts. Returning to menu.")
        return master_password, salt, fernet

    # Get all passwords and decrypt them
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, password FROM passwords")
    rows = c.fetchall()
    decrypted_passwords = []
    for row in rows:
        id, encrypted_password = row
        try:
            password = fernet.decrypt(encrypted_password.encode()).decode()
            decrypted_passwords.append((id, password))
        except Exception:
            print(f"Failed to decrypt password for entry ID {id}. Aborting change.")
            conn.close()
            return master_password, salt, fernet

    # Prompt for new master password
    while True:
        new_master_password = getpass("Enter new master password: ")
        confirm_password = getpass("Confirm new master password: ")
        if new_master_password != confirm_password:
            print("Passwords do not match. Try again.")
        elif not new_master_password.strip():
            print("Password cannot be empty. Try again.")
        else:
            break

    new_salt = os.urandom(16)
    new_pw_hash = hash_master_password(new_master_password, new_salt)
    set_config(new_salt + new_pw_hash)
    new_key = derive_key(new_master_password, new_salt)
    new_fernet = Fernet(new_key)

    # Re-encrypt all passwords
    for id, password in decrypted_passwords:
        new_encrypted = new_fernet.encrypt(password.encode()).decode()
        c.execute("UPDATE passwords SET password=? WHERE id=?", (new_encrypted, id))
    conn.commit()
    conn.close()
    print("Master password changed and all passwords re-encrypted successfully!")
    return new_master_password, new_salt, new_fernet

def main():
    print("=== Nicholas Secure Password Manager ===")
    master_password, salt = verify_master_password()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    init_db()

    while True:
        print("\nOptions:")
        print("1. Add new password")
        print("2. View stored passwords")
        print("3. Delete a password")
        print("4. Change master password")
        print("5. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            service = input("Service name: ")
            username = input("Username: ")
            password = getpass("Password: ")
            add_password(service, username, password, fernet)
        elif choice == "2":
            get_passwords(fernet)
        elif choice == "3":
            delete_password(fernet)
        elif choice == "4":
            master_password, salt, fernet = change_master_password(master_password, salt, fernet)
        elif choice == "5":
            print("Your passwords have been securely stored. Goodbye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
