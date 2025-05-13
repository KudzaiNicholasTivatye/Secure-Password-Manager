# Secure Password Manager

A robust and secure password manager built in Python that allows users to safely store, manage, and encrypt their passwords using strong cryptographic practices.

---

## Features

- **Master Password Protection:**  
  Set a master password on first use. The master password is required to access the password vault on subsequent logins.

- **Strong Encryption:**  
  Passwords are encrypted using Fernet symmetric encryption (AES-128 in CBC mode with HMAC-SHA256) and a key derived securely from the master password using PBKDF2-HMAC-SHA256 with a unique salt.

- **Password Management:**  
  Add, view, and delete passwords for various services securely.

- **Change Master Password:**  
  Change the master password at any time, which securely re-encrypts all stored passwords with the new key.

- **Secure Storage:**  
  Passwords and configuration (salt and hashed master password) are stored locally in encrypted form.

---

## How It Works

1. **Setup:**  
   On first run, the user sets a master password. A unique salt is generated and stored, and a hash of the master password is saved securely.

2. **Login:**  
   On subsequent runs, the user must enter the master password to unlock the vault.

3. **Encryption:**  
   The master password and salt are used to derive an encryption key via PBKDF2-HMAC-SHA256. This key encrypts/decrypts all stored passwords using Fernet symmetric encryption.

4. **Password Management:**  
   Users can add new passwords, view decrypted passwords, delete entries, and change the master password securely.

---

## Installation

1. Clone the repository:


2. Install dependencies:


---

## Usage

Run the password manager script:


Follow the on-screen prompts to:

- Set or enter your master password  
- Add, view, or delete passwords  
- Change your master password  

---

## Security Notes

- The master password is never stored in plain text.  
- Passwords are encrypted at rest and only decrypted in memory when needed.  
- Uses industry-standard cryptographic algorithms and key derivation functions.  
- Always keep your master password secure and do not share it.

---

## Technologies Used

- Python 3  
- `cryptography` library for encryption  
- SQLite for local password storage  
- PBKDF2-HMAC-SHA256 for key derivation  
- Fernet symmetric encryption (AES + HMAC)

---

## Acknowledgments

Thanks to [Uncommon.org](https://uncommon.org) for the opportunity to learn Python and software development with a focus on cybersecurity.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
