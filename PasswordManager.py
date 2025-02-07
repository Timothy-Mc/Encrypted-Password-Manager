import sqlite3
import base64
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from getpass import getpass


DB_Name = "passwords.db"

def initialise_DB():
    connection = sqlite3.connect(DB_Name)
    cursor = connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
          id INTEGER PRIMARY KEY,
          service TEXT,
          username TEXT,
          password TEXT
            )
          ''')
    connection.commit()
    connection.close()

def obtain_key():
    # Obtain key from file
    with open("aes_key.key", "rb") as key_file:
        data = key_file.read()
        salt, key = data[:16], data[16:]
        return base64.urlsafe_b64decode(key)

def encrypt(password, key):
    # ? Encrypts using AES-256-GCM

    #Random initialisation vector
    iv = os.urandom(12) #! Size is typically 12 bytes because the GCM mode utilizes a 16-byte nonce, with the first 12 bytes dedicated to the IV and the remaining 4 bytes used as a counter

    # https://cryptography.io/en/3.4.2/hazmat/primitives/symmetric-encryption.html#cryptography.hazmat.primitives.ciphers.CipherAlgorithm
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(password.encode()) + encryptor.finalize()
    
    #https://docs.python.org/3/library/base64.html
    return base64.b64encode(iv + encryptor.tag + ct).decode() # Store IV + tag + ciphertext

def decrypt(encrypted_passwd, key):
    # ? Decrypts using AES-256-GCM

    encrypted_data = base64.b64decode(encrypted_passwd)
    iv = encrypted_data[:12] # The first 12 bytes where the iv is stored is looked at, used for randomness in AES-GCM encryption
    tag = encrypted_data[12:28] # The next 16 bytes (28-12 = 16) are looked at which verifies the data hasn't been tampered with.
    ct = encrypted_data[28:] #The remaining bytes which is the actual encrypted password.

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag)) #AES-256 Encpytion, GCM mode - IV used for decryption and Authentication Tag for integrity check
    decryptor = cipher.decryptor()

    return (decryptor.update(ct) + decryptor.finalize()).decode()
    

def store_pass():
    key = obtain_key()

    service = input("Service: ")
    username = input("Username: ")
    password = getpass("Password: ")

    encrypted_passwd = encrypt(password, key)

    connection = sqlite3.connect(DB_Name)
    cursor = connection.cursor()
    cursor.execute('INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)', (service, username, encrypted_passwd))
    connection.commit()
    connection.close()
    print("Password Stored")


def retrieve_pass():
    key = obtain_key()
    service = input("Service you want to retrieve: ")

    connection = sqlite3.connect(DB_Name)
    cursor = connection.cursor()
    cursor.execute('SELECT username, password FROM passwords WHERE service=?', (service,))
    result = cursor.fetchone()
    connection.close()
    
    if result:
        username, encrypted_passwd = result
        decrypted_passwd = decrypt(encrypted_passwd, key)
        print(f"\nService {service}\nUsername: {username}\nPassword: {decrypted_passwd}")
    else:
        print("Nothing found.")

def main():
    initialise_DB()
    

    while True:
        print("\n1. Store Passwords\n2. Retrieve Passwords\n3. Exit\n")
        choice = input("Enter Choice: ")

        if choice == "1":
            store_pass()
        elif choice == "2":
            retrieve_pass()
        elif choice == "3":
            break
        else:
            print("Invalid Input")

if __name__ == "__main__":
    main()