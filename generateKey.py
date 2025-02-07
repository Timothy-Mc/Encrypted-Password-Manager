from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/

def generate_key():
    password = input("Set master passwoord: ").encode()
    salt = os.urandom(16)
    #Derive
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    with open("aes_key.key", "wb") as key_file:
        key_file.write(salt+key)

    print("Encryption Completed")

generate_key()