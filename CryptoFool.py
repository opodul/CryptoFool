import base64
import hashlib
import binascii
import os
import getpass
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_custom_salt(length=12):
    lowers = "abcdefghijkmnopqrstuvwxyz"     # excluded: l
    uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ"      # excluded: I, O
    digits = "123456789"                     # excluded: 0

    result = []
    last_type = None

    for i in range(length):
        if i == 0:
            # First character can be anything
            pool = lowers + uppers + digits
        else:
            if last_type == "digit":
                pool = lowers + uppers
            elif last_type == "lower":
                pool = uppers + digits
            else:  # last_type == "upper"
                pool = lowers + digits

        char = secrets.choice(pool)
        result.append(char)

        # Update last_type
        if char in digits:
            last_type = "digit"
        elif char in lowers:
            last_type = "lower"
        else:
            last_type = "upper"

    return "".join(result)

def derive_key(password, salt, iterations):
    """Derive a 256-bit key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def decrypt_string(full_string, password):
    """Decode and decrypt the string format: Hint$Salt!Iter#Data."""
    try:
        # Parsing the format: Indication$Salt!Iterations#Data
        parts = full_string.split('$')
        hint_part = parts[0]
        
        salt_and_iter = parts[1].split('!')
        salt_part = salt_and_iter[0]
        
        iter_and_data = salt_and_iter[1].split('#')
        iterations = int(iter_and_data[0])
        data_part = iter_and_data[1]
        
        # Base64 decode to retrieve IV (12 bytes) + Ciphertext
        iv_data = base64.b64decode(data_part)
        iv = iv_data[:12]
        datain = iv_data[12:]
        
        # Derive the exact same key as the HTML tool
        key = derive_key(password, salt_part, iterations)
        
        # AES-GCM Decryption
        aesgcm = AESGCM(key)
        dataout = aesgcm.decrypt(iv, datain, None)
        
        return dataout.decode('utf-8')
    except Exception as e:
        return f"\n[!] Decryption Error: Incorrect password or invalid format.\nDetails: {e}"

def encrypt_string(hint, salt, iterations, datain, password):
    """Encrypt data and generate the Hint$Salt!Iter#Data string."""
    # Derive the secret key
    key = derive_key(password, salt, iterations)
    
    # AES-GCM Encryption
    aesgcm = AESGCM(key)
    
    # Generate a random 12-byte IV (nonce) using OS entropy
    iv = os.urandom(12) 
    
    dataout = aesgcm.encrypt(iv, datain.encode('utf-8'), None)
    
    # Concatenate IV + Ciphertext then encode to Base64
    iv_data = iv + dataout
    b64_data = base64.b64encode(iv_data).decode('utf-8')
    
    return f"{hint}${salt}!{iterations}#{b64_data}"

def main():
    print("="*40)
    print("     PYTHON CryptoFool ")
    print("="*40)
    
    choice = input("\n[E] Encrypt a message\n[D] Decrypt a string\nChoice: ").lower()
    
    if choice == 'e':
        hint = input("Password Hint: ")
        def_salt = generate_custom_salt()
        salt = input(f"Salt [{def_salt}]: ") or def_salt
        it = int(input("Iterations [654321]: ") or "654321")
        msg = input("Data: ")
        pwd = getpass.getpass("Password: ")
        
        encrypted_str = encrypt_string(hint, salt, it, msg, pwd)
        header="--------- GENERATED METADATA ---------"
        print(f"\n{header}")
        print(encrypted_str)
        print("-" * len(header) )
        
    elif choice == 'd':
        full_str = input("\nPaste full string (Hint$Salt!Iter#Data):\n> ").strip()
        pwd = getpass.getpass("Master Password: ")
        
        decrypted_msg = decrypt_string(full_str, pwd)
        header="--------- DECRYPTED MESSAGE ---------"
        print(f"\n{header}")
        print(decrypted_msg)
        print("-" * len(header) )
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
    
