import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# AES Encryption
# AES Encryption with CFB mode and Padding
# AES Encryption with CFB mode and Padding
def encrypt_file(file_data, password):
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive a key using the password and salt (key derivation function)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Use AES in CFB mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to ensure it's the correct block size for AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the padded file data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data, key, iv, salt



# AES Decryption with CFB mode and Padding Removal
def decrypt_file(encrypted_data, password, iv, salt):
    # Ensure the password is always encoded to bytes
    password = password.encode()  # Always encode the password, assuming it's passed as a string

    # Derive the key from the password and salt
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password)

    # Create the cipher for decryption using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data to restore the original file
    try:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except ValueError as e:
        raise ValueError(f"Padding error: {str(e)}")

    return data




# Encrypt the AES key (password as a string) with the requester's public RSA key
def encrypt_key_for_requester(password, requester_public_key):
    # Ensure the password is in string format
    password_bytes = password.encode('utf-8')  # Convert string to bytes

    # Import the requester's public RSA key
    rsa_key = RSA.import_key(requester_public_key)
    
    # Create the RSA cipher
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    # Encrypt the password (which is now in bytes)
    encrypted_key = cipher_rsa.encrypt(password_bytes)
    
    return encrypted_key


# Decrypt the AES key (password as a string) with the requester's private RSA key
def decrypt_key_for_requester(encrypted_key, requester_private_key):
    # Import the requester's private RSA key
    rsa_key = RSA.import_key(requester_private_key)
    
    # Create the RSA cipher
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    # Decrypt the encrypted password (AES key), which is in bytes
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    
    # Convert the decrypted password (bytes) back to a string
    decrypted_key_string = decrypted_key.decode('utf-8')
    
    return decrypted_key_string

def generate_aes_key(password, salt):
    from hashlib import pbkdf2_hmac
    key = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key