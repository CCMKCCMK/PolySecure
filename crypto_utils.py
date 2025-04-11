import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import InvalidTag

def hash_password(password, salt=None):
    """
    Hash a password using PBKDF2 with SHA256.
    
    Args:
        password (str): The password to hash
        salt (bytes, optional): Salt for the hash. If not provided, generates random salt
        
    Returns:
        tuple: (key, salt) where key is the derived key and salt is the salt used
    """
    if not salt:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_file(file_data, key):
    """
    Encrypt file data using AES-GCM.
    
    Args:
        file_data (bytes): Data to encrypt
        key (bytes): Encryption key
        
    Returns:
        bytes: IV + authentication tag + encrypted data
    """
    iv = os.urandom(12)  # GCM mode needs 12 bytes IV
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    return iv + encryptor.tag + encrypted_data


def decrypt_file(encrypted_data, key):
    """
    Decrypt file data using AES-GCM.

    Args:
        encrypted_data (bytes): IV + tag + encrypted data
        key (bytes): Decryption key

    Returns:
        bytes: Decrypted data

    Raises:
        InvalidTag if authentication fails
    """
    try:
        # Extract IV (Initialization Vector), tag, and ciphertext
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        # # Debug: Print extracted components
        # print("[DEBUG] IV (hex):", iv.hex())
        # print("[DEBUG] Tag (hex):", tag.hex())
        # print("[DEBUG] Ciphertext length:", len(ciphertext))
        #
        # # Debug: Print decryption key
        # print("[DEBUG] Decryption key (hex):", key.hex())

        # Initialize the decryptor
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
        ).decryptor()
        # print("[DEBUG] Decryptor initialized successfully.")

        # Perform decryption
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        # print("[DEBUG] Decryption completed successfully.")

        return decrypted_data
    except InvalidTag as e:
        print("[ERROR] Decryption failed: Invalid tag. The data may have been tampered with or the key is incorrect.")
        raise e
    except Exception as e:
        print("[ERROR] Decryption failed:", str(e))
        raise e

def generate_key_pair():
    """
    Generate RSA public/private key pair.
    
    Returns:
        tuple: (private_key_pem, public_key_pem) as PEM-encoded bytes
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_bytes, public_bytes

def encrypt_file_key(file_key, public_key_pem):
    """
    Encrypt a file key using RSA public key.
    
    Args:
        file_key (bytes): Symmetric key to encrypt
        public_key_pem (bytes): PEM-encoded public key
        
    Returns:
        bytes: Encrypted file key
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_key = public_key.encrypt(
        file_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_file_key(encrypted_key, private_key_pem):
    """
    Decrypt a file key using RSA private key.
    
    Args:
        encrypted_key (bytes): Encrypted symmetric key
        private_key_pem (bytes): PEM-encoded private key
        
    Returns:
        bytes: Decrypted file key
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )
    file_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return file_key

def sign_data(data, private_key_pem):
    """
    Create digital signature using RSA private key.
    
    Args:
        data (bytes): Data to sign
        private_key_pem (bytes): PEM-encoded private key
        
    Returns:
        bytes: Digital signature
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data, signature, public_key_pem):
    """
    Verify digital signature using RSA public key.
    
    Args:
        data (bytes): Original data
        signature (bytes): Signature to verify
        public_key_pem (bytes): PEM-encoded public key
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def validate_filename(filename):
    """
    Validate filename to prevent path traversal attacks.
    
    Args:
        filename (str): Filename to validate
        
    Returns:
        bool: True if filename is valid, False otherwise
        
    Only allows alphanumeric characters, underscore, hyphen and period.
    """
    import re
    return bool(re.match(r'^[a-zA-Z0-9_\-\.]+$', filename))
