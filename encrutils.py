import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Dict, Optional, List, Any

# Generic Dict to handle config
ConfigDict = Dict[str, Any]  

def generate_or_load_key(key_file: str) -> Optional[bytes]:
    """Generate and store a new encryption key if it doesn't exist already"""
    if os.path.exists(key_file):
        with open(key_file, 'rb') as file:
            key_data = file.read()
            # Ensure the key is a valid length for AES
            if len(key_data) not in (16, 24, 32):
                # If invalid key size detected, regenerate the key
                return None
            return key_data
    else:
        return generate_new_key(key_file)

def generate_new_key(key_file: str) -> bytes:
    """Generate a new AES-256 key and save it to file"""
    # Generate specifically a 256-bit key (32 bytes)
    key = os.urandom(32)  # 32 bytes = 256 bits
    
    # Save the key to file
    with open(key_file, 'wb') as file:
        file.write(key)
    
    return key

def encrypt_value(value: str, key: bytes) -> str:
    """Encrypt a string value with AES-GCM"""
    if not value:
        return value
    
    # Check if already encrypted
    if value.startswith('ENCRYPTED:'):
        return value
    
    # Generate a random 96-bit IV (recommended for GCM)
    iv = os.urandom(12)
    
    # Create an encryptor
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Encrypt the value
    ciphertext = encryptor.update(value.encode()) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    # Combine IV, ciphertext, and tag into a single string
    encrypted_data = base64.b64encode(iv + ciphertext + tag).decode()
    
    # Add a marker to identify encrypted values
    return f"ENCRYPTED:{encrypted_data}"

def decrypt_value(value: str, key: bytes) -> str:
    """Decrypt a value encrypted with AES-GCM"""
    if not value or not value.startswith('ENCRYPTED:'):
        return value
    
    # Get the base64-encoded data
    encrypted_data = base64.b64decode(value[10:])  # Remove 'ENCRYPTED:' prefix
    
    # Extract the IV (first 12 bytes), and tag (last 16 bytes)
    iv = encrypted_data[:12]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[12:-16]
    
    # Create a decryptor
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    
    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext.decode()

def handle_config_encryption(config: ConfigDict, key: bytes, 
                           sensitive_fields: List[str], 
                           original_config: ConfigDict) -> ConfigDict:
    """Recursively process config to encrypt sensitive fields, but only if they existed in original file"""
    encrypted_config: ConfigDict = {}
    
    for k, v in config.items():
        if isinstance(v, dict) and k in original_config and isinstance(original_config[k], dict):
            # Recursively handle nested dictionaries
            encrypted_config[k] = handle_config_encryption(v, key, sensitive_fields, original_config[k])
        elif k in sensitive_fields and v and k in original_config and original_config[k]:
            # Only encrypt and save if the field was in the original config
            # Add type checking to ensure v is a string before encrypting
            if isinstance(v, str):
                encrypted_config[k] = encrypt_value(v, key)
            else:
                # this should not happen as at the moment sensistive fields contain just strings
                encrypted_config[k] = v
        else:
            encrypted_config[k] = v
            
    return encrypted_config

def decrypt_config(config: ConfigDict, key: bytes) -> ConfigDict:
    """Recursively decrypt all encrypted values in the config"""
    decrypted_config: ConfigDict = {}
    
    for k, v in config.items():
        if isinstance(v, dict):
            decrypted_config[k] = decrypt_config(v, key)
        elif isinstance(v, str) and v.startswith('ENCRYPTED:'):
            decrypted_config[k] = decrypt_value(v, key)
        else:
            decrypted_config[k] = v
            
    return decrypted_config