"""
Encryption utilities for sensitive data protection
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class PasswordEncryption:
    """Handles encryption/decryption of passwords at rest"""
    
    def __init__(self, key=None):
        """
        Initialize encryption with a key
        
        Args:
            key: Optional encryption key. If not provided, will generate or load from env
        """
        if key:
            self.key = key
        else:
            # Load from environment or generate
            key_b64 = os.environ.get('ADBASHER_ENCRYPTION_KEY')
            if key_b64:
                self.key = base64.urlsafe_b64decode(key_b64)
            else:
                # Generate new key (should be saved to .env in production)
                self.key = Fernet.generate_key()
                print(f"WARNING: Generated new encryption key. Save to .env as ADBASHER_ENCRYPTION_KEY={self.key.decode()}")
        
        self.cipher = Fernet(self.key)
    
    def encrypt_password(self, password: str) -> str:
        """
        Encrypt a password
        
        Args:
            password: Plain text password
            
        Returns:
            Base64-encoded encrypted password
        """
        if not password:
            return ""
        
        encrypted = self.cipher.encrypt(password.encode())
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt_password(self, encrypted_password: str) -> str:
        """
        Decrypt a password
        
        Args:
            encrypted_password: Base64-encoded encrypted password
            
        Returns:
            Plain text password
        """
        if not encrypted_password:
            return ""
        
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_password.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode('utf-8')

# Global encryption instance
encryption = PasswordEncryption()

def encrypt_sensitive_data(data: dict) -> dict:
    """
    Encrypt sensitive fields in a dictionary
    
    Args:
        data: Dictionary potentially containing sensitive data
        
    Returns:
        Dictionary with encrypted sensitive fields
    """
    encrypted = data.copy()
    
    # Encrypt password if present
    if 'password' in encrypted and encrypted['password']:
        encrypted['password'] = encryption.encrypt_password(encrypted['password'])
        encrypted['password_encrypted'] = True
    
    return encrypted

def decrypt_sensitive_data(data: dict) -> dict:
    """
    Decrypt sensitive fields in a dictionary
    
    Args:
        data: Dictionary with encrypted sensitive fields
        
    Returns:
        Dictionary with decrypted sensitive fields
    """
    decrypted = data.copy()
    
    # Decrypt password if encrypted
    if data.get('password_encrypted') and 'password' in decrypted:
        decrypted['password'] = encryption.decrypt_password(decrypted['password'])
        decrypted['password_encrypted'] = False
    
    return decrypted

def generate_encryption_key() -> str:
    """Generate a new encryption key for .env file"""
    key = Fernet.generate_key()
    return key.decode()
