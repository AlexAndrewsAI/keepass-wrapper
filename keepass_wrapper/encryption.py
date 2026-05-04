"""Encryption utilities for secure password storage using Fernet.

This module provides symmetric encryption for sensitive data (passwords and OTP
secrets) using the cryptography library's Fernet scheme. Fernet provides strong
encryption with built-in timestamp verification and HMAC authentication.
"""

from cryptography.fernet import Fernet


class EncryptionManager:
    """Manages in-memory encryption and decryption of sensitive data.
    
    This class provides a simple interface for symmetric encryption using Fernet,
    a strong cryptographic scheme that includes authentication and timestamp
    verification. A new encryption key is generated for each EncryptionManager
    instance, meaning encryption is session-based and keys are not persisted.
    
    Security Considerations:
        - A new key is generated per session; encrypted data cannot be decrypted
          in future sessions.
        - Encryption is performed in-memory only; data at rest in the KeePass
          database remains in its original encrypted state.
        - Keys are stored in memory; data remains encrypted only while the
          EncryptionManager instance is alive.
        - Suitable for protecting passwords in memory during program execution,
          not for persistent storage.
    
    Attributes:
        key: The Fernet encryption key as bytes (randomly generated on init).
        cipher_suite: The Fernet cipher instance used for encryption/decryption.
    """

    def __init__(self) -> None:
        """Initialize the encryption manager with a new Fernet key.
        
        Generates a new random Fernet key and creates a cipher suite instance.
        The key and cipher suite are stored in memory for use during the lifetime
        of this object. Once the object is destroyed, the key is lost and any
        encrypted data from this session cannot be decrypted.
        
        Returns:
            None
        """
        self.key: bytes = Fernet.generate_key()
        self.cipher_suite: Fernet = Fernet(self.key)

    def encrypt(self, data: str) -> bytes:
        """Encrypt a plaintext string using Fernet symmetric encryption.
        
        Converts the input string to bytes and encrypts it using the session's
        Fernet cipher suite. The resulting ciphertext includes a timestamp and
        HMAC for authentication and tamper detection.
        
        Args:
            data: The plaintext string to encrypt (e.g., a password or OTP secret).
        
        Returns:
            Encrypted bytes containing the ciphertext, timestamp, and HMAC.
            Can be safely stored and later decrypted with the decrypt() method.
        """
        return self.cipher_suite.encrypt(data.encode())

    def decrypt(self, data: bytes) -> str:
        """Decrypt Fernet-encrypted bytes to plaintext string.
        
        Decrypts the ciphertext using the session's Fernet cipher suite. The
        timestamp and HMAC are automatically verified; an exception is raised
        if the data is tampered with or expired.
        
        Args:
            data: The encrypted bytes (typically produced by encrypt()).
        
        Returns:
            Decrypted plaintext string.
        
        Raises:
            cryptography.fernet.InvalidToken: If the ciphertext is invalid,
                                             tampered with, or was encrypted
                                             with a different key.
        """
        return self.cipher_suite.decrypt(data).decode()
