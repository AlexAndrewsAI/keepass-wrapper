from cryptography.fernet import Fernet


class EncryptionManager:
    """Manages encryption/decryption operations."""

    def __init__(self) -> None:
        """Initialize with a new Fernet key."""
        self.key: bytes = Fernet.generate_key()
        self.cipher_suite: Fernet = Fernet(self.key)

    def encrypt(self, data: str) -> bytes:
        """Encrypt a string using Fernet.

        Args:
            data: The plaintext string to encrypt

        Returns:
            Encrypted bytes
        """
        return self.cipher_suite.encrypt(data.encode())

    def decrypt(self, data: bytes) -> str:
        """Decrypt encrypted bytes.

        Args:
            data: The encrypted bytes to decrypt

        Returns:
            Decrypted plaintext string
        """
        return self.cipher_suite.decrypt(data).decode()
