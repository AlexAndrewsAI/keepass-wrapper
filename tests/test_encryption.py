import pytest
from cryptography.fernet import InvalidToken

from keepass_wrapper.encryption import EncryptionManager


def test_encryption_manager_creates_key() -> None:
    """Test that EncryptionManager creates a key on initialization."""
    manager = EncryptionManager()
    assert manager._key is not None
    assert len(manager._key) > 0


def test_encrypt_decrypt_roundtrip() -> None:
    """Test that encryption and decryption are reversible."""
    manager = EncryptionManager()
    original = "my_secret_password"

    encrypted = manager.encrypt(original)
    decrypted = manager.decrypt(encrypted)

    assert decrypted == original


def test_different_keys_cant_decrypt() -> None:
    """Test that data encrypted with one key cannot be decrypted with another."""
    manager1 = EncryptionManager()
    manager2 = EncryptionManager()

    encrypted = manager1.encrypt("secret_data")

    # A Fernet token signed with a different key must raise InvalidToken.
    # Narrow assertion (B017/PT011): the broader Exception is not acceptable
    # because it would also swallow programming errors such as AttributeError.
    with pytest.raises(InvalidToken):
        manager2.decrypt(encrypted)


def test_clear_overwrites_key_with_zeros() -> None:
    """Test that clear() overwrites the key with zeros for security."""
    manager = EncryptionManager()
    original_key = manager._key

    manager.clear()

    # After clear, the key should be all zeros
    assert manager._key == b"\x00" * len(original_key)
