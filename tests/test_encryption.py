from keepass_wrapper.encryption import EncryptionManager


def test_encryption_manager_creates_key() -> None:
    manager = EncryptionManager()
    assert manager.key is not None
    assert len(manager.key) > 0


def test_encrypt_decrypt_roundtrip() -> None:
    manager = EncryptionManager()
    original = "my_secret_password"

    encrypted = manager.encrypt(original)
    decrypted = manager.decrypt(encrypted)

    assert decrypted == original


def test_different_keys_cant_decrypt() -> None:
    manager1 = EncryptionManager()
    manager2 = EncryptionManager()

    encrypted = manager1.encrypt("secret_data")

    # This should raise an exception
    try:
        manager2.decrypt(encrypted)
        assert False, "Should have raised an exception"
    except Exception:
        pass  # Expected
