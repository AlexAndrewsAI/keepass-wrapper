import subprocess
from unittest.mock import Mock, patch

from keepass_wrapper.encryption import EncryptionManager
from keepass_wrapper.entry import KeePassEntry


def test_entry_with_encryption() -> None:
    """Test creating a KeePassEntry with encryption."""
    mock_entry = Mock()
    mock_entry.title = "Gmail"
    mock_entry.username = "user@gmail.com"
    mock_entry.password = "super_secret_password"
    mock_entry.otp = "JBSWY3DPEBLW64TMMQ======"
    mock_entry.url = "https://mail.google.com"

    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    assert entry.title == "Gmail"
    assert entry.username == "user@gmail.com"
    assert entry.password is not None
    assert entry.otp is not None
    assert entry.url == "https://mail.google.com"


def test_entry_get_password_with_encryption() -> None:
    """Test retrieving decrypted password."""
    mock_entry = Mock()
    mock_entry.title = "Gmail"
    mock_entry.username = "user@gmail.com"
    mock_entry.password = "super_secret_password"
    mock_entry.otp = None
    mock_entry.url = None

    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    password = entry.get_password()
    assert password == "super_secret_password"


def test_entry_get_totp_with_encryption() -> None:
    """Test retrieving and generating TOTP."""
    mock_entry = Mock()
    mock_entry.title = "GitHub"
    mock_entry.username = "octocat"
    mock_entry.password = "password123"
    mock_entry.otp = "JBSWY3DPEBLW64TMMQ======"
    mock_entry.url = None

    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    totp = entry.get_totp()
    assert totp is not None
    assert len(totp) == 6
    assert totp.isdigit()


def test_entry_get_totp_with_url_format() -> None:
    """Test TOTP extraction from URL-formatted secret."""
    mock_entry = Mock()
    mock_entry.title = "GitHub"
    mock_entry.username = "octocat"
    mock_entry.password = "password123"
    mock_entry.otp = "secret=JBSWY3DPEBLW64TMMQ======&issuer=GitHub"
    mock_entry.url = None

    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    totp = entry.get_totp()
    assert totp is not None
    assert len(totp) == 6
    assert totp.isdigit()


def test_entry_get_password_no_encryption_manager() -> None:
    """Test get_password raises RuntimeError when encryption manager is removed."""
    mock_entry = Mock()
    mock_entry.title = "Test"
    mock_entry.username = "user"
    mock_entry.password = "secret"
    mock_entry.otp = None
    mock_entry.url = None

    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    # Remove the encryption manager to trigger the error
    entry._encryption_manager = None  # type: ignore[assignment]

    try:
        entry.get_password()
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        assert "Cannot decrypt password" in str(e)


def test_entry_get_totp_no_otp() -> None:
    """Test get_totp returns None when no OTP secret is stored."""
    mock_entry = Mock()
    mock_entry.title = "Test"
    mock_entry.username = "user"
    mock_entry.password = "secret"
    mock_entry.otp = None
    mock_entry.url = None

    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    totp = entry.get_totp()
    assert totp is None


def test_entry_get_totp_no_encryption_manager() -> None:
    """Test get_totp raises RuntimeError when encryption manager is removed."""
    mock_entry = Mock()
    mock_entry.title = "Test"
    mock_entry.username = "user"
    mock_entry.password = "secret"
    mock_entry.otp = "JBSWY3DPEBLW64TMMQ======"
    mock_entry.url = None

    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    # Remove the encryption manager to trigger the error
    entry._encryption_manager = None  # type: ignore[assignment]

    try:
        entry.get_totp()
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        assert "Cannot decrypt OTP" in str(e)


def test_entry_bash_with_password_success() -> None:
    """Test executing bash command with password input."""
    mock_entry = Mock()
    mock_entry.title = "SSH"
    mock_entry.username = "admin"
    mock_entry.password = "secure_pass"
    mock_entry.otp = None
    mock_entry.url = None

    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    with patch("subprocess.Popen") as mock_popen:
        mock_process = Mock()
        mock_process.communicate.return_value = ("output", "")
        mock_popen.return_value = mock_process

        stdout, stderr = entry.bash_with_password(["ssh", "user@host"])

        assert stdout == "output"
        assert stderr == ""
        mock_popen.assert_called_once()

        # Verify the process was called with stdin pipe
        call_kwargs = mock_popen.call_args[1]
        assert call_kwargs["stdin"] == subprocess.PIPE
        assert call_kwargs["stdout"] == subprocess.PIPE
        assert call_kwargs["stderr"] == subprocess.PIPE


def test_entry_bash_with_password_no_password() -> None:
    """Test bash_with_password raises error when password not available."""
    mock_entry = Mock()
    mock_entry.title = "Test"
    mock_entry.username = "user"
    mock_entry.password = None
    mock_entry.otp = None
    mock_entry.url = None
    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    try:
        entry.bash_with_password(["cmd"])
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Password not available" in str(e)


def test_entry_optional_fields() -> None:
    """Test entry with minimal fields."""
    mock_entry = Mock()
    mock_entry.title = "Minimal"
    mock_entry.username = None
    mock_entry.password = None
    mock_entry.otp = None
    mock_entry.url = None
    manager = EncryptionManager()
    entry = KeePassEntry(mock_entry, encryption_manager=manager)

    assert entry.title == "Minimal"
    assert entry.username is None
    assert entry.password is None
    assert entry.otp is None
    assert entry.url is None