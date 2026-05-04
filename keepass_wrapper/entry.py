import subprocess
from typing import Protocol

from keepass_wrapper.encryption import EncryptionManager
from keepass_wrapper.otp import extract_totp_secret, generate_totp


class KeePassEntryLike(Protocol):
    """Protocol defining the interface of a pykeepass Entry."""
    title: str
    username: str | None
    url: str | None
    password: str | None
    otp: str | None


class KeePassEntry:
    """Represents a KeePass entry with optional encryption and TOTP support."""

    def __init__(
        self,
        entry: KeePassEntryLike,
        encryption_manager: EncryptionManager | None = None,
    ) -> None:
        """Initialize a KeePass entry."""
        self.title: str = entry.title
        self.username: str | None = entry.username if entry.username else None
        self.url: str | None = entry.url if entry.url else None
        self._encryption_manager = encryption_manager

        # Store password/OTP as either encrypted (bytes) or plaintext (str)
        self.password: str | bytes | None = None
        self.otp: str | bytes | None = None

        if encryption_manager:
            if entry.password:
                self.password = encryption_manager.encrypt(entry.password)
            if entry.otp:
                self.otp = encryption_manager.encrypt(entry.otp)
        else:
            self.password = entry.password if entry.password else None
            self.otp = entry.otp if entry.otp else None

    def get_password(self) -> str | None:
        """Retrieve decrypted password."""
        if not self.password:
            return None
        
        if isinstance(self.password, bytes):
            assert self._encryption_manager is not None
            return self._encryption_manager.decrypt(self.password)
        return self.password

    def get_totp(self) -> str | None:
        """Generate TOTP code from encrypted OTP secret."""
        if not self.otp:
            return None
        
        if isinstance(self.otp, bytes):
            assert self._encryption_manager is not None
            otp_value = self._encryption_manager.decrypt(self.otp)
        else:
            otp_value = self.otp
        
        secret = extract_totp_secret(otp_value)
        return generate_totp(secret)

    def bash_with_password(
        self,
        command: list[str],
        count: int = 1,
    ) -> tuple[str, str]:
        """Execute a bash command with password input."""
        password = self.get_password()
        if not password:
            raise ValueError("Password not available for bash execution")

        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        password_input = (password + "\n") * count
        stdout, stderr = process.communicate(input=password_input)

        return stdout, stderr
