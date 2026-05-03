import subprocess
from typing import Optional

from keepass_wrapper.encryption import EncryptionManager
from keepass_wrapper.otp import extract_totp_secret, generate_totp


class KeePassEntry:
    """Represents a KeePass entry with optional encryption and TOTP support."""

    def __init__(
        self,
        entry: object,
        encryption_manager: Optional[EncryptionManager] = None,
    ) -> None:
        """Initialize a KeePass entry.

        Args:
            entry: A pykeepass Entry object
            encryption_manager: Optional EncryptionManager for encrypting sensitive data
        """
        self.title: str = entry.title  # type: ignore
        self.username: Optional[str] = entry.username if entry.username else None  # type: ignore
        self.url: Optional[str] = entry.url if entry.url else None  # type: ignore

        # Encrypt password and OTP if encryption manager is provided
        self.password: Optional[bytes] = None
        self.otp: Optional[bytes] = None

        # Encrypt password and OTP if encryption manager is provided
        if encryption_manager:
            if entry.password:  # type: ignore
                self.password = encryption_manager.encrypt(entry.password)  # type: ignore
            if entry.otp:  # type: ignore
                self.otp = encryption_manager.encrypt(entry.otp)  # type: ignore
        else:
            # Store plaintext password when no encryption
            self.password = entry.password if entry.password else None  # type: ignore
            self.otp = entry.otp if entry.otp else None  # type: ignore

        self._encryption_manager = encryption_manager



    def get_password(self) -> Optional[str]:
        """Retrieve decrypted password.

        Returns:
            The plaintext password or None if not available
        """
        if self.password and self._encryption_manager:
            return self._encryption_manager.decrypt(self.password)
        return None

    def get_totp(self) -> Optional[str]:
        """Generate TOTP code from encrypted OTP secret.

        Returns:
            The current TOTP code or None if OTP not available
        """
        if self.otp and self._encryption_manager:
            decrypted_otp = self._encryption_manager.decrypt(self.otp)
            secret = extract_totp_secret(decrypted_otp)
            return generate_totp(secret)
        return None

    def bash_with_password(
        self,
        command: list[str],
        count: int = 1,
    ) -> tuple[str, str]:
        """Execute a bash command with password input.

        Args:
            command: List of command arguments (as for subprocess.Popen)
            count: Number of times to repeat the password input

        Returns:
            Tuple of (stdout, stderr)
        """
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
