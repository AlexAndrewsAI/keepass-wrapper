import subprocess
from typing import Protocol

from keepass_wrapper.encryption import EncryptionManager
from keepass_wrapper.otp import extract_totp_secret, generate_totp


class KeePassEntryLike(Protocol):
    """Protocol defining the interface of a pykeepass Entry.
    
    This protocol ensures type compatibility with pykeepass Entry objects,
    allowing duck-typing for testing and flexibility with different KeePass
    implementations.
    
    Attributes:
        title: The display name of the password entry.
        username: The associated username or login identifier.
        url: The website or service URL associated with the entry.
        password: The plaintext password value.
        otp: The OTP configuration or secret string (often in TOTP format).
    """
    title: str
    username: str | None
    url: str | None
    password: str | None
    otp: str | None


class KeePassEntry:
    """Represents a KeePass password entry with optional encryption and TOTP support.
    
    This class wraps a pykeepass Entry and provides secure access to sensitive data
    through on-demand decryption and automatic TOTP generation. Passwords and OTP
    secrets can be stored either encrypted (in-memory) or plaintext depending on
    the encryption manager configuration.
    
    Attributes:
        title: The display name of the password entry.
        username: The associated username or login identifier.
        url: The website or service URL associated with the entry.
        password: The password value (encrypted as bytes or plaintext str).
        otp: The OTP secret (encrypted as bytes or plaintext str).
    """

    def __init__(
        self,
        entry: KeePassEntryLike,
        encryption_manager: EncryptionManager | None = None,
    ) -> None:
        """Initialize a KeePass entry from a pykeepass Entry object.
        
        Extracts basic entry metadata and optionally encrypts sensitive data
        (password and OTP secret) using the provided encryption manager.
        
        Args:
            entry: A pykeepass Entry object or compatible protocol object containing
                   the entry data to be wrapped.
            encryption_manager: An optional EncryptionManager instance for encrypting
                               sensitive fields. If None, data is stored plaintext.
        
        Returns:
            None
        """
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
        """Retrieve the plaintext password, decrypting if necessary.
        
        If the password is encrypted (stored as bytes), it is decrypted on-demand
        using the encryption manager. Otherwise, the plaintext password is returned
        as-is.
        
        Returns:
            The plaintext password string, or None if no password is stored.
        
        Raises:
            RuntimeError: If password is encrypted but no encryption manager is available.
        """
        if not self.password:
            return None

        if isinstance(self.password, bytes):
            if not self._encryption_manager:
                raise RuntimeError(
                    "Cannot decrypt password: encryption manager not initialized"
                )
            return self._encryption_manager.decrypt(self.password)
        return self.password

    def get_totp(self) -> str | None:
        """Generate a time-based one-time password (TOTP) code.
        
        Extracts the TOTP secret from the OTP field (decrypting if necessary),
        then generates the current 6-digit TOTP code. Commonly used for
        two-factor authentication.
        
        Returns:
            A 6-digit TOTP code as a string, or None if no OTP secret is stored.
        
        Raises:
            RuntimeError: If OTP is encrypted but no encryption manager is available.
        """
        if not self.otp:
            return None

        if isinstance(self.otp, bytes):
            if not self._encryption_manager:
                raise RuntimeError(
                    "Cannot decrypt password: encryption manager not initialized"
                )
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
        """Execute a bash command with automatic password input.
        
        Runs a subprocess command and automatically pipes the password to stdin.
        Useful for automating commands that require password authentication
        (e.g., SSH, sudo, or encrypted archives). The password can be provided
        multiple times if needed for commands with repeated prompts.
        
        Args:
            command: List of command tokens to execute (passed directly to Popen).
            count: Number of times to repeat the password input (default: 1).
                   Useful for commands with multiple password prompts.
        
        Returns:
            A tuple of (stdout, stderr) containing the command's output streams
            as strings.
        
        Raises:
            ValueError: If no password is available for the entry.
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
