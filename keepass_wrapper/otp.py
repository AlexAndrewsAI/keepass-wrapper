import pyotp
from urllib.parse import parse_qs, urlparse


def extract_totp_secret(otp_string: str) -> str:
    """Extract the TOTP secret from a KeePass OTP string.

    Handles formats like:
    - Plain secret: "JBSWY3DPEBLW64TMMQ======"
    - URL format: "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEBLW64TMMQ======&issuer=Example"
    - Partial URL: "secret=JBSWY3DPEBLW64TMMQ======&issuer=Example"

    Args:
        otp_string: The OTP string from KeePass

    Returns:
        The extracted TOTP secret

    Raises:
        ValueError: If the OTP string is malformed or missing a secret
    """
    if not otp_string:
        raise ValueError("OTP string is empty")

    # If it's a full URL or looks like one
    if "secret=" in otp_string:
        # Handle both full otpauth:// URLs and partial secret=... strings
        query = otp_string
        if "://" in otp_string:
            parsed = urlparse(otp_string)
            query = parsed.query

        params = parse_qs(query)
        secrets = params.get("secret")

        if not secrets or not secrets[0]:
            raise ValueError("Malformed OTP string: secret parameter missing or empty")

        return secrets[0]

    return otp_string


def generate_totp(secret: str) -> str:
    """Generate current TOTP code from a secret.

    Args:
        secret: The TOTP secret key

    Returns:
        The current 6-digit TOTP code
    """
    totp = pyotp.TOTP(secret)
    return totp.now()
