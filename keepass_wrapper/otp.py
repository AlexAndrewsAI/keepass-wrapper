import pyotp


def extract_totp_secret(otp_string: str) -> str:
    """Extract the TOTP secret from a KeePass OTP string.

    Handles formats like:
    - Plain secret: "JBSWY3DPEBLW64TMMQ======"
    - URL format: "secret=JBSWY3DPEBLW64TMMQ======&issuer=Example"

    Args:
        otp_string: The OTP string from KeePass

    Returns:
        The extracted TOTP secret

    Raises:
        ValueError: If the OTP string is malformed or missing a secret
    """
    if not otp_string:
        raise ValueError("OTP string is empty")

    if "secret=" in otp_string:
        parts = otp_string.split("secret=")
        if len(parts) < 2:
            raise ValueError("Malformed OTP string: secret parameter missing value")
        secret = parts[1]
        if "&" in secret:
            secret = secret.split("&")[0]
        if not secret:
            raise ValueError("Malformed OTP string: secret parameter is empty")
        return secret
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
