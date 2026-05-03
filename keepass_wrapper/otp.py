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
    """
    if "secret=" in otp_string:
        secret = otp_string.split("secret=")[1]
        if "&" in secret:
            secret = secret.split("&")[0]
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
