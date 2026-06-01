import pytest

from keepass_wrapper.otp import extract_totp_secret, generate_totp


def test_extract_totp_secret_plain() -> None:
    """Test extracting a plain TOTP secret."""
    secret = "JBSWY3DPEBLW64TMMQ======"
    result = extract_totp_secret(secret)
    assert result == secret


def test_extract_totp_secret_from_url_format() -> None:
    """Test extracting TOTP secret from URL parameter format."""
    otp_url = "secret=JBSWY3DPEBLW64TMMQ======&issuer=Example"
    result = extract_totp_secret(otp_url)
    assert result == "JBSWY3DPEBLW64TMMQ======"


def test_extract_totp_secret_with_ampersand() -> None:
    """Test extracting TOTP secret from URL with multiple parameters."""
    otp_url = "secret=ABC123&period=30&digits=6"
    result = extract_totp_secret(otp_url)
    assert result == "ABC123"


def test_extract_totp_secret_empty_string() -> None:
    """Test that empty OTP string raises ValueError."""
    with pytest.raises(ValueError, match="empty"):
        extract_totp_secret("")


def test_extract_totp_secret_full_otpauth_url() -> None:
    """Test extraction from a full otpauth:// URL."""
    otp_url = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEBLW64TMMQ======&issuer=Example"
    result = extract_totp_secret(otp_url)
    assert result == "JBSWY3DPEBLW64TMMQ======"


def test_extract_totp_secret_malformed_url() -> None:
    """Test that URL with missing secret raises ValueError."""
    with pytest.raises(ValueError, match="Malformed"):
        extract_totp_secret("secret=&issuer=Example")


def test_generate_totp_returns_string() -> None:
    """Test that generate_totp returns a 6-digit string."""
    # Using a test secret
    secret = "JBSWY3DPEBLW64TMMQ======"
    result = generate_totp(secret)

    assert isinstance(result, str)
    assert len(result) == 6
    assert result.isdigit()
