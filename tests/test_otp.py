from keepass_wrapper.otp import extract_totp_secret, generate_totp


def test_extract_totp_secret_plain() -> None:
    secret = "JBSWY3DPEBLW64TMMQ======"
    result = extract_totp_secret(secret)
    assert result == secret


def test_extract_totp_secret_from_url_format() -> None:
    otp_url = "secret=JBSWY3DPEBLW64TMMQ======&issuer=Example"
    result = extract_totp_secret(otp_url)
    assert result == "JBSWY3DPEBLW64TMMQ======"


def test_extract_totp_secret_with_ampersand() -> None:
    otp_url = "secret=ABC123&period=30&digits=6"
    result = extract_totp_secret(otp_url)
    assert result == "ABC123"


def test_extract_totp_secret_empty_string() -> None:
    """Test that empty OTP string raises ValueError."""
    try:
        extract_totp_secret("")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "empty" in str(e)


def test_extract_totp_secret_full_otpauth_url() -> None:
    """Test extraction from a full otpauth:// URL."""
    otp_url = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEBLW64TMMQ======&issuer=Example"
    result = extract_totp_secret(otp_url)
    assert result == "JBSWY3DPEBLW64TMMQ======"


def test_extract_totp_secret_malformed_url() -> None:
    """Test that URL with missing secret raises ValueError."""
    otp_url = "secret=&issuer=Example"
    try:
        extract_totp_secret(otp_url)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Malformed" in str(e)


def test_generate_totp_returns_string() -> None:
    # Using a test secret
    secret = "JBSWY3DPEBLW64TMMQ======"
    result = generate_totp(secret)

    assert isinstance(result, str)
    assert len(result) == 6
    assert result.isdigit()
