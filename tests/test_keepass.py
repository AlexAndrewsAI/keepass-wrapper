from unittest.mock import Mock, patch

import pytest

from keepass_wrapper.keepass import KeePass


def create_mock_entry(
    title: str,
    username: str = "user",
    password: str | None = None,
    otp: str | None = None,
    url: str | None = None,
) -> Mock:
    """Factory function to create mock KeePass entries."""
    mock_entry = Mock()
    mock_entry.title = title
    mock_entry.username = username
    mock_entry.password = password
    mock_entry.otp = otp
    mock_entry.url = url
    return mock_entry


def create_mock_pykeepass(entries: list[Mock]) -> Mock:
    """Factory function to create mock PyKeePass instance."""
    mock_kp = Mock()
    mock_kp.entries = entries
    return mock_kp


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_initialization_default_encryption(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test KeePass initialization with default encryption enabled."""
    mock_getpass.return_value = "password"
    mock_entry = create_mock_entry("Test Entry")
    mock_kp = create_mock_pykeepass([mock_entry])
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass()

    assert len(keepass.entries) == 1
    assert keepass.entries[0].title == "Test Entry"
    assert keepass.encryption_manager is not None


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_authentication_failure_then_success(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test KeePass retries on authentication failure."""
    mock_kp = create_mock_pykeepass([])
    mock_pykeepass.side_effect = [Exception("Wrong password"), mock_kp]
    mock_getpass.return_value = "password"

    keepass = KeePass()

    assert keepass.entries == []


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_authentication_max_retries(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test KeePass raises error after max authentication attempts."""
    mock_pykeepass.side_effect = Exception("Wrong password")
    mock_getpass.return_value = "password"

    with pytest.raises(ValueError, match="Failed to authenticate"):
        KeePass()


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_find_entries_by_title(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test finding entries by title."""
    mock_getpass.return_value = "password"
    entries = [
        create_mock_entry("Gmail", username="user"),
        create_mock_entry("GitHub", username="developer"),
    ]
    mock_kp = create_mock_pykeepass(entries)
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass()
    results = keepass.find_entries("Gmail")

    assert len(results) == 1
    assert results[0].title == "Gmail"


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_find_entries_partial_match(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test finding entries with partial title match."""
    mock_getpass.return_value = "password"
    entries = [
        create_mock_entry("Gmail Account"),
        create_mock_entry("Gmail Backup"),
    ]
    mock_kp = create_mock_pykeepass(entries)
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass()
    results = keepass.find_entries("Gmail")

    assert len(results) == 2


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_find_entries_exact_match(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test finding entries with exact title match."""
    mock_getpass.return_value = "password"
    entries = [
        create_mock_entry("Gmail"),
        create_mock_entry("Gmail Account"),
    ]
    mock_kp = create_mock_pykeepass(entries)
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass()
    results = keepass.find_entries("Gmail", exact=True)

    assert len(results) == 1
    assert results[0].title == "Gmail"


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_find_entries_startswith(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test finding entries with startswith match."""
    mock_getpass.return_value = "password"
    entries = [
        create_mock_entry("Gmail Personal"),
        create_mock_entry("Email"),
    ]
    mock_kp = create_mock_pykeepass(entries)
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass()
    results = keepass.find_entries("Gmail", startswith=True)

    assert len(results) == 1
    assert results[0].title == "Gmail Personal"


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_find_entries_multiple_titles(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test finding entries by multiple title filters."""
    mock_getpass.return_value = "password"
    entries = [
        create_mock_entry("Gmail"),
        create_mock_entry("GitHub"),
        create_mock_entry("Twitter"),
    ]
    mock_kp = create_mock_pykeepass(entries)
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass()
    results = keepass.find_entries(["Gmail", "GitHub"])

    assert len(results) == 2
    titles = {entry.title for entry in results}
    assert titles == {"Gmail", "GitHub"}


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_with_title_filter_in_config(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test KeePass initialization with title filter in config."""
    mock_getpass.return_value = "password"
    entries = [
        create_mock_entry("Gmail"),
        create_mock_entry("GitHub"),
    ]
    mock_kp = create_mock_pykeepass(entries)
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass(filter_title="Gmail")

    assert len(keepass.entries) == 1
    assert keepass.entries[0].title == "Gmail"
