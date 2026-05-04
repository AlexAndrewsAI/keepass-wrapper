from unittest.mock import Mock, patch

from keepass_wrapper.keepass import KeePass


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_initialization_default_encryption(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test KeePass initialization with default encryption enabled."""
    mock_getpass.return_value = "password"

    # Mock PyKeePass instance
    mock_kp = Mock()
    mock_entry = Mock()
    mock_entry.title = "Test Entry"
    mock_entry.username = "testuser"
    mock_entry.password = None
    mock_entry.otp = None
    mock_entry.url = None

    mock_kp.entries = [mock_entry]
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass()

    assert len(keepass.entries) == 1
    assert keepass.entries[0].title == "Test Entry"
    # With default encryption enabled, kp should be None
    assert keepass.kp is None
    assert keepass.encryption_manager is not None


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_authentication_failure_then_success(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test KeePass retries on authentication failure."""
    # First call fails, second succeeds
    mock_kp_success = Mock()
    mock_kp_success.entries = []
    mock_pykeepass.side_effect = [Exception("Wrong password"), mock_kp_success]

    mock_getpass.return_value = "password"

    keepass = KeePass()

    assert keepass.kp is None  # kp is cleared after encryption


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_authentication_max_retries(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test KeePass raises error after max authentication attempts."""
    mock_pykeepass.side_effect = Exception("Wrong password")
    mock_getpass.return_value = "password"

    try:
        KeePass()
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Failed to authenticate" in str(e)


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_find_entries_by_title(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test finding entries by title."""
    mock_getpass.return_value = "password"

    mock_kp = Mock()
    mock_entry1 = Mock()
    mock_entry1.title = "Gmail"
    mock_entry1.username = "user"
    mock_entry1.password = None
    mock_entry1.otp = None
    mock_entry1.url = None

    mock_entry2 = Mock()
    mock_entry2.title = "GitHub"
    mock_entry2.username = "developer"
    mock_entry2.password = None
    mock_entry2.otp = None
    mock_entry2.url = None

    mock_kp.entries = [mock_entry1, mock_entry2]
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

    mock_kp = Mock()
    mock_entry1 = Mock()
    mock_entry1.title = "Gmail Account"
    mock_entry1.username = "user"
    mock_entry1.password = None
    mock_entry1.otp = None
    mock_entry1.url = None

    mock_entry2 = Mock()
    mock_entry2.title = "Gmail Backup"
    mock_entry2.username = "backup"
    mock_entry2.password = None
    mock_entry2.otp = None
    mock_entry2.url = None

    mock_kp.entries = [mock_entry1, mock_entry2]
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

    mock_kp = Mock()
    mock_entry1 = Mock()
    mock_entry1.title = "Gmail"
    mock_entry1.username = "user"
    mock_entry1.password = None
    mock_entry1.otp = None
    mock_entry1.url = None

    mock_entry2 = Mock()
    mock_entry2.title = "Gmail Account"
    mock_entry2.username = "account"
    mock_entry2.password = None
    mock_entry2.otp = None
    mock_entry2.url = None

    mock_kp.entries = [mock_entry1, mock_entry2]
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

    mock_kp = Mock()
    mock_entry1 = Mock()
    mock_entry1.title = "Gmail Personal"
    mock_entry1.username = "personal"
    mock_entry1.password = None
    mock_entry1.otp = None
    mock_entry1.url = None

    mock_entry2 = Mock()
    mock_entry2.title = "Email"
    mock_entry2.username = "email"
    mock_entry2.password = None
    mock_entry2.otp = None
    mock_entry2.url = None

    mock_kp.entries = [mock_entry1, mock_entry2]
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

    mock_kp = Mock()
    mock_entry1 = Mock()
    mock_entry1.title = "Gmail"
    mock_entry1.username = "user1"
    mock_entry1.password = None
    mock_entry1.otp = None
    mock_entry1.url = None

    mock_entry2 = Mock()
    mock_entry2.title = "GitHub"
    mock_entry2.username = "user2"
    mock_entry2.password = None
    mock_entry2.otp = None
    mock_entry2.url = None

    mock_entry3 = Mock()
    mock_entry3.title = "Twitter"
    mock_entry3.username = "user3"
    mock_entry3.password = None
    mock_entry3.otp = None
    mock_entry3.url = None

    mock_kp.entries = [mock_entry1, mock_entry2, mock_entry3]
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass()

    results = keepass.find_entries(["Gmail", "GitHub"])
    assert len(results) == 2
    titles = [entry.title for entry in results]
    assert "Gmail" in titles
    assert "GitHub" in titles


@patch("keepass_wrapper.keepass.getpass.getpass")
@patch("keepass_wrapper.keepass.PyKeePass")
def test_keepass_with_title_filter_in_config(
    mock_pykeepass: Mock, mock_getpass: Mock
) -> None:
    """Test KeePass initialization with title filter in config."""
    mock_getpass.return_value = "password"

    mock_kp = Mock()
    mock_entry1 = Mock()
    mock_entry1.title = "Gmail"
    mock_entry1.username = "user"
    mock_entry1.password = None
    mock_entry1.otp = None
    mock_entry1.url = None

    mock_entry2 = Mock()
    mock_entry2.title = "GitHub"
    mock_entry2.username = "developer"
    mock_entry2.password = None
    mock_entry2.otp = None
    mock_entry2.url = None

    mock_kp.entries = [mock_entry1, mock_entry2]
    mock_pykeepass.return_value = mock_kp

    keepass = KeePass(filter_title="Gmail")

    assert len(keepass.entries) == 1
    assert keepass.entries[0].title == "Gmail"

