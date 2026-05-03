import pytest

from keepass_wrapper.keepass import KeePass


@pytest.fixture(scope="session")
def keepass_instance() -> KeePass:
    """Fixture that provides a single KeePass instance for all tests."""
    return KeePass(encrypt_entries=False)


@pytest.fixture(scope="session")
def keepass_encrypted() -> KeePass:
    """Fixture that provides a single encrypted KeePass instance."""
    return KeePass(encrypt_entries=True)


def test_keepass_loads_entries_from_database(keepass_instance: KeePass) -> None:
    """Test that KeePass loads entries from the database."""
    assert len(keepass_instance.entries) >= 8
    titles = [entry.title for entry in keepass_instance.entries]
    assert "Gmail" in titles


def test_keepass_find_single_entry(keepass_instance: KeePass) -> None:
    """Test retrieving a single entry and accessing its fields."""
    results = keepass_instance.find_entries("Gmail")

    assert len(results) == 1
    assert results[0].username == "john.doe@gmail.com"
    assert results[0].password == "p@ssw0rd123"
    assert results[0].url == "https://gmail.com"


def test_keepass_find_entry_no_results(keepass_instance: KeePass) -> None:
    """Test finding entry that doesn't exist."""
    results = keepass_instance.find_entries("NonExistent")

    assert len(results) == 0


def test_keepass_find_multiple_entries_same_title(keepass_instance: KeePass) -> None:
    """Test finding when multiple entries share the same title."""
    results = keepass_instance.find_entries("Duplicate Title")

    assert len(results) == 2
    usernames = [entry.username for entry in results]
    assert "user1" in usernames
    assert "user2" in usernames


def test_keepass_find_entry_with_special_characters(keepass_instance: KeePass) -> None:
    """Test entries containing special characters."""
    results = keepass_instance.find_entries("Special!Entry")

    assert len(results) == 1
    assert results[0].username == "user#special"
    assert results[0].password == "~!@#$%^&*()"


def test_keepass_find_entry_missing_optional_fields(keepass_instance: KeePass) -> None:
    """Test entries with missing optional fields."""
    results = keepass_instance.find_entries("Test Account")

    assert len(results) == 1
    assert results[0].password == "test123"
    assert results[0].url is None


def test_keepass_find_entry_with_port_in_url(keepass_instance: KeePass) -> None:
    """Test entries with non-standard ports in URL."""
    results = keepass_instance.find_entries("Local Database")

    assert len(results) == 1
    assert results[0].url == "localhost:5432"


def test_keepass_partial_title_match(keepass_instance: KeePass) -> None:
    """Test finding entries with partial title match."""
    results = keepass_instance.find_entries("AWS")

    assert len(results) == 1
    assert "Production" in results[0].title


def test_keepass_case_insensitive_search(keepass_instance: KeePass) -> None:
    """Test that searches are case-insensitive."""
    results_lower = keepass_instance.find_entries("gmail")
    results_upper = keepass_instance.find_entries("GMAIL")

    assert len(results_lower) == 1
    assert len(results_upper) == 1
    assert results_lower[0].title == results_upper[0].title


def test_keepass_exact_match_filtering(keepass_instance: KeePass) -> None:
    """Test exact title matching."""
    results = keepass_instance.find_entries("Duplicate Title", exact=True)

    assert len(results) == 2


def test_keepass_startswith_match(keepass_instance: KeePass) -> None:
    """Test startswith filtering."""
    results = keepass_instance.find_entries("Dup", startswith=True)

    assert len(results) == 2
    assert all("Duplicate" in entry.title for entry in results)


def test_keepass_find_multiple_titles(keepass_instance: KeePass) -> None:
    """Test finding entries by multiple title filters."""
    results = keepass_instance.find_entries(["Gmail", "GitHub"])

    assert len(results) == 2
    titles = [entry.title for entry in results]
    assert "Gmail" in titles
    assert "GitHub" in titles


def test_keepass_with_encryption_passwords_are_encrypted(
    keepass_encrypted: KeePass,
) -> None:
    """Test that passwords are encrypted in memory when encryption is enabled."""
    results = keepass_encrypted.find_entries("Gmail")

    # Encrypted password should not be in plaintext
    assert results[0].password != b"p@ssw0rd123"


def test_keepass_encryption_manager_initialized(keepass_encrypted: KeePass) -> None:
    """Test that encryption manager is initialized when enabled."""
    assert keepass_encrypted.encryption_manager is not None
    assert keepass_encrypted.kp is None


def test_keepass_all_entries_have_title(keepass_instance: KeePass) -> None:
    """Test that all loaded entries have a title field."""
    for entry in keepass_instance.entries:
        assert entry.title is not None
        assert len(entry.title) > 0


def test_keepass_entry_username_field(keepass_instance: KeePass) -> None:
    """Test that entries have username field populated."""
    results = keepass_instance.find_entries("Gmail")

    assert results[0].username is not None
