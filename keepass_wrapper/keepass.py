"""KeePass database manager with encryption and TOTP support.

This module provides a high-level interface for managing KeePass password databases,
with in-memory encryption for passwords and OTP secrets. It handles
database authentication, entry wrapping, and entry filtering.
"""

import gc
import getpass
import logging
from typing import Any

from pykeepass import PyKeePass
from pykeepass.exceptions import BinaryError, CredentialsError  # type: ignore

from keepass_wrapper.config import DEFAULT_TEST_DATABASE, Config
from keepass_wrapper.encryption import EncryptionManager
from keepass_wrapper.entry import KeePassEntry, KeePassEntryLike


class KeePass:
    """Manager for KeePass database with encryption and TOTP support.

    This class provides a secure interface to a KeePass (.kdbx) database. It handles
    authentication, wraps entries with in-memory encryption, and provides
    filtering and search capabilities. After loading, the underlying PyKeePass
    instance is explicitly cleaned up to minimize sensitive data in memory.

    Attributes:
        config: Configuration object containing database path and filter settings.
        encryption_manager: EncryptionManager instance for encrypting passwords and
                           OTP secrets.
        entries: List of KeePassEntry objects loaded from the database.

    """

    config: Config
    encryption_manager: EncryptionManager
    entries: list[KeePassEntry]

    def __init__(
        self,
        database_path: str | None = None,
        filter_title: str | None = None,
        encryption_manager: EncryptionManager | None = None,
    ) -> None:
        """Initialize the KeePass manager and load the database.

        Prompts the user for a password, authenticates to the KeePass database,
        wraps all entries with encryption, and applies any specified
        title filters. The underlying PyKeePass object is cleaned up after loading
        to minimize sensitive data in memory.

        Args:
            database_path: Path to the .kdbx database file. If None, uses the default
                          path from Config.
            filter_title: Optional title substring to filter entries after loading.
                         Only entries containing this string (case-insensitive) will
                         be retained.
            encryption_manager: Optional EncryptionManager instance to use. If None,
                               a new one is created.

        Returns:
            None

        Raises:
            ValueError: If unable to authenticate to the KeePass database after
                       the maximum number of attempts (3).

        """
        config = Config(
            database_path=database_path or DEFAULT_TEST_DATABASE,
            filter_title=filter_title,
        )

        self.config = config
        self.encryption_manager = encryption_manager or EncryptionManager()

        # Load KeePass database with password prompt
        kp = self._load_database(config.database_path)

        try:
            # Wrap entries with encryption
            self.entries = self._wrap_entries(kp.entries)

            # Apply title filter after wrapping
            if config.filter_title:
                self.entries = self._apply_filter(config.filter_title)
        finally:
            # Clean up references
            del kp
            gc.collect()

    def __enter__(self) -> "KeePass":
        """Context manager entry point."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Context manager exit point, ensures sensitive data is cleared."""
        self.close()

    def _load_database(self, database_path: str) -> PyKeePass:
        """Load and authenticate to the KeePass database.

        Prompts the user for a password and opens KeePass database
        at the specified path. Supports multiple authentication attempts with
        helpful feedback on failure.

        Args:
            database_path: Path to the .kdbx database file.

        Returns:
            An authenticated PyKeePass instance.

        Raises:
            ValueError: If authentication fails after 3 attempts.

        """
        max_attempts = 3

        for attempt in range(max_attempts):
            try:
                password = getpass.getpass("Enter KeePass password: ")
                return PyKeePass(database_path, password=password)
            except (CredentialsError, BinaryError) as e:
                logging.warning("Authentication failed: %s", e)
                if attempt < max_attempts - 1:
                    logging.warning(
                        "Try again (%d attempts remaining).",
                        max_attempts - attempt - 1,
                    )
                else:
                    raise ValueError(
                        f"Failed to authenticate after {max_attempts} attempts"
                    ) from e

    def _wrap_entries(self, entries: list[KeePassEntryLike]) -> list[KeePassEntry]:
        """Wrap pykeepass Entry objects with KeePassEntry wrapper.

        Converts raw pykeepass Entry objects into KeePassEntry instances with
        encryption. This allows for consistent access patterns and
        secure password handling across the application.

        Args:
            entries: List of pykeepass Entry objects from the database.

        Returns:
            List of KeePassEntry wrapper objects with encryption applied.

        """
        return [
            KeePassEntry(entry, encryption_manager=self.encryption_manager)
            for entry in entries
        ]

    def _apply_filter(self, filter_title: str) -> list[KeePassEntry]:
        """Apply title filter to entries during initialization.

        This is a private method used during initialization to filter entries
        by title. It delegates to the public find_entries method but keeps
        initialization logic separate from the public search API.

        Args:
            filter_title: Title substring to filter entries by (case-insensitive).

        Returns:
            Filtered list of KeePassEntry objects.

        """
        return self.find_entries(filter_title)

    def find_entries(
        self,
        title: str | list[str],
        exact: bool = False,
        startswith: bool = False,
    ) -> list[KeePassEntry]:
        """Find entries by title using flexible matching strategies.

        Searches the loaded entries for titles matching the given criteria. Supports
        partial substring matching (default), exact matching, and prefix matching.
        All comparisons are case-insensitive. Multiple search terms can be provided,
        returning all entries matching any of the titles.

        Args:
            title: A single title string or list of title strings to search for.
            exact: If True, match only entries with exactly matching titles
                  (case-insensitive). Default: False.
            startswith: If True, match entries whose titles start with the search term
                       (case-insensitive). Default: False.

        Returns:
            List of KeePassEntry objects matching the search criteria. Returns an
            empty list if no matches are found. Each matching entry appears only once
            even if it matches multiple search terms.

        Note:
            If both exact and startswith are False (the default), matching uses
            substring containment (the search term can appear anywhere in the title).

        """
        titles_to_search = title if isinstance(title, list) else [title]
        matching_entries: list[KeePassEntry] = []

        for entry in self.entries:
            entry_title_lower = entry.title.lower()

            for search_title in titles_to_search:
                search_title_lower = search_title.lower()

                if (
                    (exact and search_title_lower == entry_title_lower)
                    or (startswith and entry_title_lower.startswith(search_title_lower))
                    or (
                        not exact
                        and not startswith
                        and search_title_lower in entry_title_lower
                    )
                ):
                    matching_entries.append(entry)
                    break  # Don't add same entry multiple times

        return matching_entries

    def close(self) -> None:
        """Close the KeePass manager and clear sensitive data from memory."""
        self.entries = []
        self.encryption_manager.clear()
        gc.collect()
