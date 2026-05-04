import gc
import getpass

from pykeepass import PyKeePass

from keepass_wrapper.config import Config
from keepass_wrapper.encryption import EncryptionManager
from keepass_wrapper.entry import KeePassEntry


class KeePass:
    """Manager for KeePass database with encryption."""

    def __init__(
        self,
        database_path: str | None = None,
        filter_title: str | None = None,
        enable_encryption: bool = True,
    ) -> None:
        """Initialize KeePass manager.

        Args:
            database_path: Path to the .kdbx file (uses config default if None)
            filter_title: Optional title filter for entries
            enable_encryption: Whether to encrypt passwords in memory (default: True)

        Raises:
            ValueError: If unable to authenticate to KeePass database
        """
        config = Config.from_kwargs(
            database_path=database_path,
            filter_title=filter_title,
        )

        self.config = config
        self.encryption_manager = EncryptionManager() if enable_encryption else None

        # Load KeePass database with password prompt
        self.kp = self._load_database(config.database_path)

        # Get entries, optionally filtered by title
        entries = self.kp.entries

        # Wrap entries with encryption
        self.entries: list[KeePassEntry] = self._wrap_entries(entries)

        # Apply title filter after wrapping
        if config.filter_title:
            self.entries = self.find_entries(config.filter_title)

        # Clean up PyKeePass object after loading entries
        self.kp = None
        gc.collect()

    def _load_database(self, database_path: str) -> PyKeePass:
        """Load KeePass database with password authentication.

        Args:
            database_path: Path to the .kdbx file

        Returns:
            Authenticated PyKeePass instance

        Raises:
            ValueError: If authentication fails
        """
        max_attempts = 3
        attempts = 0

        while attempts < max_attempts:
            try:
                password = getpass.getpass("Enter KeePass password: ")
                return PyKeePass(database_path, password=password)
            except Exception as e:
                attempts += 1
                print(f"Authentication failed: {e}")
                if attempts < max_attempts:
                    print(f"Try again ({max_attempts - attempts} attempts remaining).")
                else:
                    raise ValueError(
                        "Failed to authenticate to KeePass database after "
                        f"{max_attempts} attempts"
                    )

        # This should never be reached
        raise ValueError("Unknown error loading KeePass database")

    def _wrap_entries(self, entries: list[object]) -> list[KeePassEntry]:
        """Wrap KeePass entries with optional encryption.

        Args:
            entries: List of pykeepass Entry objects

        Returns:
            List of KeePassEntry objects
        """
        wrapped: list[KeePassEntry] = []

        for entry in entries:
            wrapped_entry = KeePassEntry(
                entry,
                encryption_manager=self.encryption_manager,
            )
            wrapped.append(wrapped_entry)

        return wrapped
    def find_entries(
        self,
        title: str | list[str],
        exact: bool = False,
        startswith: bool = False,
    ) -> list[KeePassEntry]:
        """Find entries by title."""
        if not isinstance(title, list):
            titles_to_search = [title]
        else:
            titles_to_search = title

        matching_entries = []

        # Search through already-loaded and wrapped entries
        for entry in self.entries:
            for search_title in titles_to_search:
                entry_title: str = entry.title.lower()
                search_title_lower = search_title.lower()

                if exact and search_title_lower == entry_title:
                    matching_entries.append(entry)
                elif startswith and entry_title.startswith(search_title_lower):
                    matching_entries.append(entry)
                elif not exact and search_title_lower in entry_title:
                    matching_entries.append(entry)

        return matching_entries
