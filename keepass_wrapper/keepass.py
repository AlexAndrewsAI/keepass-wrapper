import gc
import getpass

from pykeepass import PyKeePass

from keepass_wrapper.config import Config
from keepass_wrapper.encryption import EncryptionManager
from keepass_wrapper.entry import KeePassEntry, KeePassEntryLike


class KeePass:
    """Manager for KeePass database with encryption."""

    config: Config
    encryption_manager: EncryptionManager | None
    entries: list[KeePassEntry]

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
        kp = self._load_database(config.database_path)

        # Wrap entries with optional encryption
        self.entries = self._wrap_entries(kp.entries)

        # Apply title filter after wrapping
        if config.filter_title:
            self.entries = self.find_entries(config.filter_title)

        # Clean up references
        del kp
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

        for attempt in range(max_attempts):
            try:
                password = getpass.getpass("Enter KeePass password: ")
                return PyKeePass(database_path, password=password)
            except Exception as e:
                print(f"Authentication failed: {e}")
                if attempt < max_attempts - 1:
                    print(f"Try again ({max_attempts - attempt - 1} attempts remaining).")
                else:
                    raise ValueError(
                        f"Failed to authenticate to KeePass database after {max_attempts} attempts"
                    ) from e

    def _wrap_entries(self, entries: list[KeePassEntryLike]) -> list[KeePassEntry]:
        """Wrap KeePass entries with optional encryption.

        Args:
            entries: List of pykeepass Entry objects

        Returns:
            List of KeePassEntry objects
        """
        return [
            KeePassEntry(entry, encryption_manager=self.encryption_manager)
            for entry in entries
        ]

    def find_entries(
        self,
        title: str | list[str],
        exact: bool = False,
        startswith: bool = False,
    ) -> list[KeePassEntry]:
        """Find entries by title."""
        titles_to_search = title if isinstance(title, list) else [title]
        matching_entries: list[KeePassEntry] = []

        for entry in self.entries:
            entry_title_lower = entry.title.lower()
            
            for search_title in titles_to_search:
                search_title_lower = search_title.lower()

                if (
                    (exact and search_title_lower == entry_title_lower)
                    or (startswith and entry_title_lower.startswith(search_title_lower))
                    or (not exact and not startswith and search_title_lower in entry_title_lower)
                ):
                    matching_entries.append(entry)
                    break  # Don't add same entry multiple times

        return matching_entries
