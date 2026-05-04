from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

current_file = Path(__file__).resolve()
print(current_file)            # full path to the file
print(current_file.parent)     # directory containing the file

# Convert Path to string
DEFAULT_TEST_DATABASE = str(current_file.parent.parent / "tests" / "test.kdbx")

class Config(BaseModel):
    """Configuration for KeePass wrapper."""

    database_path: str = Field(
        default=DEFAULT_TEST_DATABASE,
        description="Path to the KeePass database file",
    )
    filter_title: str | None = Field(
        default=None,
        description="Optional title filter for entries",
    )

    model_config = {"title": "KeePass Wrapper Config"}

    @classmethod
    def from_kwargs(
        cls,
        database_path: str | None = None,
        filter_title: str | None = None,
    ) -> "Config":
        """Create a Config instance with optional customizations."""
        kwargs: dict[str, Any] = {}  # Use Any to avoid type conflicts
        if database_path is not None:
            kwargs["database_path"] = database_path
        if filter_title is not None:
            kwargs["filter_title"] = filter_title
        return cls(**kwargs)
