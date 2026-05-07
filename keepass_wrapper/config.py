from pathlib import Path

from pydantic import BaseModel, Field

current_file = Path(__file__).resolve()

# Convert Path to string
DEFAULT_TEST_DATABASE: str = str(current_file.parent.parent / "tests" / "test.kdbx")


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
