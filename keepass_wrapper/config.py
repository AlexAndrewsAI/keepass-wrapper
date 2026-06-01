"""Configuration module.

Provides Pydantic-based configuration management for KeePass wrapper.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

current_file = Path(__file__).resolve()

# Convert Path to string
DEFAULT_TEST_DATABASE: str = str(current_file.parent.parent / "tests" / "test.kdbx")


class Config(BaseSettings):
    """Configuration for KeePass wrapper.

    Values can be set via environment variables prefixed with KEEPASS_
    (e.g., KEEPASS_DATABASE_PATH).
    """

    database_path: str = Field(
        default=DEFAULT_TEST_DATABASE,
        description="Path to the KeePass database file",
    )
    filter_title: str | None = Field(
        default=None,
        description="Optional title filter for entries",
    )

    model_config = SettingsConfigDict(
        env_prefix="KEEPASS_",
        title="KeePass Wrapper Config",
    )
