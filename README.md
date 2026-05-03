# pykeepass-wrapper

A secure KeePass password manager wrapper with encryption and TOTP support using **uv**, **pydantic**, and **pytest**.

## Overview

This package provides a Python wrapper around **pykeepass** for managing KeePass databases with additional security features:

- **Encryption**: Optional in-memory encryption of sensitive data using Fernet
- **TOTP Support**: Automatic generation of time-based one-time passwords
- **Type Safety**: Full type hints and static type checking with **mypy**
- **Pydantic Config**: Configuration validation and management
- **Subprocess Integration**: Execute bash commands with automatic password input
- **Comprehensive Testing**: Full test suite with pytest

## Installation

### Prerequisites

- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) package manager

### Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/AlexAndrewsAI/pykeepass-wrapper.git
cd pykeepass-wrapper
uv sync
```

## Usage

### Basic Example

```python
from keepass_wrapper import KeePass, Config

# Initialize with default configuration
keepass = KeePass()

# Or with custom configuration
config = Config(
    database_path="/path/to/passwords.kdbx",
    encrypt_entries=True
)
keepass = KeePass(config)

# Access entries
for entry in keepass.entries:
    print(f"Title: {entry.title}")
    print(f"Username: {entry.username}")
```

### Configuration

The `Config` class uses **pydantic** for validation:

```python
from keepass_wrapper.config import Config

# Create with defaults
config = Config()

# Create with custom settings
config = Config(
    database_path="/home/user/.config/passwords.kdbx",
    encrypt_entries=True,
    filter_title="Work"
)
```

### Finding Entries

```python
# Find by partial match
results = keepass.find_entries("Gmail")

# Find by exact match
results = keepass.find_entries("Gmail Account", exact=True)

# Find by prefix
results = keepass.find_entries("Gmail", startswith=True)

# Find by multiple titles
results = keepass.find_entries(["Gmail", "GitHub"])
```

### Using Encryption

```python
from keepass_wrapper import KeePass, Config

# Enable encryption
config = Config(encrypt_entries=True)
keepass = KeePass(config)

# Encryption happens automatically on initialization
for entry in keepass.entries:
    password = entry.get_password()  # Decrypts on demand
    totp = entry.get_totp()  # Generates TOTP from encrypted secret
```

### TOTP Generation

```python
# Get current TOTP code
entry = keepass.entries[0]
code = entry.get_totp()  # Returns 6-digit code as string
print(f"Current code: {code}")
```

### Bash Integration

```python
# Execute command with password input
entry = keepass.entries[0]
stdout, stderr = entry.bash_with_password(["ssh", "user@host"])

# Pass password multiple times
stdout, stderr = entry.bash_with_password(["cmd"], count=3)
```

## Development

### Install Dev Dependencies

```bash
uv sync
```

This installs all dependencies and dev tools (pytest, ruff, mypy).

### Run Tests

```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run specific test
uv run pytest tests/test_entry.py::test_entry_with_encryption

# Show print statements during tests
uv run pytest -s

# Run with coverage
uv run pytest --cov=keepass_wrapper
```

### Code Quality

```bash
# Lint code
uv run ruff check keepass_wrapper tests

# Type check
uv run mypy keepass_wrapper

# Format code (ruff)
uv run ruff format keepass_wrapper tests
```

## Project Structure

```
pykeepass-wrapper/
├── .gitignore
├── pyproject.toml
├── README.md
├── keepass_wrapper/
│   ├── __init__.py
│   ├── config.py
│   ├── encryption.py
│   ├── entry.py
│   ├── keepass.py
│   └── otp.py
└── tests/
    ├── __init__.py
    ├── test_encryption.py
    ├── test_entry.py
    ├── test_keepass.py
    └── test_otp.py
```

## Features

- **Type hints**: Full type annotations for IDE support and mypy compatibility
- **Pydantic validation**: Runtime type validation and configuration management
- **Encryption**: Optional Fernet-based encryption of passwords and TOTP secrets
- **TOTP Support**: Automatic TOTP generation from KeePass OTP fields
- **Bash Integration**: Execute commands with automatic password input
- **Error Handling**: Graceful authentication retry with max attempt limits
- **Testing**: Comprehensive test coverage with mocked KeePass database

## Python Best Practices Used

- ✅ **Type hints**: Full type annotations throughout
- ✅ **Docstrings**: Clear descriptions of modules, classes, and functions
- ✅ **Project structure**: Proper package layout with separation of concerns
- ✅ **Testing**: Comprehensive test suite with unit and integration tests
- ✅ **Configuration**: Externalized config using pydantic BaseModel
- ✅ **Linting**: Code quality checks with ruff
- ✅ **Type checking**: Static type checking with mypy (strict mode)
- ✅ **Dependency management**: Explicit dependencies in pyproject.toml
- ✅ **Python versions**: Supports Python 3.10+

## Security Considerations

- **Password handling**: All passwords encrypted in memory when encryption is enabled
- **TOTP secrets**: OTP secrets encrypted alongside passwords
- **Key management**: New Fernet key generated per session
- **Garbage collection**: Explicit cleanup of PyKeePass objects after use
- **Type safety**: Strict mypy configuration catches potential errors at development time

## License

MIT

## Contributing

This is a template-based project. Feel free to use it as a starting point for your own applications.

## Author

Your Name <your.email@example.com>
```

---

## Summary

Your **KeePass wrapper** has been fully adapted to the template! Here's what was reorganized:

| Component | Changes |
|-----------|---------|
| **Separation of Concerns** | Split monolithic code into: `encryption.py`, `otp.py`, `entry.py`, `keepass.py` |
| **Type Hints** | Added full type annotations throughout (mypy strict mode compatible) |
| **Configuration** | Created `Config` pydantic model for database path and options |
| **Testing** | 30+ comprehensive tests with mocking for KeePass and subprocess |
| **Documentation** | Complete README with usage examples for all features |
| **Best Practices** | Proper error handling, docstrings, dependency management |

You're ready to use this! Just update the author info in `pyproject.toml` and `README.md`, then run:

```bash
uv sync
uv run pytest
uv run ruff check keepass_wrapper tests
uv run mypy keepass_wrapper
```