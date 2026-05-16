# pykeepass-wrapper

A secure KeePass password manager wrapper with encryption and TOTP support using **uv**, **pydantic**, and **pytest**.

## Overview

This package provides a Python wrapper around **pykeepass** for managing KeePass databases with additional security features:

- **Encryption**: In-memory encryption of sensitive data using Fernet
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

# Initialize with default settings
# (prompts for password, uses default .kdbx path from config)
keepass = KeePass()

# Or with custom database path
keepass = KeePass(database_path="/path/to/passwords.kdbx")

# Access entries
for entry in keepass.entries:
    print(f"Title: {entry.title}")
    print(f"Username: {entry.username}")
```

### Configuration

KeePass initializes with a **Pydantic Config** internally. You can customize behavior via constructor arguments:

```python
from keepass_wrapper import KeePass

# Custom database path
keepass = KeePass(database_path="/home/user/.config/passwords.kdbx")

# Filter entries by title on initialization
keepass = KeePass(
    database_path="/home/user/.config/passwords.kdbx",
    filter_title="Work"
)
```

### Finding Entries

```python
# Find by partial match (default)
results = keepass.find_entries("Gmail")

# Find by exact match
results = keepass.find_entries("Gmail Account", exact=True)

# Find by prefix
results = keepass.find_entries("Gmail", startswith=True)

# Find by multiple titles
results = keepass.find_entries(["Gmail", "GitHub"])
```

### Using Encrypted Entries

```python
from keepass_wrapper import KeePass

# Encryption is enabled by default
keepass = KeePass()

for entry in keepass.entries:
    password = entry.get_password()  # Decrypts on demand
    totp = entry.get_totp()  # Generates TOTP from encrypted secret
    
    if password:
        print(f"{entry.title}: {password}")
    if totp:
        print(f"TOTP: {totp}")
```

### TOTP Generation

```python
# Get current TOTP code
entry = keepass.entries[0]

code = entry.get_totp()
if code:
    print(f"Current code: {code}")  # Returns 6-digit code as string
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
- **Encryption**: Fernet-based encryption of passwords and TOTP secrets
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

- **Password handling**: All passwords encrypted in memory
- **TOTP secrets**: OTP secrets encrypted alongside passwords
- **Key management**: New Fernet key generated per session
- **Garbage collection**: Explicit cleanup of PyKeePass objects after use
- **Type safety**: Strict mypy configuration catches potential errors at development time

## License

MIT

## Contributing

This is a template-based project. Feel free to use it as a starting point for your own applications.

## Author

AlexAndrewsAI <alex.andrews.ai@protonmail.com>