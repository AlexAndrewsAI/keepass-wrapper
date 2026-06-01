# pykeepass-wrapper

A secure KeePass password manager wrapper with encryption and TOTP support using **uv**, **pydantic**, and **pytest**.

## Uses

- [mount-encrypted-filesystem](https://github.com/AlexAndrewsAI/mount-encrypted-filesystem)
- [backup-keepass-unlock](https://github.com/AlexAndrewsAI/backup-keepass-unlock)

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

### Basic Example (Recommended)

Using a context manager ensures that sensitive data and encryption keys are cleared from memory as soon as you are finished:

```python
from keepass_wrapper import KeePass

with KeePass(database_path="/path/to/passwords.kdbx") as keepass:
    for entry in keepass.entries:
        print(f"Title: {entry.title}")
```

### Manual Management

If you cannot use a context manager, ensure you call `.close()` explicitly:

```python
from keepass_wrapper import KeePass

# Initialize
keepass = KeePass()

try:
    # Access entries
    results = keepass.find_entries("Gmail")
finally:
    # Always close to clear memory
    keepass.close()
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
keepass-wrapper/
├── AGENTS_MANUAL_CHECKS.md
├── AGENTS.md
├── .gitignore
├── keepass_wrapper
│   ├── config.py
│   ├── encryption.py
│   ├── entry.py
│   ├── __init__.py
│   ├── keepass.py
│   └── otp.py
├── pyproject.toml
├── README.md
├── tests
│   ├── __init__.py
│   ├── test_encryption.py
│   ├── test_entry.py
│   ├── test.kdbx
│   ├── test_kdbx.py
│   ├── test_keepass.py
│   └── test_otp.py
└── uv.lock
```

## Features

- **Type hints**: Full type annotations for IDE support and mypy compatibility
- **Pydantic validation**: Runtime type validation and configuration management
- **Encryption**: Fernet-based encryption of passwords and TOTP secrets
- **TOTP Support**: Automatic TOTP generation from KeePass OTP fields
- **Bash Integration**: Execute commands with automatic password input
- **Error Handling**: Graceful authentication retry with max attempt limits
- **Testing**: Comprehensive test coverage with mocked KeePass database

## Security Considerations

- **In-Memory Encryption**: Sensitive fields (passwords, OTP secrets) are encrypted using Fernet (AES-128-CBC) while stored in memory. A unique key is generated per session.
- **Context Management**: Use the `with KeePass(...)` pattern to ensure encryption keys and decrypted objects are cleared from memory immediately after use.
- **Garbage Collection**: The library uses `gc.collect()` and explicit reference clearing to minimize the window where sensitive data might reside in memory.
- **Subprocess Integration**: `bash_with_password` pipes the password directly to `stdin`. While more secure than CLI arguments, the password string briefly exists in the subprocess's input buffer.

### Limitations of In-Memory Security

While this wrapper provides significantly more protection than storing passwords in plaintext Python strings, users should be aware of the following:

1.  **Memory Zeroing**: Python's memory management does not guarantee that physical memory is zeroed immediately after a string or byte array is deleted. Sensitive data may persist in RAM until overwritten by another process or the OS.
2.  **Swap Space**: If your system swaps memory to disk, encrypted or plaintext secrets could be written to persistent storage. It is recommended to disable swap on systems handling highly sensitive data.
3.  **Process Inspection**: A user with root privileges or the same user ID as the Python process can potentially inspect the process memory and extract encryption keys or decrypted secrets.

## Disclaimer

This software is intended for personal use and is provided "as is", without any warranty of any kind, express or implied. While efforts have been made to ensure security, there is no guarantee that this software is free of security vulnerabilities. Use it at your own risk.

## License

MIT

## Contributing

This is a template-based project. Feel free to use it as a starting point for your own applications.

## Author

AlexAndrewsAI <alex.andrews.ai@protonmail.com>
