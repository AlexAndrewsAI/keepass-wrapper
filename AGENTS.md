# Agent Instructions: keepass-wrapper

## Quick Start
1. **Setup:** Run `uv sync --dev` before major work sessions
2. **Activate:** Ensure `.venv` is active; run `uv venv` if missing
3. **Code:** Use `python3` or `uv run python`; always add type hints and tests

## Tech Stack
| Component | Tool |
|-----------|------|
| Environment & Dependencies | uv |
| Data Validation | Pydantic + pydantic-settings |
| KeePass Integration | pykeepass |
| Encryption | cryptography (Fernet, in-memory session key) |
| TOTP Generation | pyotp |
| Testing | pytest + pytest-cov |
| Linting & Formatting | ruff (check + format) |
| Type Checking | mypy (strict mode) |
| Coverage Threshold | 90% (`--cov-fail-under=90`) |

## Project Structure
```
keepass-wrapper/
  ├── AGENTS.md
  ├── AGENTS_MANUAL_CHECKS.md
  ├── README.md
  ├── pyproject.toml
  ├── uv.lock
  ├── keepass_wrapper/
  │   ├── __init__.py     (public API: KeePass, KeePassEntry, Config, DEFAULT_TEST_DATABASE)
  │   ├── config.py       (Pydantic BaseSettings with KEEPASS_ env prefix)
  │   ├── encryption.py   (EncryptionManager: Fernet session key, in-memory zeroing on clear())
  │   ├── entry.py        (KeePassEntry: __slots__, encrypted password/otp, bash_with_password)
  │   ├── keepass.py      (KeePass manager: auth retry, try/finally cleanup, logging)
  │   └── otp.py          (extract_totp_secret, generate_totp)
  └── tests/
      ├── __init__.py
      ├── test.kdbx       (Real KeePass database for integration tests)
      ├── test_encryption.py
      ├── test_entry.py
      ├── test_kdbx.py    (Integration tests against the real test.kdbx fixture)
      ├── test_keepass.py
      └── test_otp.py
```

### Notable design invariants
- `KeePassEntry` uses `__slots__` to reduce the memory footprint of sensitive attributes and to make accidental attribute typos fail loudly.
- `EncryptionManager` holds a session-scoped Fernet key in `_key` (private). `clear()` overwrites the key buffer with zeros before reassigning a fresh key.
- `KeePass` is usable as a context manager; `__exit__` invokes `close()`, which clears entries and calls `encryption_manager.clear()`.
- `KeePassEntry.bash_with_password` sends the password to stdin **exactly once** (the previous `count` parameter was removed for security). Callers needing multiple prompts must rely on a single authentication round (e.g. `sudo -S`).

## Essential Directives

### Code Standards
- **Type Hints:** Required on ALL function signatures and class members. Enforce strictly with mypy.
- **Docstrings:** Google-style format for all public APIs. One-line docstrings are also required on test functions.
- **Logging:** Use `logging` module only; never `print()`.
- **Relative Paths:** Never use absolute paths in code.
- **Linting:** Narrow exception handling — prefer `pytest.raises(SpecificError)` to `pytest.raises(Exception)` (B017/PT011 are enforced).

### Dependency & Configuration Management
- **Adding/Removing Dependencies:** Use `uv add` / `uv remove` commands.
- **Editing pyproject.toml:** Avoid manual edits during development. Only update `pyproject.toml` as the **final change** after all work is tested and finalized.
- **Before Major Work:** Always run `uv sync --dev` first.
- **Dev dependencies:** Defined under `[dependency-groups] dev` (PEP 735). Do **not** reintroduce a parallel `[project.optional-dependencies] dev` block.

### Testing & Quality
- **Test Coverage:** Every code change requires corresponding tests in `tests/`. The suite must stay at or above **90%** line coverage.
- **Validation Before Commit:** Run the full suite — all three must pass with no errors:
  ```bash
  uv run pytest
  uv run ruff check .
  uv run mypy .
  ```
- **Per-file ruff ignores for `tests/**`** are intentionally limited to `S101`, `S105`, `D100`, and `D104` — the minimum required to keep test code idiomatic while still enforcing the test-docstring and narrow-exception rules. Do **not** add `B011`/`PT015`/`PT017`/`S110`/`D103` to this list unless a real trigger is reintroduced.

### Operational Constraints
- **No Interactive Prompts:** Mock or bypass any interactive commands (e.g. `getpass.getpass` is mocked in `tests/test_keepass.py` and `tests/test_kdbx.py`).
- **No Git Operations:** Don't stage/commit unless explicitly requested.
- **Code Review Mode:** Analyze only; record findings in `./REVIEW.md` without making modifications. At the top of the review, identify the reviewer including the name of the IDE/CLI used and the primary model that performed the review.

### File Maintenance
- **Keep Instructions Current:** Update "Tech Stack," "Project Structure," and "Workflow Commands" in this file whenever `pyproject.toml`, repository layout, or core logic changes. The README's "Project Structure" tree must mirror this section.

## Workflow Commands
```bash
# Setup
uv sync --dev                           # Install/sync all dependencies (including dev group)

# Quality gates (run all three before every commit)
uv run pytest                           # Run tests + coverage (fails under 90%)
uv run ruff check .                     # Lint
uv run ruff format .                    # Auto-format (separate from check)
uv run mypy .                           # Type check (strict)
```

## Security Notes
- A new Fernet key is generated per `EncryptionManager`; encrypted values cannot be decrypted across sessions.
- `EncryptionManager.clear()` overwrites `_key` with `b"\x00" * len(_key)` before reassignment. CPython does not guarantee physical memory zeroing; this is documented in the docstring and README.
- `KeePassEntry.bash_with_password` writes the plaintext password to the child's stdin exactly once, never to argv. The bandit `S603` warning is acknowledged inline with `# noqa: S603`.
- Auth retries are bounded at 3 attempts and use `logging.warning`; transient `CredentialsError`/`BinaryError` are caught, all other exceptions propagate.
