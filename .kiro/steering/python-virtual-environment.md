---
inclusion: always
---

# Python Virtual Environment Guidelines

## Critical Requirements

**ALWAYS use the project's virtual environment for ALL Python operations.** This project has a `venv/` directory that must be used for dependency isolation.

## Command Execution Rules

### Required Command Patterns
- Python scripts: `./venv/bin/python script_name.py`
- Package installation: `./venv/bin/python -m pip install package_name`
- Running tests: `./venv/bin/python -m pytest`
- Module execution: `./venv/bin/python -m module_name`

### Forbidden Commands
- **NEVER** use bare `python`, `pip`, or `pytest` commands
- **NEVER** use system Python or global packages

## Setup Process

If virtual environment needs initialization:
1. `python -m venv venv`
2. `./venv/bin/python -m pip install -r requirements.txt`

## Activation Alternative

For interactive sessions, activate with:
- macOS/Linux: `source venv/bin/activate`
- Then use `python`, `pip` normally until `deactivate`

## Verification

Confirm correct environment:
```bash
./venv/bin/python --version
./venv/bin/python -m pip list
```