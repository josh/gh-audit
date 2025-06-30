# Agents Guide

This project uses Python 3.11 or newer and manages dependencies with `uv`.

## Setup

Install Python 3.11 or newer and install `uv` with:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
# or
pipx install uv
```

Create a virtual environment and install the development dependencies:

```sh
uv venv
source .venv/bin/activate
uv pip install -e '.[dev]'
```

## Testing

Check code style with ruff:

```sh
ruff format --diff .
ruff check .
```

Check type correctness with mypy:

```sh
mypy .
```

This repository currently has no automated test suite.

## Formatting

You can automatically fix most formatting issues with:

```sh
ruff format .
```
