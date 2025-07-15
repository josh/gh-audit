# Agents Guide

This project uses Python 3.11 or newer and manages dependencies with `uv`.

## Setup

Install Python 3.11 or newer and install `uv` with:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
# or
pipx install uv
```

Create a virtual environment and install the development dependencies from
`uv.lock`:

```sh
uv venv
source .venv/bin/activate
uv sync
```

## Testing

Check code style with ruff:

```sh
uv run ruff format --diff .
uv run ruff check .
```

Check type correctness with mypy:

```sh
uv run mypy .
```

This repository currently has no automated test suite.

## Formatting

You can automatically fix most formatting issues with:

```sh
uv run ruff format .
```

After making changes to `pyproject.toml`, ensure its formatted with `pyproject-fmt`.

```sh
uv tool run pyproject-fmt pyproject.toml
```
