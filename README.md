# gh-audit

Personal GitHub repository meta linting tool for consistent configuration. Probably not interesting to you.

## Installation

```sh
$ pip install git+https://github.com/josh/gh-audit.git
```

## Usage

```sh
$ gh-audit --help
Usage: gh-audit [OPTIONS] [REPOSITORY]...

Options:
  --active                       Include all your non-archived repositories
  --github-token TOKEN           GitHub API token
  --verbose                      Enable debug logging
  --version                      Show the version and exit.
  --help                         Show this message and exit.
```

## Development

To contribute to this tool, first checkout the code. Then create a new virtual environment:

```sh
cd gh-audit
uv venv
source .venv/bin/activate
```

Now install the dependencies and test dependencies:

```sh
uv pip install -e '.[dev]'
```
