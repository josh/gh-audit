import logging
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from typing import Any, Literal, cast

import click
import tomllib
from github import Auth, Github, GithubException
from github.ContentFile import ContentFile
from github.Repository import Repository

logger = logging.getLogger(__name__)


@click.command()
@click.argument("repository", nargs=-1)
@click.option("--active", is_flag=True)
@click.option("--github-token", envvar="GITHUB_TOKEN")
@click.option(
    "--open-issues",
    type=click.Choice(["error", "warning"], case_sensitive=False),
)
@click.option("--verbose", is_flag=True, default=False)
@click.version_option()
def main(
    repository: list[str],
    active: bool,
    github_token: str,
    open_issues: Literal["error", "warning"],
    verbose: bool,
) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)

    with Github(auth=Auth.Token(github_token)) as g:
        user = g.get_user()

        for name in repository:
            for rule in RULES:
                rule(repo=user.get_repo(name))

        if active:
            for repo in user.get_repos():
                if repo.archived:
                    continue
                for rule in RULES:
                    rule(repo=repo)


@dataclass
class Rule:
    code: str
    name: str
    log_message: str
    issue_title: str
    level: Literal["error", "warning"]
    check: Callable[[Repository], bool]
    check_cond: Callable[[Repository], bool] = lambda _: True

    def __call__(self, repo: Repository) -> bool:
        if self.check_cond(repo) and self.check(repo):
            if self.level == "warning":
                click.echo(f"\033[33mWARN\033[0m {repo.full_name}: {self.log_message}")
            elif self.level == "error":
                click.echo(f"\033[31mERROR\033[0m {repo.full_name}: {self.log_message}")
            return False
        return True


RULES: list[Rule] = []


def define_rule(**kwargs: Any) -> None:
    RULES.append(Rule(**kwargs))


define_rule(
    code="M1",
    name="missing-description",
    log_message="Missing repository description",
    issue_title="Set repository description",
    level="error",
    check=lambda repo: not repo.description,
)

define_rule(
    code="M2",
    name="missing-license",
    log_message="Missing license file",
    issue_title="Add a LICENSE",
    level="error",
    check=lambda repo: not repo.license,
)

define_rule(
    code="M2.1",
    name="non-mit-license",
    log_message="Using non-MIT license",
    issue_title="Prefer using MIT License",
    level="warning",
    check=lambda repo: repo.license and repo.license.name != "MIT License",
)

define_rule(
    code="M3",
    name="missing-readme",
    log_message="Missing README file",
    issue_title="Add a README",
    level="error",
    check=lambda repo: not _get_readme(repo),
)

define_rule(
    code="M4",
    name="missing-topics",
    log_message="Missing topics",
    issue_title="Add topics",
    level="error",
    check=lambda repo: len(repo.topics) == 0,
)

define_rule(
    code="M4.1",
    name="too-few-topics",
    log_message="Only one topic",
    issue_title="Add more topics",
    level="warning",
    check=lambda repo: len(repo.topics) == 1,
)


def _get_readme(repo: Repository) -> ContentFile | None:
    try:
        return repo.get_readme()
    except GithubException:
        return None


@cache
def _load_pyproject(repo: Repository) -> dict[str, Any]:
    logger.debug("Loading pyproject.toml for %s", repo.full_name)
    try:
        contents = repo.get_contents(path="pyproject.toml")
    except GithubException:
        return dict()
    if isinstance(contents, list):
        return dict()
    try:
        return tomllib.loads(contents.decoded_content.decode("utf-8"))
    except tomllib.TOMLDecodeError:
        return dict()


define_rule(
    code="P1",
    name="missing-pyproject",
    log_message="Missing pyproject.toml",
    issue_title="Add a pyproject.toml",
    level="error",
    check=lambda repo: not _load_pyproject(repo),
    check_cond=lambda repo: repo.language == "Python",
)

define_rule(
    code="P1.1",
    name="missing-pyproject-project-name",
    log_message="project.name missing in pyproject.toml",
    issue_title="Add project.name to pyproject.toml",
    level="error",
    check=lambda repo: _load_pyproject(repo).get("project", {}).get("name") is None,
    check_cond=lambda repo: _load_pyproject(repo),
)


def _pyproject_requires_python(repo: Repository) -> str:
    return cast(
        str, _load_pyproject(repo).get("project", {}).get("requires-python", "")
    )


define_rule(
    code="P1.2",
    name="missing-pyproject-requires-python",
    log_message="project.requires-python missing in pyproject.toml",
    issue_title="Add project.requires-python to pyproject.toml",
    level="error",
    check=lambda repo: not _pyproject_requires_python(repo),
    check_cond=lambda repo: _load_pyproject(repo),
)

define_rule(
    code="P1.2.1",
    name="missing-pyproject-requires-python-3-12",
    log_message="project.requires-python should be 3.10 or older",
    issue_title="Use project.requires-python >= '3.10'",
    level="warning",
    check=lambda repo: _pyproject_requires_python(repo) == ">=3.12",
    check_cond=lambda repo: _load_pyproject(repo),
)

define_rule(
    code="P1.2.2",
    name="missing-pyproject-requires-python-3-11",
    log_message="project.requires-python should be 3.10 or older",
    issue_title="Use project.requires-python >= '3.10'",
    level="warning",
    check=lambda repo: _pyproject_requires_python(repo) == ">=3.11",
    check_cond=lambda repo: _load_pyproject(repo),
)


@cache
def _ruff_extend_select(repo: Repository) -> list[str]:
    return cast(
        list[str],
        _load_pyproject(repo)
        .get("tool", {})
        .get("ruff", {})
        .get("lint", {})
        .get("extend-select", []),
    )


define_rule(
    code="P1.3.1",
    name="missing-pyproject-ruff-isort-rules",
    log_message="tool.ruff.lint.extend-select missing 'I' to enable isort rules",
    issue_title="Add 'I' to tool.ruff.lint.extend-select",
    level="error",
    check=lambda repo: "I" not in _ruff_extend_select(repo),
    check_cond=lambda repo: _load_pyproject(repo),
)

define_rule(
    code="P1.3.2",
    name="missing-pyproject-ruff-pyupgrade-rules",
    log_message="tool.ruff.lint.extend-select missing 'UP' to enable pyupgrade rules",
    issue_title="Add 'UP' to tool.ruff.lint.extend-select",
    level="error",
    check=lambda repo: "UP" not in _ruff_extend_select(repo),
    check_cond=lambda repo: _load_pyproject(repo),
)


if __name__ == "__main__":
    main()
