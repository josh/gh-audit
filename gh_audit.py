import logging
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from typing import Any, Literal, cast

import click
import tomllib
import yaml
from github import Auth, Github, GithubException
from github.ContentFile import ContentFile
from github.Repository import Repository

logger = logging.getLogger(__name__)


@click.command()
@click.argument("repository", nargs=-1)
@click.option(
    "--active", is_flag=True, help="Include all your non-archived repositories"
)
@click.option(
    "--github-token",
    envvar="GITHUB_TOKEN",
    help="GitHub API token",
    metavar="TOKEN",
)
@click.option(
    "--open-issues",
    type=click.Choice(["error", "warning"], case_sensitive=False),
    help="Open issues for the rule violations",
)
@click.option("--verbose", is_flag=True, default=False, help="Enable debug logging")
@click.version_option()
def main(
    repository: list[str],
    active: bool,
    github_token: str,
    open_issues: Literal["error", "warning"] | None,
    verbose: bool,
) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)

    with Github(auth=Auth.Token(github_token)) as g:
        user = g.get_user()

        for name in repository:
            repo = user.get_repo(name)
            for rule in RULES:
                rule(repo=repo)

        if active:
            for repo in user.get_repos():
                if repo.owner.login != user.login:
                    continue
                if repo.archived:
                    continue
                for rule in RULES:
                    rule(repo=repo)


@dataclass
class Rule:
    name: str
    log_message: str
    issue_title: str
    level: Literal["error", "warning"]
    check: Callable[[Repository], bool]
    check_cond: Callable[[Repository], bool] = lambda _: True

    def __call__(self, repo: Repository) -> bool:
        if self.check_cond(repo) and self.check(repo):
            if self.level == "warning":
                click.echo(
                    f"{repo.full_name}: \033[33mwarn:\033[0m {self.log_message} [{self.name}]"
                )
            elif self.level == "error":
                click.echo(
                    f"{repo.full_name}: \033[31merror:\033[0m {self.log_message} [{self.name}]"
                )
            return False
        return True


RULES: list[Rule] = []


def define_rule(**kwargs: Any) -> None:
    RULES.append(Rule(**kwargs))


define_rule(
    name="missing-description",
    log_message="Missing repository description",
    issue_title="Set repository description",
    level="error",
    check=lambda repo: not repo.description,
)

define_rule(
    name="missing-license",
    log_message="Missing license file",
    issue_title="Add a LICENSE",
    level="error",
    check=lambda repo: not repo.license,
    check_cond=lambda repo: repo.visibility == "public",
)

define_rule(
    name="non-mit-license",
    log_message="Using non-MIT license",
    issue_title="Prefer using MIT License",
    level="warning",
    check=lambda repo: repo.license and repo.license.name != "MIT License",
    check_cond=lambda repo: repo.visibility == "public",
)

define_rule(
    name="missing-readme",
    log_message="Missing README file",
    issue_title="Add a README",
    level="error",
    check=lambda repo: not _get_readme(repo),
)

define_rule(
    name="missing-topics",
    log_message="Missing topics",
    issue_title="Add topics",
    level="error",
    check=lambda repo: len(repo.topics) == 0,
)

define_rule(
    name="too-few-topics",
    log_message="Only one topic",
    issue_title="Add more topics",
    level="warning",
    check=lambda repo: len(repo.topics) == 1,
)

define_rule(
    name="has-issues",
    log_message="Repository doesn't have Issues enabled",
    issue_title="Enable GitHub Issues",
    level="warning",
    check=lambda repo: not repo.has_issues,
)

define_rule(
    name="no-projects",
    log_message="Repository has Projects enabled",
    issue_title="Disable GitHub Projects",
    level="warning",
    check=lambda repo: repo.has_projects,
)

define_rule(
    name="no-wiki",
    log_message="Repository has Wiki enabled",
    issue_title="Disable GitHub Wiki",
    level="warning",
    check=lambda repo: repo.has_wiki,
)

# define_rule(
#     name="no-discussions",
#     log_message="Repository has Discussions enabled",
#     issue_title="Disable GitHub Discussions",
#     level="warning",
#     check=lambda repo: repo.has_discussions,
# )


def _get_readme(repo: Repository) -> ContentFile | None:
    try:
        return repo.get_readme()
    except GithubException:
        return None


def _get_contents(repo: Repository, path: str) -> ContentFile | None:
    try:
        contents = repo.get_contents(path=path)
    except GithubException:
        return None
    if isinstance(contents, list):
        return None
    return contents


@cache
def _load_pyproject(repo: Repository) -> dict[str, Any]:
    logger.debug("Loading pyproject.toml for %s", repo.full_name)
    contents = _get_contents(repo, path="pyproject.toml")
    if not contents:
        return dict()
    try:
        return tomllib.loads(contents.decoded_content.decode("utf-8"))
    except tomllib.TOMLDecodeError:
        return dict()


define_rule(
    name="missing-pyproject",
    log_message="Missing pyproject.toml",
    issue_title="Add a pyproject.toml",
    level="error",
    check=lambda repo: not _load_pyproject(repo),
    check_cond=lambda repo: repo.language == "Python",
)

define_rule(
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


def _has_requirements_txt(repo: Repository) -> bool:
    if _get_contents(repo, path="requirements.txt"):
        return True
    return False


define_rule(
    name="missing-pyproject-requires-python",
    log_message="project.requires-python missing in pyproject.toml",
    issue_title="Add project.requires-python to pyproject.toml",
    level="error",
    check=lambda repo: not _pyproject_requires_python(repo),
    check_cond=lambda repo: _load_pyproject(repo),
)

define_rule(
    name="missing-pyproject-requires-python-3-12",
    log_message="project.requires-python should be 3.10 or older",
    issue_title="Use project.requires-python >= '3.10'",
    level="warning",
    check=lambda repo: _pyproject_requires_python(repo) == ">=3.12",
    check_cond=lambda repo: _load_pyproject(repo),
)

define_rule(
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
    name="missing-pyproject-ruff-isort-rules",
    log_message="tool.ruff.lint.extend-select missing 'I' to enable isort rules",
    issue_title="Add 'I' to tool.ruff.lint.extend-select",
    level="error",
    check=lambda repo: "I" not in _ruff_extend_select(repo),
    check_cond=lambda repo: _load_pyproject(repo),
)

define_rule(
    name="missing-pyproject-ruff-pyupgrade-rules",
    log_message="tool.ruff.lint.extend-select missing 'UP' to enable pyupgrade rules",
    issue_title="Add 'UP' to tool.ruff.lint.extend-select",
    level="error",
    check=lambda repo: "UP" not in _ruff_extend_select(repo),
    check_cond=lambda repo: _load_pyproject(repo),
)


def _mypy_strict(repo: Repository) -> bool | None:
    return cast(
        bool | None,
        _load_pyproject(repo).get("tool", {}).get("mypy", {}).get("strict"),
    )


define_rule(
    name="mypy-strict-declared",
    log_message="mypy strict mode is not declared",
    issue_title="Declare a mypy strict mode",
    level="error",
    check=lambda repo: _mypy_strict(repo) is None,
    check_cond=lambda repo: _load_pyproject(repo),
)

define_rule(
    name="mypy-strict",
    log_message="mypy strict mode is not enabled",
    issue_title="Enable mypy strict mode",
    level="warning",
    check=lambda repo: _mypy_strict(repo) is False,
    check_cond=lambda repo: _load_pyproject(repo),
)

define_rule(
    name="requirements-txt-exact",
    log_message="Use exact versions in requirements.txt",
    issue_title="Use exact versions in requirements.txt",
    level="error",
    check=lambda repo: _requirements_txt_is_exact(repo) is False,
    check_cond=lambda repo: _has_requirements_txt(repo),
)


def _requirements_txt_is_exact(repo: Repository) -> bool:
    if contents := _get_contents(repo, path="requirements.txt"):
        text = contents.decoded_content.decode("utf-8")
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "@" in line:
                continue
            if "==" not in line:
                return False
        return True
    else:
        return True


@cache
def _dependabot_config(repo: Repository) -> dict[str, Any]:
    logger.debug("Loading .github/dependabot.yml for %s", repo.full_name)
    contents = _get_contents(repo, path=".github/dependabot.yml")
    if not contents:
        return dict()
    try:
        return cast(
            dict[str, Any],
            yaml.safe_load(contents.decoded_content.decode("utf-8")),
        )
    except yaml.YAMLError:
        return dict()


def _dependabot_update_schedule_intervals(repo: Repository) -> set[str]:
    return {
        update.get("schedule", {}).get("interval")
        for update in _dependabot_config(repo).get("updates", [])
    }


define_rule(
    name="dependabot-schedule-monthly",
    log_message="Dependabot should be scheduled monthly",
    issue_title="Schedule Dependabot monthly",
    level="warning",
    check=lambda repo: _dependabot_update_schedule_intervals(repo) != {"monthly"},
    check_cond=lambda repo: _dependabot_config(repo),
)

define_rule(
    name="pip-dependabot",
    log_message="Dependabot should be enabled for pip ecosystem",
    issue_title="Enable Dependabot for pip ecosystem",
    level="error",
    check=lambda repo: "pip"
    not in [
        update.get("package-ecosystem")
        for update in _dependabot_config(repo).get("updates", [])
    ],
    check_cond=lambda repo: _has_requirements_txt(repo),
)


def _get_workflow(repo: Repository, name: str) -> dict[str, Any]:
    contents = _get_contents(repo, path=f".github/workflows/{name}.yml")
    if not contents:
        return dict()
    try:
        return cast(
            dict[str, Any],
            yaml.safe_load(contents.decoded_content.decode("utf-8")),
        )
    except yaml.YAMLError:
        return dict()


def _job_defined(repo: Repository, workflows: list[str], name: str) -> bool:
    for workflow in workflows:
        if name in _get_workflow(repo, workflow).get("jobs", {}):
            return True
    return False


define_rule(
    name="missing-ruff-lint-workflow",
    log_message="Missing GitHub Actions workflow for ruff linting",
    issue_title="Add Lint workflow for ruff",
    level="error",
    check=lambda repo: _job_defined(repo, ["lint", "test"], "ruff") is False,
    check_cond=lambda repo: repo.language == "Python",
)

define_rule(
    name="missing-mypy-lint-workflow",
    log_message="Missing GitHub Actions workflow for mypy type checking",
    issue_title="Add Lint workflow for mypy",
    level="error",
    check=lambda repo: _job_defined(repo, ["lint", "test"], "mypy") is False,
    check_cond=lambda repo: repo.language == "Python",
)


if __name__ == "__main__":
    main()
