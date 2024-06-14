import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Final, Literal, cast

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


OK: Final = "OK"
FAIL: Final = "FAIL"
RESULT = Literal["OK", "FAIL"]


@dataclass
class Rule:
    name: str
    log_message: str
    issue_title: str
    level: Literal["error", "warning"]
    check: Callable[[Repository], RESULT]
    check_cond: Callable[[Repository], bool] = lambda _: True

    def __call__(self, repo: Repository) -> bool:
        if self.check_cond(repo) and self.check(repo) is FAIL:
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


def define_rule(**kwargs: Any) -> Callable[[Callable[[Repository], RESULT]], None]:
    def _inner_define_rule(check: Callable[[Repository], RESULT]) -> None:
        rule = Rule(check=check, **kwargs)
        RULES.append(rule)

    return _inner_define_rule


@define_rule(
    name="missing-description",
    log_message="Missing repository description",
    issue_title="Set repository description",
    level="error",
)
def _missing_description(repo: Repository) -> RESULT:
    if repo.description:
        return OK
    return FAIL


@define_rule(
    name="missing-license",
    log_message="Missing license file",
    issue_title="Add a LICENSE",
    level="error",
    check_cond=lambda repo: repo.visibility == "public",
)
def _missing_license(repo: Repository) -> RESULT:
    if repo.get_license():
        return OK
    return FAIL


@define_rule(
    name="non-mit-license",
    log_message="Using non-MIT license",
    issue_title="Prefer using MIT License",
    level="warning",
    check_cond=lambda repo: repo.visibility == "public",
)
def _non_mit_license(repo: Repository) -> RESULT:
    if repo.license and repo.license.name != "MIT License":
        return FAIL
    return OK


@define_rule(
    name="missing-readme",
    log_message="Missing README file",
    issue_title="Add a README",
    level="error",
)
def _missing_readme(repo: Repository) -> RESULT:
    if _get_readme(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-topics",
    log_message="Missing topics",
    issue_title="Add topics",
    level="error",
)
def _missing_topics(repo: Repository) -> RESULT:
    if len(repo.topics) == 0:
        return FAIL
    return OK


@define_rule(
    name="too-few-topics",
    log_message="Only one topic",
    issue_title="Add more topics",
    level="warning",
)
def _too_few_topics(repo: Repository) -> RESULT:
    if len(repo.topics) == 1:
        return FAIL
    return OK


@define_rule(
    name="has-issues",
    log_message="Repository doesn't have Issues enabled",
    issue_title="Enable GitHub Issues",
    level="warning",
)
def _has_issues(repo: Repository) -> RESULT:
    if repo.has_issues:
        return OK
    return FAIL


@define_rule(
    name="no-projects",
    log_message="Repository has Projects enabled",
    issue_title="Disable GitHub Projects",
    level="warning",
)
def _no_projects(repo: Repository) -> RESULT:
    if repo.has_projects:
        return FAIL
    return OK


@define_rule(
    name="no-wiki",
    log_message="Repository has Wiki enabled",
    issue_title="Disable GitHub Wiki",
    level="warning",
)
def _no_wiki(repo: Repository) -> RESULT:
    if repo.has_wiki:
        return FAIL
    return OK


# Check if repo is larger than 1GB
@define_rule(
    name="git-size",
    log_message="Repository size is too large",
    issue_title="Reduce repository size",
    level="error",
)
def _git_size_error(repo: Repository) -> RESULT:
    if repo.size > (1024 * 1024):
        return FAIL
    return OK


# Check if repo is larger than 50MB
@define_rule(
    name="git-size",
    log_message="Repository size is too large",
    issue_title="Reduce repository size",
    level="warning",
)
def _git_size_warning(repo: Repository) -> RESULT:
    if repo.size > (50 * 1024):
        return FAIL
    return OK


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
def _get_contents_text(repo: Repository, path: str) -> str:
    if contents := _get_contents(repo, path=path):
        return contents.decoded_content.decode("utf-8")
    else:
        return ""


@cache
def _ls_tree(repo: Repository) -> list[Path]:
    return [Path(item.path) for item in repo.get_git_tree("HEAD", recursive=True).tree]


@cache
def _file_extnames(repo: Repository) -> set[str]:
    return {path.suffix for path in _ls_tree(repo)} - {""}


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


@define_rule(
    name="missing-pyproject",
    log_message="Missing pyproject.toml",
    issue_title="Add a pyproject.toml",
    level="error",
    check_cond=lambda repo: repo.language == "Python",
)
def _missing_pyproject(repo: Repository) -> RESULT:
    if _load_pyproject(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-pyproject-project-name",
    log_message="project.name missing in pyproject.toml",
    issue_title="Add project.name to pyproject.toml",
    level="error",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _missing_pyproject_project_name(repo: Repository) -> RESULT:
    if _load_pyproject(repo).get("project", {}).get("name") is None:
        return FAIL
    return OK


def _pyproject_classifiers(repo: Repository) -> set[str]:
    return set(_load_pyproject(repo).get("project", {}).get("classifiers", []))


_MIT_LICENSE_CLASSIFIER = "License :: OSI Approved :: MIT License"


@define_rule(
    name="pyproject-mit-license-classifier",
    log_message="License classifier missing in pyproject.toml",
    issue_title="Add License classifier to pyproject.toml",
    level="error",
    check_cond=lambda repo: _load_pyproject(repo)
    and repo.license
    and repo.license.name == "MIT License",
)
def _pyproject_mit_license_classifier(repo: Repository) -> RESULT:
    if _MIT_LICENSE_CLASSIFIER in _pyproject_classifiers(repo):
        return OK
    return FAIL


def _pyproject_author_names(repo: Repository) -> set[str]:
    names: set[str] = set()
    for author in _load_pyproject(repo).get("project", {}).get("authors", []):
        if name := author.get("name"):
            names.add(name)
    return names


def _pyproject_author_emails(repo: Repository) -> set[str]:
    emails: set[str] = set()
    for author in _load_pyproject(repo).get("project", {}).get("authors", []):
        if email := author.get("email"):
            emails.add(email)
    return emails


@define_rule(
    name="pyproject-omit-license",
    log_message="License classifier should be omitted when using MIT License",
    issue_title="Omit License classifier in pyproject.toml",
    level="warning",
    check_cond=lambda repo: repo.license and repo.license.name == "MIT License",
)
def _pyproject_omit_license(repo: Repository) -> RESULT:
    if "license" in _load_pyproject(repo).get("project", {}):
        return FAIL
    return OK


@define_rule(
    name="pyproject-author-name",
    log_message="project.authors[0].name missing in pyproject.toml",
    issue_title="Add a project.authors name to pyproject.toml",
    level="warn",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _pyproject_author_name(repo: Repository) -> RESULT:
    if len(_pyproject_author_names(repo)) == 0:
        return FAIL
    return OK


@define_rule(
    name="pyproject-omit-author-email",
    log_message="project.authors[0].email should be omitted for privacy",
    issue_title="Remove project.authors email in pyproject.toml",
    level="warning",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _pyproject_omit_author_email(repo: Repository) -> RESULT:
    if len(_pyproject_author_emails(repo)) > 0:
        return FAIL
    return OK


@define_rule(
    name="pyproject-readme",
    log_message="project.readme missing in pyproject.toml",
    issue_title="Add project.readme to pyproject.toml",
    level="error",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _pyproject_readme(repo: Repository) -> RESULT:
    if _load_pyproject(repo).get("project", {}).get("readme") is None:
        return FAIL
    return OK


def _pyproject_requires_python(repo: Repository) -> str:
    return cast(
        str, _load_pyproject(repo).get("project", {}).get("requires-python", "")
    )


@define_rule(
    name="missing-pyproject-requires-python",
    log_message="project.requires-python missing in pyproject.toml",
    issue_title="Add project.requires-python to pyproject.toml",
    level="error",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _missing_pyproject_requires_python(repo: Repository) -> RESULT:
    if _pyproject_requires_python(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-pyproject-requires-python-3-12",
    log_message="project.requires-python should be 3.10 or older",
    issue_title="Use project.requires-python >= '3.10'",
    level="warning",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _missing_pyproject_requires_python_3_12(repo: Repository) -> RESULT:
    if _pyproject_requires_python(repo) == ">=3.12":
        return FAIL
    return OK


@define_rule(
    name="missing-pyproject-requires-python-3-11",
    log_message="project.requires-python should be 3.10 or older",
    issue_title="Use project.requires-python >= '3.10'",
    level="warning",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _missing_pyproject_requires_python_3_11(repo: Repository) -> RESULT:
    if _pyproject_requires_python(repo) == ">=3.11":
        return FAIL
    return OK


@cache
def _pyproject_all_dependencies(repo: Repository) -> set[str]:
    deps: set[str] = set()
    project = _load_pyproject(repo).get("project", {})
    for dep in project.get("dependencies", []):
        deps.add(dep)
    for extra_deps in project.get("optional-dependencies", {}).values():
        for dep in extra_deps:
            deps.add(dep)
    return deps


def _pydep_has_lower_bound(dep: str) -> bool:
    return "==" in dep or ">" in dep or "~=" in dep or "@" in dep


@define_rule(
    name="pyproject-dependency-lower-bound",
    log_message="Dependencies should have lower bound",
    issue_title="Add lower bound to pyproject.toml dependencies",
    level="error",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _pyproject_dependency_lower_bound(repo: Repository) -> RESULT:
    for dep in _pyproject_all_dependencies(repo):
        if not _pydep_has_lower_bound(dep):
            return FAIL
    return OK


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


@define_rule(
    name="missing-pyproject-ruff-isort-rules",
    log_message="tool.ruff.lint.extend-select missing 'I' to enable isort rules",
    issue_title="Add 'I' to tool.ruff.lint.extend-select",
    level="error",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _missing_pyproject_ruff_isort_rules(repo: Repository) -> RESULT:
    if "I" in _ruff_extend_select(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-pyproject-ruff-pyupgrade-rules",
    log_message="tool.ruff.lint.extend-select missing 'UP' to enable pyupgrade rules",
    issue_title="Add 'UP' to tool.ruff.lint.extend-select",
    level="error",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _missing_pyproject_ruff_pyupgrade_rules(repo: Repository) -> RESULT:
    if "UP" in _ruff_extend_select(repo):
        return OK
    return FAIL


def _mypy_strict(repo: Repository) -> bool | None:
    return cast(
        bool | None,
        _load_pyproject(repo).get("tool", {}).get("mypy", {}).get("strict"),
    )


@define_rule(
    name="mypy-strict-declared",
    log_message="mypy strict mode is not declared",
    issue_title="Declare a mypy strict mode",
    level="error",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _mypy_strict_declared(repo: Repository) -> RESULT:
    if _mypy_strict(repo) is None:
        return FAIL
    return OK


@define_rule(
    name="mypy-strict",
    log_message="mypy strict mode is not enabled",
    issue_title="Enable mypy strict mode",
    level="warning",
    check_cond=lambda repo: _load_pyproject(repo),
)
def _mypy_strict_enabled(repo: Repository) -> RESULT:
    if _mypy_strict(repo) is False:
        return FAIL
    return OK


@define_rule(
    name="requirements-txt-exact",
    log_message="Use exact versions in requirements.txt",
    issue_title="Use exact versions in requirements.txt",
    level="error",
    check_cond=lambda repo: _has_requirements_txt(repo),
)
def _requirements_txt_exact(repo: Repository) -> RESULT:
    if _requirements_txt_is_exact(repo) is False:
        return FAIL
    return OK


@define_rule(
    name="requirements-txt-uv-compiled",
    log_message="requirements.txt is not compiled by uv",
    issue_title="Compile requirements.txt with uv",
    level="warning",
    check_cond=lambda repo: _has_requirements_txt(repo),
)
def _requirements_txt_uv_compiled(repo: Repository) -> RESULT:
    if "uv pip compile" in _requirements_txt(repo):
        return OK
    return FAIL


def _has_requirements_txt(repo: Repository) -> bool:
    if _get_contents(repo, path="requirements.txt"):
        return True
    return False


def _requirements_txt(repo: Repository) -> str:
    return _get_contents_text(repo, path="requirements.txt")


def _requirements_txt_is_exact(repo: Repository) -> bool:
    if text := _requirements_txt(repo):
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


@define_rule(
    name="dependabot-schedule-monthly",
    log_message="Dependabot should be scheduled monthly",
    issue_title="Schedule Dependabot monthly",
    level="warning",
    check_cond=lambda repo: _dependabot_config(repo),
)
def _dependabot_schedule_monthly(repo: Repository) -> RESULT:
    if _dependabot_update_schedule_intervals(repo) != {"monthly"}:
        return FAIL
    return OK


@define_rule(
    name="pip-dependabot",
    log_message="Dependabot should be enabled for pip ecosystem",
    issue_title="Enable Dependabot for pip ecosystem",
    level="error",
    check_cond=lambda repo: _has_requirements_txt(repo),
)
def _pip_dependabot(repo: Repository) -> RESULT:
    for update in _dependabot_config(repo).get("updates", []):
        if update.get("package-ecosystem") == "pip":
            return OK
    return FAIL


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


def _job_runs(repo: Repository, workflows: list[str], pattern: str) -> bool:
    for workflow in workflows:
        for name, job in _get_workflow(repo, workflow).get("jobs", {}).items():
            for step in job.get("steps", []):
                if re.search(pattern, step.get("run", "")):
                    return True
    return False


@define_rule(
    name="missing-ruff",
    log_message="Missing GitHub Actions workflow for ruff linting",
    issue_title="Add Lint workflow for ruff",
    level="error",
    check_cond=lambda repo: repo.language == "Python",
)
def _missing_ruff_error(repo: Repository) -> RESULT:
    if _job_runs(repo, ["lint", "test"], "ruff ") is False:
        return FAIL
    return OK


@define_rule(
    name="missing-ruff",
    log_message="Missing GitHub Actions workflow for ruff linting",
    issue_title="Add Lint workflow for ruff",
    level="warning",
    check_cond=lambda repo: ".py" in _file_extnames(repo),
)
def _missing_ruff_warning(repo: Repository) -> RESULT:
    if _job_runs(repo, ["lint", "test"], "ruff ") is False:
        return FAIL
    return OK


@define_rule(
    name="missing-mypy",
    log_message="Missing GitHub Actions workflow for mypy type checking",
    issue_title="Add Lint workflow for mypy",
    level="error",
    check_cond=lambda repo: repo.language == "Python",
)
def _missing_mypy(repo: Repository) -> RESULT:
    if _job_runs(repo, ["lint", "test"], "mypy ") is False:
        return FAIL
    return OK


@define_rule(
    name="missing-shfmt",
    log_message="Missing GitHub Actions workflow for shfmt linting",
    issue_title="Add Lint workflow for shfmt",
    level="warning",
    check_cond=lambda repo: ".sh" in _file_extnames(repo),
)
def _missing_shfmt(repo: Repository) -> RESULT:
    if _job_runs(repo, ["lint", "test"], "shfmt "):
        return OK
    return FAIL


@define_rule(
    name="missing-shellcheck",
    log_message="Missing GitHub Actions workflow for shellcheck linting",
    issue_title="Add Lint workflow for shellcheck",
    level="warning",
    check_cond=lambda repo: ".sh" in _file_extnames(repo),
)
def _missing_shellcheck(repo: Repository) -> RESULT:
    if _job_runs(repo, ["lint", "test"], "shellcheck "):
        return OK
    return FAIL


if __name__ == "__main__":
    main()
