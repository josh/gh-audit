import logging
import re
import subprocess
import tomllib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Final, Literal, NotRequired, TypedDict, cast

import click
import yaml
from github import Auth, Github, GithubException
from github.ContentFile import ContentFile
from github.Repository import Repository

logger = logging.getLogger(__name__)


def _gh_auth_token() -> str | None:
    try:
        p = subprocess.run(
            ["gh", "auth", "token"],
            check=True,
            capture_output=True,
            encoding="utf-8",
        )
        return p.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


class RuleParamType(click.ParamType):
    name = "rule"

    def convert(self, value: str, param: Any, ctx: Any) -> "Rule":
        for rule in RULES:
            if rule.name == value:
                return rule
        self.fail(f"Unknown rule: {value}", param, ctx)


_RULE_TYPE = RuleParamType()


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
    required=True,
    default=_gh_auth_token(),
)
@click.option("--verbose", is_flag=True, default=False, help="Enable debug logging")
@click.option(
    "--rule",
    "override_rules",
    type=_RULE_TYPE,
    multiple=True,
    help="Specify rules to run",
)
@click.option(
    "--format",
    type=click.Choice(["repo", "rule"], case_sensitive=False),
    default="repo",
    required=True,
)
@click.version_option()
def main(
    repository: list[str],
    active: bool,
    override_rules: tuple["Rule", ...],
    format: Literal["repo", "rule"],
    github_token: str,
    verbose: bool,
) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)

    rules: list[Rule] = RULES
    if override_rules:
        rules = list(override_rules)
    logger.debug("Applying %d rules", len(rules))

    global rule_message_format
    if format == "repo":
        rule_message_format = "{repo}: {level} {log_message} [{rule}]"
    elif format == "rule":
        rule_message_format = "{rule}: {level} {log_message} [{repo}]"

    with Github(auth=Auth.Token(github_token)) as g:
        user = g.get_user()

        for name in repository:
            repo = user.get_repo(name)
            for rule in rules:
                rule(repo=repo)

        if active:
            for repo in user.get_repos():
                if repo.owner.login != user.login:
                    continue
                if repo.archived:
                    continue
                for rule in rules:
                    rule(repo=repo)


OK: Final = "OK"
SKIP: Final = "OK"
FAIL: Final = "FAIL"
RESULT = Literal["OK", "FAIL"]
rule_message_format = "{repo}: {level} {log_message} [{name}]"


@dataclass
class Rule:
    name: str
    log_message: str
    level: Literal["error", "warning"]
    check: Callable[[Repository], RESULT]

    def __call__(self, repo: Repository) -> bool:
        if self.check(repo) is FAIL:
            if self.level == "warning":
                level = "\033[33mwarn:\033[0m"
            elif self.level == "error":
                level = "\033[31merror:\033[0m"

            formatted_message = rule_message_format.format(
                rule=self.name,
                repo=repo.full_name,
                level=level,
                log_message=self.log_message,
            )
            click.echo(formatted_message)

            return False
        return True


RULES: list[Rule] = []


def define_rule(**kwargs: Any) -> Callable[[Callable[[Repository], RESULT]], None]:
    def _inner_define_rule(check: Callable[[Repository], RESULT]) -> None:
        rule = Rule(check=check, **kwargs)
        RULES.append(rule)

    return _inner_define_rule


WorkflowStep = TypedDict(
    "WorkflowStep",
    {
        "name": NotRequired[str],
        "uses": NotRequired[str],
        "run": NotRequired[str],
        "with": NotRequired[dict[str, str]],
        "env": NotRequired[dict[str, str]],
    },
)

WorkflowJob = TypedDict(
    "WorkflowJob",
    {
        "runs-on": str,
        "env": NotRequired[dict[str, str]],
        "permissions": NotRequired[dict[str, str]],
        "steps": list[WorkflowStep],
    },
)


class Workflow(TypedDict):
    name: str
    on: str | list[str] | dict[str, Any]
    permissions: NotRequired[dict[str, str]]
    concurrency: NotRequired[Any]
    env: NotRequired[dict[str, str]]
    jobs: dict[str, WorkflowJob]


@define_rule(
    name="missing-description",
    log_message="Missing repository description",
    level="error",
)
def _missing_description(repo: Repository) -> RESULT:
    if repo.description:
        return OK
    return FAIL


@define_rule(
    name="missing-license",
    log_message="Missing license file",
    level="error",
)
def _missing_license(repo: Repository) -> RESULT:
    if repo.visibility == "private":
        return SKIP

    try:
        if repo.get_license():
            return OK
    except GithubException:
        pass
    return FAIL


@define_rule(
    name="non-mit-license",
    log_message="Using non-MIT license",
    level="warning",
)
def _non_mit_license(repo: Repository) -> RESULT:
    if repo.visibility == "private":
        return SKIP
    if repo.license and repo.license.name != "MIT License":
        return FAIL
    return OK


@define_rule(
    name="missing-readme",
    log_message="Missing README file",
    level="error",
)
def _missing_readme(repo: Repository) -> RESULT:
    if _get_readme(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-topics",
    log_message="Missing topics",
    level="error",
)
def _missing_topics(repo: Repository) -> RESULT:
    if len(repo.topics) == 0:
        return FAIL
    return OK


@define_rule(
    name="too-few-topics",
    log_message="Only one topic",
    level="warning",
)
def _too_few_topics(repo: Repository) -> RESULT:
    if len(repo.topics) == 1:
        return FAIL
    return OK


@define_rule(
    name="has-issues",
    log_message="Repository doesn't have Issues enabled",
    level="warning",
)
def _has_issues(repo: Repository) -> RESULT:
    if repo.has_issues:
        return OK
    return FAIL


@define_rule(
    name="no-projects",
    log_message="Repository has Projects enabled",
    level="warning",
)
def _no_projects(repo: Repository) -> RESULT:
    if repo.has_projects:
        return FAIL
    return OK


@define_rule(
    name="no-wiki",
    log_message="Repository has Wiki enabled",
    level="error",
)
def _no_wiki(repo: Repository) -> RESULT:
    if repo.has_wiki:
        return FAIL
    return OK


@define_rule(
    name="no-discussions",
    log_message="Repository has Discussions enabled",
    level="error",
)
def _no_discussions(repo: Repository) -> RESULT:
    if repo.has_discussions:
        return FAIL
    return OK


# Check if repo is larger than 1GB
@define_rule(
    name="git-size",
    log_message="Repository size is too large",
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
    level="error",
)
def _missing_pyproject(repo: Repository) -> RESULT:
    if repo.language != "Python":
        return SKIP
    if _load_pyproject(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-pyproject-project-name",
    log_message="project.name missing in pyproject.toml",
    level="error",
)
def _missing_pyproject_project_name(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if pyproject.get("project", {}).get("name") is None:
        return FAIL
    return OK


def _pyproject_classifiers(repo: Repository) -> set[str]:
    return set(_load_pyproject(repo).get("project", {}).get("classifiers", []))


_MIT_LICENSE_CLASSIFIER = "License :: OSI Approved :: MIT License"


@define_rule(
    name="pyproject-mit-license-classifier",
    log_message="License classifier missing in pyproject.toml",
    level="error",
)
def _pyproject_mit_license_classifier(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP
    if not repo.license:
        return SKIP
    if repo.license.name != "MIT License":
        return SKIP

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
    level="warning",
)
def _pyproject_omit_license(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP
    if not repo.license:
        return SKIP
    if repo.license.name != "MIT License":
        return SKIP

    if "license" in _load_pyproject(repo).get("project", {}):
        return FAIL
    return OK


@define_rule(
    name="pyproject-author-name",
    log_message="project.authors[0].name missing in pyproject.toml",
    level="warn",
)
def _pyproject_author_name(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if len(_pyproject_author_names(repo)) == 0:
        return FAIL
    return OK


@define_rule(
    name="pyproject-omit-author-email",
    log_message="project.authors[0].email should be omitted for privacy",
    level="warning",
)
def _pyproject_omit_author_email(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if len(_pyproject_author_emails(repo)) > 0:
        return FAIL
    return OK


@define_rule(
    name="pyproject-readme",
    log_message="project.readme missing in pyproject.toml",
    level="error",
)
def _pyproject_readme(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if pyproject.get("project", {}).get("readme") is None:
        return FAIL
    return OK


def _pyproject_requires_python(repo: Repository) -> str:
    return cast(
        str, _load_pyproject(repo).get("project", {}).get("requires-python", "")
    )


@define_rule(
    name="missing-pyproject-requires-python",
    log_message="project.requires-python missing in pyproject.toml",
    level="error",
)
def _missing_pyproject_requires_python(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if _pyproject_requires_python(repo):
        return OK
    return FAIL


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
    level="error",
)
def _pyproject_dependency_lower_bound(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    for dep in _pyproject_all_dependencies(repo):
        if not _pydep_has_lower_bound(dep):
            return FAIL
    return OK


@define_rule(
    name="pyproject-optional-dependencies-name",
    log_message="pyproject optional-dependencies should be named 'dev'",
    level="warning",
)
def _project_optional_dependencies_name(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    deps = pyproject.get("project", {}).get("optional-dependencies", {})
    if not deps:
        return OK
    if list(deps.keys()) != ["dev"]:
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
    level="error",
)
def _missing_pyproject_ruff_isort_rules(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if "I" in _ruff_extend_select(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-pyproject-ruff-pyupgrade-rules",
    log_message="tool.ruff.lint.extend-select missing 'UP' to enable pyupgrade rules",
    level="error",
)
def _missing_pyproject_ruff_pyupgrade_rules(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

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
    level="error",
)
def _mypy_strict_declared(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if _mypy_strict(repo) is None:
        return FAIL
    return OK


@define_rule(
    name="mypy-strict",
    log_message="mypy strict mode is not enabled",
    level="warning",
)
def _mypy_strict_enabled(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if _mypy_strict(repo) is False:
        return FAIL
    return OK


@define_rule(
    name="requirements-txt-exact",
    log_message="Use exact versions in requirements.txt",
    level="error",
)
def _requirements_txt_exact(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP
    if _requirements_txt_is_exact(repo) is False:
        return FAIL
    return OK


@define_rule(
    name="requirements-txt-uv-compiled",
    log_message="requirements.txt is not compiled by uv",
    level="warning",
)
def _requirements_txt_uv_compiled(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP
    if "uv pip compile" in _requirements_txt(repo):
        return OK
    return FAIL


@cache
def _has_requirements_txt(repo: Repository) -> bool:
    if _get_contents(repo, path="requirements.txt"):
        return True
    return False


@cache
def _requirements_txt(repo: Repository) -> str:
    return _get_contents_text(repo, path="requirements.txt")


@cache
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
def _requirements_txt_has_types(repo: Repository) -> bool:
    if text := _requirements_txt(repo):
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "types-" in line:
                return True
        return False
    else:
        return False


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
    name="delete-branch-on-merge",
    log_message="Repository should delete branches on merge",
    level="error",
)
def _delete_branch_on_merge(repo: Repository) -> RESULT:
    if repo.delete_branch_on_merge:
        return OK
    return FAIL


@define_rule(
    name="allow-auto-merge",
    log_message="Repository should allow auto-merge",
    level="warning",
)
def _auto_merge(repo: Repository) -> RESULT:
    if repo.fork:
        return SKIP
    if not _dependabot_config(repo):
        return SKIP
    if repo.allow_auto_merge:
        return OK
    return FAIL


@define_rule(
    name="enable-merge-commit",
    log_message="Repository should allow merge commits",
    level="warning",
)
def _enable_merge_commit(repo: Repository) -> RESULT:
    if repo.allow_merge_commit:
        return OK
    return FAIL


@define_rule(
    name="disable-squash-merge",
    log_message="Repository should not allow squash merging",
    level="warning",
)
def _disable_squash_merge(repo: Repository) -> RESULT:
    if not repo.allow_squash_merge:
        return OK
    return FAIL


@define_rule(
    name="disable-rebase-merge",
    log_message="Repository should not allow rebase merging",
    level="warning",
)
def _disable_rebase_merge(repo: Repository) -> RESULT:
    if not repo.allow_rebase_merge:
        return OK
    return FAIL


@define_rule(
    name="dependabot-schedule-monthly",
    log_message="Dependabot should be scheduled monthly",
    level="warning",
)
def _dependabot_schedule_monthly(repo: Repository) -> RESULT:
    if not _dependabot_config(repo):
        return SKIP
    if _dependabot_update_schedule_intervals(repo) != {"monthly"}:
        return FAIL
    return OK


@define_rule(
    name="pip-dependabot",
    log_message="Dependabot should be enabled for pip ecosystem",
    level="error",
)
def _pip_dependabot(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP
    for update in _dependabot_config(repo).get("updates", []):
        if update.get("package-ecosystem") == "pip":
            return OK
    return FAIL


@define_rule(
    name="pip-dependabot-ignore-types",
    log_message="Dependabot should ignore types-* packages",
    level="warning",
)
def _dependabot_ignores_pip_types(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP

    for update in _dependabot_config(repo).get("updates", []):
        if update.get("package-ecosystem") == "pip":
            for ignored in update.get("ignore", []):
                if ignored.get("dependency-name") == "types-*":
                    return OK

    return FAIL


@define_rule(
    name="no-devcontainer",
    log_message="Avoid using devcontainers",
    level="warning",
)
def _no_devcontainer(repo: Repository) -> RESULT:
    if _get_contents(repo, path=".devcontainer/devcontainer.json"):
        return FAIL
    return OK


@define_rule(
    name="disable-actions",
    log_message="Repository without workflows should disable Actions",
    level="error",
)
def _disable_actions(repo: Repository) -> RESULT:
    if _get_workflow_paths(repo):
        return SKIP
    permissions = _get_actions_permissions(repo)
    if permissions["enabled"]:
        return FAIL
    else:
        return OK


@define_rule(
    name="disable-all-actions",
    log_message="Repository should not allow all actions",
    level="warning",
)
def _actions_allowed_actions_all(repo: Repository) -> RESULT:
    if repo.visibility == "private":
        return SKIP
    permissions = _get_actions_permissions(repo)
    if permissions["enabled"] is False:
        return SKIP
    allowed_actions = permissions.get("allowed_actions")
    if allowed_actions == "all":
        return FAIL
    return OK


@define_rule(
    name="allow-github-owned-actions",
    log_message="Repository allow actions created by GitHub",
    level="error",
)
def _actions_github_owned_allowed(repo: Repository) -> RESULT:
    if not _workflow_step_uses(repo, re.compile("actions/")):
        return SKIP

    permissions = _get_actions_permissions(repo)
    if permissions["enabled"] is False:
        return SKIP
    elif permissions.get("allowed_actions") == "all":
        return OK
    elif permissions.get("allowed_actions") == "local_only":
        return FAIL
    elif permissions.get("allowed_actions") == "selected":
        selected_actions = _get_repo_actions_selected_actions(repo)
        if selected_actions["github_owned_allowed"]:
            return OK
        else:
            return FAIL
    else:
        return OK


def _allow_org_owned_actions(repo: Repository, trusted_org: str) -> RESULT:
    org_pattern = re.compile(f"{trusted_org}/")
    if not _workflow_step_uses(repo, org_pattern):
        return SKIP
    permissions = _get_actions_permissions(repo)
    if permissions["enabled"] is False:
        return SKIP
    elif permissions.get("allowed_actions") == "all":
        return OK
    elif permissions.get("allowed_actions") == "local_only":
        return FAIL
    elif permissions.get("allowed_actions") == "selected":
        selected_actions = _get_repo_actions_selected_actions(repo)
        if f"{trusted_org}/*" in selected_actions["patterns_allowed"]:
            return OK
        else:
            return FAIL
    else:
        return OK


@define_rule(
    name="allow-astral-owned-actions",
    log_message="Repository allow actions created by astral-sh",
    level="error",
)
def _allow_astral_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "astral-sh")


@define_rule(
    name="allow-aws-owned-actions",
    log_message="Repository allow actions created by aws-actions",
    level="error",
)
def _allow_aws_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "aws-actions")


@define_rule(
    name="allow-dependabot-owned-actions",
    log_message="Repository allow actions created by dependabot",
    level="error",
)
def _allow_dependabot_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "dependabot")


@define_rule(
    name="allow-docker-owned-actions",
    log_message="Repository allow actions created by docker",
    level="error",
)
def _allow_docker_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "docker")


@define_rule(
    name="allow-determinate-systems-owned-actions",
    log_message="Repository allow actions created by DeterminateSystems",
    level="error",
)
def _allow_determinate_systems_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "DeterminateSystems")


@define_rule(
    name="allow-cachix-owned-actions",
    log_message="Repository allow actions created by cachix",
    level="error",
)
def _allow_cachix_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "cachix")


@define_rule(
    name="default-workflow-permissions",
    log_message="Actions should default to read permissions",
    level="error",
)
def _default_workflow_permissions(repo: Repository) -> RESULT:
    if repo.fork:
        return SKIP
    if not _get_actions_permissions(repo)["enabled"]:
        return SKIP
    permissions = _get_workflow_permissions(repo)
    if permissions["default_workflow_permissions"] == "write":
        return FAIL
    return OK


@define_rule(
    name="allow-actions-approve-prs",
    log_message="Allow Actions to approve pull request reviews",
    level="warning",
)
def _allow_actions_approve_prs(repo: Repository) -> RESULT:
    if repo.fork:
        return SKIP
    if not _get_actions_permissions(repo)["enabled"]:
        return SKIP
    permissions = _get_workflow_permissions(repo)
    if permissions["can_approve_pull_request_reviews"]:
        return OK
    return FAIL


class RepositoryActionPermissions(TypedDict):
    enabled: bool
    allowed_actions: NotRequired[Literal["all", "local_only", "selected"]]


class RepositoryWorkflowPermissions(TypedDict):
    default_workflow_permissions: Literal["read", "write"]
    can_approve_pull_request_reviews: bool


class RepositorySelectedActions(TypedDict):
    github_owned_allowed: bool
    verified_allowed: bool
    patterns_allowed: list[str]


@cache
def _get_actions_permissions(repo: Repository) -> RepositoryActionPermissions:
    _, data = repo._requester.requestJsonAndCheck(
        "GET", f"{repo.url}/actions/permissions"
    )
    return cast(RepositoryActionPermissions, data)


@cache
def _get_repo_actions_selected_actions(repo: Repository) -> RepositorySelectedActions:
    _, data = repo._requester.requestJsonAndCheck(
        "GET", f"{repo.url}/actions/permissions/selected-actions"
    )
    return cast(RepositorySelectedActions, data)


@cache
def _get_workflow_permissions(repo: Repository) -> RepositoryWorkflowPermissions:
    _, data = repo._requester.requestJsonAndCheck(
        "GET", f"{repo.url}/actions/permissions/workflow"
    )
    return cast(RepositoryWorkflowPermissions, data)


# TODO: Deprecate this util
@cache
def _get_workflow(repo: Repository, name: str) -> Workflow:
    return _get_workflow_by_path(repo, Path(f".github/workflows/{name}.yml"))


@cache
def _get_workflow_by_path(repo: Repository, path: Path) -> Workflow:
    assert str(path).startswith(".github/workflows/"), path
    contents = _get_contents(repo, path=str(path))
    empty_workflow: Workflow = {
        "name": "",
        "on": "",
        "jobs": {},
    }
    if not contents:
        return empty_workflow
    try:
        workflow = yaml.safe_load(contents.decoded_content.decode("utf-8"))
        # Workaround stupid YAML parsing bug
        if True in workflow:
            workflow["on"] = workflow.pop(True)
        return cast(Workflow, workflow)
    except yaml.YAMLError:
        return empty_workflow


@cache
def _get_workflow_paths(repo: Repository) -> list[Path]:
    paths: list[Path] = []
    for path in _ls_tree(repo):
        if (
            len(path.parts) == 3
            and path.parts[0] == ".github"
            and path.parts[1] == "workflows"
        ):
            assert path.suffix == ".yml" or path.suffix == ".yaml"
            paths.append(path)
    return paths


def _iter_workflow_jobs(repo: Repository) -> Iterator[tuple[str, WorkflowJob]]:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        yield from workflow.get("jobs", {}).items()


def _iter_workflow_steps(repo: Repository) -> Iterator[WorkflowStep]:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        for job in workflow.get("jobs", {}).values():
            yield from job.get("steps", [])


def _job_defined(repo: Repository, workflows: list[str], name: str) -> bool:
    for workflow in workflows:
        if name in _get_workflow(repo, workflow).get("jobs", {}):
            return True
    return False


def _any_job_defined(repo: Repository, job_name: str) -> bool:
    for name, _ in _iter_workflow_jobs(repo):
        if name == job_name:
            return True
    return False


def _workflow_step_uses(repo: Repository, pattern: re.Pattern[str]) -> bool:
    for step in _iter_workflow_steps(repo):
        step_uses = step.get("uses", "")
        if re.match(pattern, step_uses):
            return True
    return False


@define_rule(
    name="use-uv-pip",
    log_message="Use uv to install pip dependencies",
    level="warning",
)
def _use_uv_pip(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP

    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("pip install", run) and not re.search("uv pip install", run):
            return FAIL

    return OK


@define_rule(
    name="setup-uv",
    log_message="Use astral-sh/setup-uv",
    level="error",
)
def _setup_uv(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("pipx install uv", run):
            return FAIL
    return OK


@define_rule(
    name="uv-pip-install-with-requirements",
    log_message="Use uv pip install with requirements.txt",
    level="error",
)
def _uv_pip_install_with_requirements(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP

    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("uv pip install", run) and not re.search("requirements.txt", run):
            return FAIL

    return OK


@define_rule(
    name="setup-python-with-python-version-file",
    log_message="setup-python should use pyproject.toml",
    level="error",
)
def _setup_python_with_python_version_file(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        if not step.get("uses", "").startswith("actions/setup-python"):
            continue
        if "matrix" in step.get("with", {}).get("python-version", ""):
            continue
        if step.get("with", {}).get("python-version-file", "") != "pyproject.toml":
            return FAIL

    return OK


@define_rule(
    name="disable-setup-python-cache",
    log_message="setup-python cache should be disabled when using uv",
    level="error",
)
def _disable_setup_python_cache(repo: Repository) -> RESULT:
    for name, job in _iter_workflow_jobs(repo):
        if not _job_uses_uv(job):
            continue

        for step in job.get("steps", []):
            if step.get("uses", "").startswith("actions/setup-python"):
                if step.get("with", {}).get("cache", None) is not None:
                    return FAIL

    return OK


def _job_uses_uv(job: WorkflowJob) -> bool:
    for step in job.get("steps", []):
        if re.search("uv ", step.get("run", "")):
            return True
    return False


@define_rule(
    name="missing-ruff",
    log_message="Missing GitHub Actions workflow for ruff linting",
    level="error",
)
def _missing_ruff_error(repo: Repository) -> RESULT:
    if repo.language != "Python":
        return SKIP

    for step in _iter_workflow_steps(repo):
        if re.search("ruff ", step.get("run", "")):
            return OK

    return OK


@define_rule(
    name="missing-ruff",
    log_message="Missing GitHub Actions workflow for ruff linting",
    level="warning",
)
def _missing_ruff_warning(repo: Repository) -> RESULT:
    if ".py" not in _file_extnames(repo):
        return SKIP

    for step in _iter_workflow_steps(repo):
        if re.search("ruff ", step.get("run", "")):
            return OK

    return OK


class RepositoryRulesetRequiredStatusCheck(TypedDict):
    context: str


class RepositoryRulesetRequiredStatusChecksParameters(TypedDict):
    required_status_checks: list[RepositoryRulesetRequiredStatusCheck]


class RepositoryRulesetRequiredStatusChecks(TypedDict):
    type: Literal["required_status_checks"]
    parameters: RepositoryRulesetRequiredStatusChecksParameters


RepositoryRuleset = RepositoryRulesetRequiredStatusChecks


@cache
def _get_repo_rulesets(
    repo: Repository, branch: str = "main"
) -> list[RepositoryRuleset]:
    _, data = repo._requester.requestJsonAndCheck(
        "GET", f"{repo.url}/rules/branches/{branch}"
    )
    return cast(list[RepositoryRuleset], data)


def _required_status_check(repo: Repository, job_name: str) -> RESULT:
    if not _any_job_defined(repo, job_name):
        return SKIP

    for ruleset in _get_repo_rulesets(repo):
        if ruleset["type"] == "required_status_checks":
            for check in ruleset["parameters"]["required_status_checks"]:
                if check["context"] == job_name:
                    return OK
    return FAIL


@define_rule(
    name="required-test-status-check",
    log_message="Add Ruleset to require 'test' status check",
    level="warning",
)
def _required_test_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "test")


@define_rule(
    name="required-ruff-status-check",
    log_message="Add Ruleset to require 'ruff' status check",
    level="warning",
)
def _required_ruff_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "ruff")


@define_rule(
    name="missing-mypy",
    log_message="Missing GitHub Actions workflow for mypy type checking",
    level="error",
)
def _missing_mypy(repo: Repository) -> RESULT:
    if repo.language != "Python":
        return SKIP

    for step in _iter_workflow_steps(repo):
        if re.search("mypy ", step.get("run", "")):
            return OK

    return OK


@define_rule(
    name="required-mypy-status-check",
    log_message="Add Ruleset to require 'mypy' status check",
    level="warning",
)
def _required_mypy_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "mypy")


@define_rule(
    name="missing-shfmt",
    log_message="Missing GitHub Actions workflow for shfmt linting",
    level="warning",
)
def _missing_shfmt(repo: Repository) -> RESULT:
    if ".sh" not in _file_extnames(repo):
        return SKIP

    for step in _iter_workflow_steps(repo):
        if re.search("shfmt ", step.get("run", "")):
            return OK

    return FAIL


@define_rule(
    name="required-shfmt-status-check",
    log_message="Add Ruleset to require 'shfmt' status check",
    level="warning",
)
def _required_shfmt_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "shfmt")


@define_rule(
    name="missing-shellcheck",
    log_message="Missing GitHub Actions workflow for shellcheck linting",
    level="warning",
)
def _missing_shellcheck(repo: Repository) -> RESULT:
    if ".sh" not in _file_extnames(repo):
        return SKIP

    for step in _iter_workflow_steps(repo):
        if re.search("shellcheck ", step.get("run", "")):
            return OK

    return FAIL


@define_rule(
    name="required-shellcheck-status-check",
    log_message="Add Ruleset to require 'shellcheck' status check",
    level="warning",
)
def _required_shellcheck_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "shellcheck")


@define_rule(
    name="git-commit-name",
    log_message="Git commit name to github-actions",
    level="error",
)
def _git_commit_name(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("git config", run) and re.search("user.name", run):
            if not re.search("github-actions\\[bot\\]", run):
                return FAIL
    return OK


@define_rule(
    name="git-commit-email",
    log_message="Git commit email to github-actions",
    level="error",
)
def _git_commit_email(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("git config", run) and re.search("user.email", run):
            if not re.search(
                "41898282\\+github-actions\\[bot\\]@users\\.noreply\\.github\\.com", run
            ):
                return FAIL
    return OK


@define_rule(
    name="github-pat",
    log_message="Avoid using GitHub PAT in Actions",
    level="warning",
)
def _github_pat(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        env: dict[str, str] = step.get("env", {})
        for name, value in env.items():
            if value == "${{ secrets.GH_TOKEN }}":
                return FAIL

    return OK


@define_rule(
    name="no-workflow-env-secrets",
    log_message="Do not expose secrets to entire workflow environment",
    level="warning",
)
def _no_workflow_env_secrets(repo: Repository) -> RESULT:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        env = workflow.get("env", {})
        for value in env.values():
            if "${{ secrets." in value:
                return FAIL
    return OK


@define_rule(
    name="no-job-env-secrets",
    log_message="Do not expose secrets to entire job environment",
    level="warning",
)
def _no_job_env_secrets(repo: Repository) -> RESULT:
    for _, job in _iter_workflow_jobs(repo):
        env = job.get("env", {})
        for value in env.values():
            if "${{ secrets." in value:
                return FAIL
    return OK


@define_rule(
    name="wip-gh-pages-branch",
    log_message="Avoid using gh-pages branch",
    level="warning",
)
def _gh_pages_branch(repo: Repository) -> RESULT:
    for branch in repo.get_branches():
        if branch.name == "gh-pages":
            return FAIL
    return OK


@define_rule(
    name="on-push-only",
    log_message="Don't trigger workflow on pull_request",
    level="error",
)
def _on_push_only(repo: Repository) -> RESULT:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        on: str | list[str] | dict[str, Any] = cast(Any, workflow).get("on", {})
        if on == "pull_request":
            return FAIL
        if isinstance(on, list) and "pull_request" in on:
            return FAIL
        if isinstance(on, dict) and "pull_request" in on:
            return FAIL
    return OK


@define_rule(
    name="git-push-concurrency-group",
    log_message="Jobs that use git push must be in a concurrency group",
    level="error",
)
def _git_push_concurrency_group(repo: Repository) -> RESULT:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        workflow_has_concurrency_group = "concurrency" in workflow

        for name, job in workflow.get("jobs", {}).items():
            job_has_concurrency_group = (
                workflow_has_concurrency_group or "concurrency" in job
            )
            job_has_git_push = False
            for step in job.get("steps", []):
                if re.search("git push", step.get("run", "")):
                    job_has_git_push = True
            if job_has_git_push and not job_has_concurrency_group:
                return FAIL
    return OK


@define_rule(
    name="git-push-if-commited",
    log_message="git push step should only run if changes are commited",
    level="error",
)
def _git_push_if_commited(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("git push", run) and "if" not in step:
            return FAIL
    return OK


@define_rule(
    name="enable-write-contents-permission",
    log_message="Workflows using git push must have contents write permission",
    level="error",
)
def _enable_write_contents_permission(repo: Repository) -> RESULT:
    if not _get_actions_permissions(repo)["enabled"]:
        return SKIP

    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        workflow_has_write_permission = (
            workflow.get("permissions", {}).get("contents") == "write"
        )

        for job in workflow.get("jobs", {}).values():
            job_has_write_permission = (
                job.get("permissions", {}).get("contents") == "write"
            )
            has_write_permission = (
                job_has_write_permission or workflow_has_write_permission
            )
            uses_git_push = _workflow_job_uses_git_push(job)
            if uses_git_push and not has_write_permission:
                return FAIL

    return OK


def _workflow_job_uses_git_push(job: WorkflowJob) -> bool:
    for step in job.get("steps", []):
        step_run = step.get("run", "")
        if re.search("git push", step_run):
            return True
    return False


@define_rule(
    name="dependabot-github-actions",
    log_message="Dependabot should be enabled for GitHub Actions if workflows are present",
    level="error",
)
def _github_actions_dependabot(repo: Repository) -> RESULT:
    if not _has_workflow_files(repo):
        return SKIP
    for update in _dependabot_config(repo).get("updates", []):
        if update.get("package-ecosystem") == "github-actions":
            return OK
    return FAIL


@cache
def _has_workflow_files(repo: Repository) -> bool:
    for path in _ls_tree(repo):
        if str(path).startswith(".github/workflows/"):
            return True
    return False


if __name__ == "__main__":
    main()
