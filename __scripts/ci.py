from __future__ import annotations

import atexit
import difflib
import getpass
import json
import os
import platform
import shutil
from pathlib import Path
from time import sleep
from typing import Callable
from typing import Final
from typing import Iterator
from urllib import request
from urllib.error import URLError
from urllib.parse import quote

import click
import yaml
from github import Github
from github import UnknownObjectException
from github.Issue import Issue
from github.Label import Label
from github.PullRequest import PullRequest
from github.Repository import Repository
from github.Tag import Tag
from semver import VersionInfo

from .utils import console
from .utils import execute
from .utils import generate_yaml
from .utils import get_checkmk_raw_tags_since
from .utils import get_click_silent_option
from .utils import get_click_verbosity_option
from .utils import init_logger
from .utils import logger
from .utils import on_rm_error
from .utils import replace_text_between

SERVER_MASTER_BRANCH: str = "master"
SERVER_PR_BRANCH: str = "checkmk_server_version-autoupdate"
AGENT_MASTER_BRANCH: str = "master"
AGENT_PR_BRANCH: str = "checkmk_agent_version-autoupdate"

SERVER_REPO_FILES: list[str] = ["defaults/main.yml", "README.orig.adoc"]
AGENT_REPO_FILES: list[str] = ["defaults/main.yml", "README.orig.adoc"]

FIND_MISSING_RELEASE_BASE_TITLE: Final[
    str
] = "[check-new-versions.yml] Please create a new release"

__script_executor_origin = "(could not resolve ip address location)"
try:
    _origin = json.load(
        request.urlopen("https://geolocation-db.com/json/&position=true")
    )
    __script_executor_origin = _origin["city"]
except (URLError, json.JSONDecodeError):
    pass
SCRIPT_MSG: str = (
    ":robot: *Authored by `__scripts/ci.py` python script "
    f"on {platform.node()} by {getpass.getuser()} from {__script_executor_origin}* "
)


def unidiff_output(expected: str, actual: str):
    """Returns a string containing the unified diff of two multiline
    strings."""
    diff: Iterator[str] = difflib.unified_diff(
        expected.splitlines(keepends=True), actual.splitlines(keepends=True)
    )

    return "".join(diff)


def clone_repo_and_checkout_branch(
    repo: Repository, repo_path: Path, branch: str
) -> tuple[str, Callable[..., object]]:
    if not repo_path.joinpath(".git").exists():
        execute(["git", "clone", repo.clone_url], repo_path.parent)
    if "AUTO_UPDATE_PAT" in os.environ:
        logger.notice(
            "Detected AUTO_UPDATE_PAT. Changing 'origin' to https://x-access-token:…"
        )
        execute(
            [
                "git",
                "remote",
                "set-url",
                "origin",
                f"https://x-access-token:{ os.environ['AUTO_UPDATE_PAT'] }"
                f"@github.com/{repo.full_name}",
            ],
            repo_path,
        )

    # https://git-blame.blogspot.com/2013/06/checking-current-branch-programatically.html
    _git_branch_before = (
        execute(["git", "symbolic-ref", "--short", "-q", "HEAD"], repo_path)
        .replace("refs/heads/", "")
        .strip()
    )

    if _git_branch_before != branch:
        execute(["git", "fetch"], repo_path)
        execute(["git", "checkout", branch], repo_path)

    def atexit_handler() -> None:
        logger.notice(
            "The program terminated unexpectedly! "
            f"Checking out the {repo_path.name} branch "
            "we were previously on..."
        )
        execute(["git", "checkout", _git_branch_before], repo_path)

    atexit.register(atexit_handler)

    return _git_branch_before, atexit_handler


def get_prefilled_new_release_url(
    repo: Repository,
    master: str,
    repo_other: Repository,
    new_version: str,
    new_tag: str,
    new_tag_other: str,
):
    # note: 'body' param must come last to be able to make additions
    return f"{repo.html_url}/releases/new" f"?tag=" + quote(
        new_tag
    ) + "&target=" + quote(master) + "&title=" + quote(
        f"update default to {new_version}"
    ) + "&body=" + quote(
        f"Accompanying `{repo_other.name}` release: "
        f"[{new_tag_other}]"
        f"(https://github.com/{repo_other.full_name}/releases/tag"
        f"/{new_tag_other}%)"
    )


def close_missing_release_issues(
    repo: Repository,
    latest_released_role_tag: Tag,
    current_checkmk_version: str,
    dry_run: bool,
):
    for issue in repo.get_issues(state="open"):
        if FIND_MISSING_RELEASE_BASE_TITLE not in issue.title:
            continue
        if dry_run:
            logger.info(
                f"Would've closed {issue} of {repo} with a comment "
                "as the default checkmk version in the latest role "
                "release matches the current version! "
            )
            continue
        logger.info(
            f"Closing {issue} of {repo} as the default checkmk version "
            "in the latest role release matches the current version! "
        )
        issue.create_comment(
            "Closing this Issue as the default checkmk version "
            f"defined in the latest release ([{latest_released_role_tag.name}]"
            f"({latest_released_role_tag.commit.html_url})) "
            f"now matches the current check version of {current_checkmk_version}! "
            f"\n\n {SCRIPT_MSG}"
        )
        issue.edit(state="closed")


def create_or_update_missing_release_issue(
    repo: Repository,
    latest_released_role_tag: Tag,
    latest_released_checkmk_version: str,
    current_checkmk_version: str,
    next_role_tag_create_url: str,
    dry_run: bool,
):
    GENERAL_BODY = (
        "The default checkmk version has recently been updated "
        f"from {latest_released_checkmk_version} "
        f"(in [{latest_released_role_tag.name}]"
        f"({latest_released_role_tag.commit.html_url})) "
        f"to {current_checkmk_version}, "
        "but no new GitHub release/tag has been created for it. "
    )
    BODY_TIP = (
        "\n\n"
        "Automated Version Updating is halted until a new version is released. "
        "Please use the following link as a starting point "
        "for creating the new release: \n"
        f"> {next_role_tag_create_url}"
    )
    ISSUE_BODY = GENERAL_BODY + BODY_TIP
    logger.error(ISSUE_BODY.replace("\n\n", ""))
    ISSUE_BODY += f"\n\n {SCRIPT_MSG}"

    found_issue: Issue | None = None
    for issue in repo.get_issues(state="all"):
        if (
            FIND_MISSING_RELEASE_BASE_TITLE in issue.title
            and current_checkmk_version in issue.title
        ):
            if found_issue is not None:
                logger.error(
                    "Found more than one "
                    f"'missing release {current_checkmk_version}' issues?! "
                    f"{issue} {found_issue}"
                )
                exit(1)
            found_issue = issue

    ACTUAL_ISSUE_TITLE = (
        FIND_MISSING_RELEASE_BASE_TITLE + f" for {current_checkmk_version}"
    )
    __issue_params = {"title": ACTUAL_ISSUE_TITLE, "body": ISSUE_BODY}
    if found_issue is None:
        if not dry_run:
            found_issue = repo.create_issue(
                **__issue_params, assignee=repo.owner, labels=[]
            )
            logger.info(
                "Created 'missing release issue' "
                f"{found_issue.html_url} ({__issue_params})"
            )
        else:
            logger.info(f"Would've created 'missing release issue' {__issue_params}")
    else:
        __issue_change_log = (
            "\n"
            + unidiff_output(found_issue.title, ACTUAL_ISSUE_TITLE)
            + "\n"
            + unidiff_output(found_issue.body, ISSUE_BODY)
        )
        if not dry_run:
            logger.info(
                "Editing 'missing release issue' "
                f"{found_issue.html_url}... {__issue_change_log}"
            )
            found_issue.edit(
                **__issue_params,
                assignee=repo.owner,
                state="open",
                labels=[],
            )
        else:
            logger.info(
                "Would've edited 'missing release issue' "
                f"{found_issue.html_url} {__issue_change_log}"
            )

    # close PRs
    open_version_change_prs: list[PullRequest] = []
    for pr in repo.get_pulls():
        pr_files = pr.get_files()
        for file in filter(
            lambda f: any(s == f.filename for s in SERVER_REPO_FILES), pr_files
        ):
            if "version: " in file.patch:
                open_version_change_prs.append(pr)
                break  # file loop

    for pr in open_version_change_prs:
        if dry_run:
            logger.info(
                f"Would've closed {pr} of {repo} because of "
                "release and current version mismatch error..."
            )
            continue
        logger.info(
            f"Closing {pr} of {repo} as the default checkmk version "
            f"in the latest role release does not match the current version! "
            f"May reopen again when {found_issue.html_url} is resolved. "
        )
        labels: list[Label | str] = pr.labels
        if not any("do-not-merge" == str(label) for label in labels):
            try:
                labels.append(repo.get_label("do-not-merge"))
            except UnknownObjectException:
                logger.warning(f"Could not find 'do-not-merge' label in {repo}.")
        _opt = "**Please re-open this PR if said Issue has been resolved.**"
        if ":robot:" not in pr.body:
            _opt = (
                "*This PR will re-open itself automatically on a new ci.py run "
                "once said Issue has been resolved!*"
            )
        pr.set_labels(*labels)
        pr.create_issue_comment(
            GENERAL_BODY + "\n\n"
            "Closing this pull request until "
            f"#{found_issue.number} has been resolved! {_opt}"
            f"\n\n{SCRIPT_MSG}"
        )
        pr.edit(state="closed")


def checkout_pristine_pr_branch(
    repo_path: Path, pr_branch: str, before_branch: str, files: list[str]
) -> None:
    _git_status_before = execute(["git", "status", "--porcelain"], repo_path)
    if any(s in _git_status_before for s in files):
        logger.error("Working directory is not clean! Aborting...")
        exit(1)

    # ENSURE PRISTINE BRANCH
    if f"/refs/heads/{pr_branch}" in execute(
        ["git", "ls-remote", "--heads"], repo_path
    ):
        logger.notice(
            f"Branch '{pr_branch}' already exists on remote "
            f"of {repo_path.name}. "
            f"Note that this script will force-overwrite it "
            f"to accomodate potentially changed script behaviour."
        )
        sleep(5)
    else:
        # may possibly exist locally:
        execute(
            ["git", "branch", "-D", pr_branch], repo_path, is_real_error=lambda _: False
        )
        execute(["git", "branch", pr_branch], repo_path)

    execute(["git", "fetch"], repo_path)
    execute(["git", "checkout", pr_branch], repo_path)

    execute(["git", "reset"], repo_path)
    for f in files:
        execute(["git", "checkout", "HEAD", "--", f], repo_path)


def commit_push_and_checkout_before(
    repo_path: Path,
    pr_branch: str,
    before_branch: str,
    files: list[str],
    dry_run: bool,
    atexit_handler: Callable[..., object],
    commit_title: str,
    script_msg: str,
    description: str,
):
    _git_status = execute(["git", "status", "--porcelain"], repo_path)
    if _git_status != "":
        for f in files:
            execute(["git", "add", f], repo_path)
        execute(
            ["git", "commit", "-m", commit_title, "-m", script_msg, "-m", description],
            repo_path,
        )
    if not dry_run:
        execute(
            ["git", "push", "--force", "--set-upstream", "origin", pr_branch],
            repo_path,
        )

    # eliminate windows bug
    for f in files:
        execute(["git", "add", f], repo_path)

    logger.verbose(f"Checking out previous branch of {repo_path.name} again..")
    execute(["git", "checkout", before_branch], repo_path)

    atexit.unregister(atexit_handler)


def get_sorted_semver_tags(repo: Repository) -> list[tuple[Tag, VersionInfo]]:
    """Query given repository and return list of tags that represent valid
    semantic versions strings.

    :param repo:
        `GitHub.Repository` Object used to query tags from GitHub's API
    :return:
        A list of tuples in which the first (0) item is the `github.Tag`
        and the second (1) item is a `VersionInfo` object that has
        been crufted by using the tag's name.
        The list is sorted so the latest version will always be on top ([0]).
    """
    tags_since: list[tuple[Tag, VersionInfo]] = []
    for tag in repo.get_tags():
        # https://galaxy.ansible.com/docs/contributing/version.html
        if not VersionInfo.is_valid(tag.name):
            logger.debug(
                f"Tag '{tag.name}' of '{repo.name}' does not match SemVer. "
                "Skipping.."
            )
            continue
        tags_since.append((tag, VersionInfo.parse(tag.name)))
    # sort using VersionInfo's dunders
    return sorted(tags_since, key=lambda tup: tup[1], reverse=True)


def find_pr(
    repo: Repository, branch: str, loose_str: str, next_checkmk_server_version: Tag
) -> PullRequest | None:
    pull_requests = repo.get_pulls(state="open")
    found_pr: PullRequest | None = None
    for pr in pull_requests:
        if pr.head.ref == branch and loose_str in pr.title:
            if found_pr is None:
                logger.info(f"Found open ci.py PR in {repo.name}: {pr}.")
                found_pr = pr
                continue
            logger.warning(
                f"Found more than one open ci.py PRs in {repo.name} "
                f"({found_pr}, {pr})?? Aborting..."
            )
            exit(1)

    if found_pr is not None and next_checkmk_server_version.name not in found_pr.title:
        logger.warning(
            f"{found_pr} of {repo} seems to have been created by ci.py "
            f"but it's title does not contain "
            f"'{next_checkmk_server_version.name}'! Aborting..."
        )
        exit(1)
    return found_pr


def write_and_log(file: Path, old_content: str, new_content: str):
    _server_defaults_yml_contents_diff: str = unidiff_output(old_content, new_content)
    logger.verbose(f"Unidiff of '{file}': \n" + _server_defaults_yml_contents_diff)
    file.write_text(new_content, encoding="utf-8")


def _get_server_change_notes(
    default_yml_contents_old: str, default_yml_contents_new: str
) -> list[str]:
    _retv: list[str] = []
    parsed_default_yml_contents_old = yaml.safe_load(default_yml_contents_old)
    parsed_default_yml_contents_new = yaml.safe_load(default_yml_contents_new)

    _old_checksums = parsed_default_yml_contents_old[
        "_checkmk_server_download_checksum"
    ]
    _new_checksums = parsed_default_yml_contents_new[
        "_checkmk_server_download_checksum"
    ]

    for key, checksum_new in _new_checksums.items():
        checksum_old = _old_checksums.get(key, "NONE")

        if checksum_new == "None" and checksum_old != "None":
            logger.debug("1")
            _retv.append(f"CheckMk dropped support for {key}")
        elif checksum_new != "None" and checksum_old == "NOT_EXISTENT":
            logger.debug("2")
            _retv.append(f"Added checksum for {key}")
        elif checksum_new != "None" and checksum_old == "None":
            logger.debug("3")
            _retv.append(f"CheckMk Added support for {key}")

    for key, checksum_old in _old_checksums.items():
        checksum_new = _new_checksums.get(key, "NOT_EXISTENT")
        if checksum_old == "None" and checksum_new == "NOT_EXISTENT":
            logger.debug("4")
            _retv.append(f"Dropped support for {key} by removing checksum")

    return _retv


def _make_server_changes(
    server_repo_path: Path, next_checkmk_server_version: Tag
) -> list[str]:
    default_yml: Path = server_repo_path.joinpath("defaults/main.yml")
    default_yml_contents_old: str = default_yml.read_text(encoding="utf8")
    default_yml_contents_new: str = replace_text_between(
        default_yml_contents_old,
        "# ===== BEGIN generate_yaml MANAGED SECTION",
        "# ===== END generate_yaml MANAGED SECTION",
        f"\n\n{generate_yaml(next_checkmk_server_version.name)}\n",
    )
    write_and_log(
        default_yml,
        default_yml_contents_old,
        default_yml_contents_new,
    )

    readme: Path = server_repo_path.joinpath("README.orig.adoc")
    readme_contents_old: str = readme.read_text(encoding="utf8")
    readme_contents_new: str = replace_text_between(
        readme_contents_old,
        'checkmk_server_version: "',
        '"',
        next_checkmk_server_version.name.replace("v", ""),
    )
    write_and_log(readme, readme_contents_old, readme_contents_new)
    return _get_server_change_notes(default_yml_contents_old, default_yml_contents_new)


def _make_agent_changes(agent_repo_path: Path, next_checkmk_server_version: Tag):
    default_yml: Path = agent_repo_path.joinpath("defaults/main.yml")
    default_yml_contents_old: str = default_yml.read_text(encoding="utf8")
    default_yml_contents_new: str = replace_text_between(
        default_yml_contents_old,
        "# ===== BEGIN generate_yaml MANAGED SECTION",
        "# ===== END generate_yaml MANAGED SECTION",
        "\ncheckmk_agent_version: "
        + f"{next_checkmk_server_version.name.replace('v', '')}\n",
    )
    write_and_log(
        default_yml,
        default_yml_contents_old,
        default_yml_contents_new,
    )

    readme: Path = agent_repo_path.joinpath("README.orig.adoc")
    readme_contents_old: str = readme.read_text(encoding="utf8")
    readme_contents_new: str = replace_text_between(
        readme_contents_old,
        'checkmk_agent_version: "',
        '"',
        next_checkmk_server_version.name.replace("v", ""),
    )
    write_and_log(readme, readme_contents_old, readme_contents_new)


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@click.option(
    "--dry-run",
    "--dry",
    "dry_run",
    default=False,
    is_flag=True,
    help="Disable pushing changes and do not create any Issues/PRs.",
)
@get_click_verbosity_option()
@get_click_silent_option()
def main(dry_run: bool, silent: bool, verbosity: int) -> None:
    init_logger(verbosity=verbosity, silent=silent)
    _login_or_token = os.environ["GITHUB_TOKEN"]
    github_api: Github = Github(_login_or_token)

    server_repo: Repository = github_api.get_repo(
        "JonasPammer/ansible-role-checkmk_server"
    )
    server_repo_path: Path = Path.cwd()
    (
        server_local_git_branch_before,
        server_atexit_handler,
    ) = clone_repo_and_checkout_branch(
        server_repo, server_repo_path, SERVER_MASTER_BRANCH
    )

    agent_repo: Repository = github_api.get_repo(
        "JonasPammer/ansible-role-checkmk_agent"
    )
    agent_repo_path: Path = server_repo_path.joinpath("__scripts", agent_repo.name)
    if agent_repo_path.exists():
        shutil.rmtree(agent_repo_path, onerror=on_rm_error)
    (
        agent_local_git_branch_before,
        agent_atexit_handler,
    ) = clone_repo_and_checkout_branch(agent_repo, agent_repo_path, AGENT_MASTER_BRANCH)

    server_defaults_yml: Path = server_repo_path.joinpath("defaults/main.yml")
    current_checkmk_server_version = yaml.safe_load(
        server_defaults_yml.read_text(encoding="utf8")
    )["checkmk_server_version"]
    agent_defaults_yml: Path = agent_repo_path.joinpath("defaults/main.yml")
    current_checkmk_agent_version = yaml.safe_load(
        agent_defaults_yml.read_text(encoding="utf8")
    )["checkmk_agent_version"]

    if current_checkmk_server_version != current_checkmk_agent_version:
        # TODO this should create an issue tbh
        logger.fatal(
            "Version mismatch between current checkmk_server_version "
            "and checkmk_agent_version!! Aborting, please fix.."
        )
        exit(1)
    logger.verbose(
        f"{server_repo.name} and {agent_repo.name} have "
        "the same checkmk version! Continuing.."
    )

    tags_since = get_checkmk_raw_tags_since(current_checkmk_server_version, github_api)
    if len(tags_since) == 0:
        console.print(
            "There have been no new CheckMk versions since "
            f"'{current_checkmk_server_version}'."
            "'All good. Doing nothing'."
        )
        exit(0)
    next_checkmk_server_version = tags_since[0]
    next_checkmk_server_version_date = (
        next_checkmk_server_version.commit.commit.committer.date
    )
    _next_checkmk_server_version_compare_url = (
        f"https://github.com/tribe29/checkmk/compare/v{current_checkmk_server_version}"
        f"...{next_checkmk_server_version.name}"
    )
    console.print(
        f"There have been {len(tags_since)} new versions since "
        f"'{current_checkmk_server_version}'! "
        f"Next: '{next_checkmk_server_version.name}'"
    )

    server_role_tags: Final[list[tuple[Tag, VersionInfo]]] = get_sorted_semver_tags(
        server_repo
    )
    agent_role_tags: Final[list[tuple[Tag, VersionInfo]]] = get_sorted_semver_tags(
        agent_repo
    )

    latest_released_checkmk_server_version: str = yaml.safe_load(
        server_repo.get_contents(
            "defaults/main.yml", ref=server_role_tags[0][0].commit.sha
        ).decoded_content
    )["checkmk_server_version"]

    latest_released_checkmk_agent_version: str = yaml.safe_load(
        agent_repo.get_contents(
            "defaults/main.yml", ref=agent_role_tags[0][0].commit.sha
        ).decoded_content
    )["checkmk_agent_version"]

    next_server_role_tag_version: VersionInfo = server_role_tags[0][1].bump_patch()
    next_agent_role_tag_version: VersionInfo = agent_role_tags[0][1].bump_patch()
    next_server_role_tag_create_url: str = get_prefilled_new_release_url(
        server_repo,
        SERVER_MASTER_BRANCH,
        repo_other=agent_repo,
        new_version=next_checkmk_server_version.name,
        new_tag=str(next_server_role_tag_version),
        new_tag_other=str(next_agent_role_tag_version),
    )
    next_agent_role_tag_create_url: str = get_prefilled_new_release_url(
        agent_repo,
        AGENT_MASTER_BRANCH,
        repo_other=server_repo,
        new_version=next_checkmk_server_version.name,
        new_tag=str(next_agent_role_tag_version),
        new_tag_other=str(next_server_role_tag_version),
    )

    _exit: bool = False
    if latest_released_checkmk_server_version != current_checkmk_server_version:
        create_or_update_missing_release_issue(
            server_repo,
            latest_released_role_tag=server_role_tags[0][0],
            latest_released_checkmk_version=latest_released_checkmk_server_version,
            current_checkmk_version=current_checkmk_server_version,
            next_role_tag_create_url=next_server_role_tag_create_url,
            dry_run=True,
        )
        _exit = True
    else:
        close_missing_release_issues(
            server_repo,
            server_role_tags[0][0],
            current_checkmk_server_version,
            dry_run=True,
        )

    if latest_released_checkmk_agent_version != current_checkmk_agent_version:
        create_or_update_missing_release_issue(
            server_repo,
            latest_released_role_tag=agent_role_tags[0][0],
            latest_released_checkmk_version=latest_released_checkmk_agent_version,
            current_checkmk_version=current_checkmk_agent_version,
            next_role_tag_create_url=next_agent_role_tag_create_url,
            dry_run=True,
        )
        exit(1)
    else:
        close_missing_release_issues(
            agent_repo,
            agent_role_tags[0][0],
            current_checkmk_agent_version,
            dry_run=True,
        )
    if _exit:
        exit(1)
    del _exit
    logger.verbose(
        "The checkmk version found in the latest release of both "
        f"{server_repo.name} and {agent_repo.name} match with the "
        "respective currently cloned master one. Continuing..."
    )

    _PR_NOTE1_BASE = (
        "**This PR should result in the release of a new minor version "
        "for this role**! "
        "Please use the following link as a starting point "
        "for creating the new release "
        "(ensure to **click on this link *after* merging this PR**): "
    )
    PR_NOTE2 = ""
    if len(tags_since) > 1:
        PR_NOTE2 += (
            "\n\n"
            f"NOTE: There have been **{len(tags_since)}** new versions since "
            f"{current_checkmk_server_version}. "
            "After this PR has been merged, the github workflow will run again "
            "and a new PR will open semi-immideally. "
            "Please ensure to create a proper tag/release "
            "for **every** merged ci.py PR."
        )
    COMMIT_DESCRIPTION = (
        f"*Release Date of {next_checkmk_server_version.name}: "
        f"{next_checkmk_server_version_date.strftime('%Y-%m-%d')}*"
        "\n"
        "*GitHub Compare URL (for the interested):* "
        f"{_next_checkmk_server_version_compare_url}"
        "\n\n"
    )

    checkout_pristine_pr_branch(
        repo_path=server_repo_path,
        pr_branch=SERVER_PR_BRANCH,
        before_branch=server_local_git_branch_before,
        files=SERVER_REPO_FILES,
    )
    server_change_notes: list[str] = _make_server_changes(
        server_repo_path, next_checkmk_server_version
    )

    if len(server_change_notes) != 0:
        next_server_role_tag_create_url += quote("\n\n Note: \n")
        for note in server_change_notes:
            logger.verbose("Adding NOTE '{note}' to `next_server_role_tag_create_url`.")
            next_server_role_tag_create_url += quote(f"* {note} \n")
    else:
        logger.debug("No additional release notes determined.")

    SERVER_COMMIT_TITLE: str = (
        "refactor: update default checkmk_server_version "
        f"from {current_checkmk_server_version} "
        f"to {next_checkmk_server_version.name} :arrow_up:"
    )
    SERVER_PR_NOTE1 = _PR_NOTE1_BASE + "\n> " + next_server_role_tag_create_url
    SERVER_PR_BODY: str = (
        f"{SCRIPT_MSG} \n\n {COMMIT_DESCRIPTION} \n\n" f"{SERVER_PR_NOTE1} {PR_NOTE2}"
    )
    commit_push_and_checkout_before(
        repo_path=server_repo_path,
        pr_branch=SERVER_PR_BRANCH,
        before_branch=server_local_git_branch_before,
        files=SERVER_REPO_FILES,
        atexit_handler=server_atexit_handler,
        dry_run=dry_run,
        commit_title=SERVER_COMMIT_TITLE,
        script_msg=SCRIPT_MSG,
        description=COMMIT_DESCRIPTION,
    )

    checkout_pristine_pr_branch(
        repo_path=agent_repo_path,
        pr_branch=AGENT_PR_BRANCH,
        before_branch=agent_local_git_branch_before,
        files=AGENT_REPO_FILES,
    )
    _make_agent_changes(agent_repo_path, next_checkmk_server_version)

    AGENT_COMMIT_TITLE: str = (
        "refactor: update default checkmk_agent_version "
        f"from {current_checkmk_agent_version} "
        f"to {next_checkmk_server_version.name} :arrow_up:"
    )
    AGENT_PR_NOTE1 = _PR_NOTE1_BASE + "\n> " + next_agent_role_tag_create_url
    AGENT_PR_BODY: str = (
        f"{SCRIPT_MSG} \n\n {COMMIT_DESCRIPTION} \n\n" f"{AGENT_PR_NOTE1} {PR_NOTE2}"
    )
    commit_push_and_checkout_before(
        repo_path=agent_repo_path,
        pr_branch=AGENT_PR_BRANCH,
        before_branch=agent_local_git_branch_before,
        files=AGENT_REPO_FILES,
        atexit_handler=agent_atexit_handler,
        dry_run=dry_run,
        commit_title=AGENT_COMMIT_TITLE,
        script_msg=SCRIPT_MSG,
        description=COMMIT_DESCRIPTION,
    )

    found_server_pr = find_pr(
        server_repo,
        SERVER_PR_BRANCH,
        "refactor: update default checkmk_server_version",
        next_checkmk_server_version,
    )
    if found_server_pr is None:
        __create_server_pull_params = {
            "title": SERVER_COMMIT_TITLE,
            "body": SERVER_PR_BODY,
            "head": SERVER_PR_BRANCH,
            "base": SERVER_MASTER_BRANCH,
        }
        if not dry_run:
            found_server_pr = server_repo.create_pull(**__create_server_pull_params)
            logger.info(f"Created {server_repo.name} PR: {found_server_pr.html_url}")
        else:
            logger.info(
                f"Would've created {agent_repo.name} PR: {__create_server_pull_params}"
            )

    found_agent_pr = find_pr(
        agent_repo,
        AGENT_PR_BRANCH,
        "refactor: update default checkmk_agent_version",
        next_checkmk_server_version,
    )
    if found_agent_pr is None:
        __create_agent_pull_params = {
            "title": AGENT_COMMIT_TITLE,
            "body": AGENT_PR_BODY,
            "head": AGENT_PR_BRANCH,
            "base": AGENT_MASTER_BRANCH,
        }
        if not dry_run:
            found_agent_pr = agent_repo.create_pull(**__create_agent_pull_params)
            logger.info(f"Created {agent_repo.name} PR: {found_agent_pr.html_url}")
        else:
            logger.info(
                f"Would've created {agent_repo.name} PR: {__create_agent_pull_params}"
            )

    if found_server_pr is not None:
        if found_agent_pr is not None:
            SERVER_PR_BODY += (
                "\n\n---\n"
                f"Accompanying `{agent_repo.name}` PR: " + found_agent_pr.html_url
            )
        __server_pr_change_log = (
            "\n"
            + unidiff_output(found_server_pr.title, SERVER_COMMIT_TITLE)
            + "\n"
            + unidiff_output(found_server_pr.body, SERVER_PR_BODY)
        )
        if not dry_run:
            logger.info(
                f"Editing {found_server_pr.html_url}... {__server_pr_change_log}"
            )
            found_server_pr.edit(
                title=SERVER_COMMIT_TITLE, body=SERVER_PR_BODY, state="open"
            )
        else:
            logger.info(
                f"Would've edited {found_server_pr.html_url} {__server_pr_change_log}"
            )

    if found_agent_pr is not None:
        if found_server_pr is not None:
            AGENT_PR_BODY += (
                "\n\n---\n"
                f"Accompanying `{server_repo.name}` PR: " + found_server_pr.html_url
            )
        __agent_pr_change_log = (
            "\n"
            + unidiff_output(found_agent_pr.title, AGENT_COMMIT_TITLE)
            + "\n"
            + unidiff_output(found_agent_pr.body, AGENT_PR_BODY)
        )
        if not dry_run:
            logger.info(f"Editing {found_agent_pr.html_url}... {__agent_pr_change_log}")
            found_agent_pr.edit(
                title=AGENT_COMMIT_TITLE, body=AGENT_PR_BODY, state="open"
            )
        else:
            logger.info(
                f"Would've edited {found_agent_pr.html_url} {__agent_pr_change_log}"
            )


if __name__ == "__main__":
    main()
