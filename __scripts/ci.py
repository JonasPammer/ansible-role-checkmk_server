from __future__ import annotations

import argparse
import atexit
import difflib
import getpass
import json
import os
import platform
from pathlib import Path
from time import sleep
from typing import Callable
from typing import Iterator
from urllib import request
from urllib.error import URLError

import yaml
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository
from github.Tag import Tag

from .utils import add_argparse_silent_option
from .utils import add_argparse_verbosity_option
from .utils import console
from .utils import execute
from .utils import generate_yaml
from .utils import get_checkmk_raw_tags_since
from .utils import init_logger
from .utils import logger
from .utils import replace_text_between

SERVER_MASTER_BRANCH: str = "master"
SERVER_PR_BRANCH: str = "checkmk_server_version-autoupdate"
AGENT_MASTER_BRANCH: str = "master"
AGENT_PR_BRANCH: str = "checkmk_agent_version-autoupdate"


def unidiff_output(expected: str, actual: str):
    """Returns a string containing the unified diff of two multiline
    strings."""
    diff: Iterator[str] = difflib.unified_diff(
        expected.splitlines(keepends=True), actual.splitlines(keepends=True)
    )

    return "".join(diff)


def clone_repo_and_checkout_branch(
    repo: Repository, repo_path: Path, branch: str
) -> str:
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
    return _git_branch_before


def checkout_pristine_pr_branch(
    repo_path: Path, pr_branch: str, before_branch: str, files: list[str]
) -> Callable[..., object]:
    def atexit_handler() -> None:
        logger.notice(
            "The program terminated unexpectedly! "
            f"Checking out the {repo_path.name} branch "
            "we were previously on..."
        )
        execute(["git", "checkout", before_branch], repo_path)

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
    atexit.register(atexit_handler)

    execute(["git", "reset"], repo_path)
    for f in files:
        execute(["git", "checkout", "HEAD", "--", f], repo_path)
    return atexit_handler


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
    logger.verbose(f"Checking out previous branch of {repo_path.name} again..")
    execute(["git", "checkout", before_branch], repo_path)

    atexit.unregister(atexit_handler)


def find_pr(
    repo: Repository, branch: str, loose_str: str, next_checkmk_server_version: Tag
) -> PullRequest | None:
    pull_requests = repo.get_pulls()
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


def _make_server_changes(server_repo_path: Path, next_checkmk_server_version: Tag):
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


def main() -> None:
    parser = argparse.ArgumentParser()
    add_argparse_verbosity_option(parser)
    add_argparse_silent_option(parser)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Disable pushing the changes made and creating the PR.",
    )
    args = parser.parse_args()
    init_logger(args.verbose, args.silent)

    _login_or_token = None if args.dry_run else os.environ["GITHUB_TOKEN"]
    github_api: Github = Github(_login_or_token)

    server_repo: Repository = github_api.get_repo(
        "JonasPammer/ansible-role-checkmk_server"
    )
    server_repo_path: Path = Path.cwd()
    server_local_git_branch_before = clone_repo_and_checkout_branch(
        server_repo, server_repo_path, SERVER_MASTER_BRANCH
    )

    agent_repo: Repository = github_api.get_repo(
        "JonasPammer/ansible-role-checkmk_agent"
    )
    agent_repo_path: Path = server_repo_path.joinpath("__scripts", agent_repo.name)
    agent_local_git_branch_before = clone_repo_and_checkout_branch(
        agent_repo, agent_repo_path, AGENT_MASTER_BRANCH
    )

    server_defaults_yml: Path = server_repo_path.joinpath("defaults/main.yml")
    current_checkmk_server_version = yaml.safe_load(
        server_defaults_yml.read_text(encoding="utf8")
    )["checkmk_server_version"]
    agent_defaults_yml: Path = agent_repo_path.joinpath("defaults/main.yml")
    current_checkmk_agent_version = yaml.safe_load(
        agent_defaults_yml.read_text(encoding="utf8")
    )["checkmk_agent_version"]

    if current_checkmk_server_version != current_checkmk_agent_version:
        logger.fatal(
            "Version mismatch between current checkmk_server_version "
            "and checkmk_agent_version!! Aborting, please fix.."
        )
        exit(1)

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

    _script_executor_origin = "(could not resolve ip address location)"
    try:
        _origin = json.load(
            request.urlopen("https://geolocation-db.com/json/&position=true")
        )
        _script_executor_origin = _origin["city"]
    except (URLError, json.JSONDecodeError):
        pass
    SCRIPT_MSG: str = (
        ":robot: Authored by `__scripts/ci.py` python script "
        f"on {platform.node()} by {getpass.getuser()} from {_script_executor_origin} "
    )
    PR_NOTE = (
        "**This PR should result in the release of a new minor version for this role**!"
    )
    if len(tags_since) > 1:
        PR_NOTE += (
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

    SERVER_COMMIT_TITLE: str = (
        "refactor: update default checkmk_server_version "
        f"from {current_checkmk_server_version} "
        f"to {next_checkmk_server_version.name} :arrow_up:"
    )
    AGENT_COMMIT_TITLE: str = (
        "refactor: update default checkmk_agent_version "
        f"from {current_checkmk_agent_version} "
        f"to {next_checkmk_server_version.name} :arrow_up:"
    )
    SERVER_PR_BODY: str = f"{SCRIPT_MSG} \n\n {COMMIT_DESCRIPTION} \n\n {PR_NOTE}"
    AGENT_PR_BODY: str = SERVER_PR_BODY

    server_repo_files: list[str] = ["defaults/main.yml", "README.orig.adoc"]
    server_atexit_handler = checkout_pristine_pr_branch(
        repo_path=server_repo_path,
        pr_branch=SERVER_PR_BRANCH,
        before_branch=server_local_git_branch_before,
        files=server_repo_files,
    )
    _make_server_changes(server_repo_path, next_checkmk_server_version)
    commit_push_and_checkout_before(
        repo_path=server_repo_path,
        pr_branch=SERVER_PR_BRANCH,
        before_branch=server_local_git_branch_before,
        files=server_repo_files,
        atexit_handler=server_atexit_handler,
        dry_run=args.dry_run,
        commit_title=SERVER_COMMIT_TITLE,
        script_msg=SCRIPT_MSG,
        description=COMMIT_DESCRIPTION,
    )

    agent_repo_files: list[str] = ["defaults/main.yml", "README.orig.adoc"]
    agent_atexit_handler = checkout_pristine_pr_branch(
        repo_path=agent_repo_path,
        pr_branch=AGENT_PR_BRANCH,
        before_branch=agent_local_git_branch_before,
        files=agent_repo_files,
    )
    _make_agent_changes(agent_repo_path, next_checkmk_server_version)
    commit_push_and_checkout_before(
        repo_path=agent_repo_path,
        pr_branch=AGENT_PR_BRANCH,
        before_branch=agent_local_git_branch_before,
        files=agent_repo_files,
        atexit_handler=agent_atexit_handler,
        dry_run=args.dry_run,
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
    if not args.dry_run and found_server_pr is None:
        found_server_pr = server_repo.create_pull(
            title=SERVER_COMMIT_TITLE,
            body=SERVER_PR_BODY,
            head=SERVER_PR_BRANCH,
            base=SERVER_MASTER_BRANCH,
        )
        logger.info(f"Created {server_repo.name} PR: {found_server_pr.html_url}")

    found_agent_pr = find_pr(
        agent_repo,
        AGENT_PR_BRANCH,
        "refactor: update default checkmk_agent_version",
        next_checkmk_server_version,
    )
    if not args.dry_run and found_agent_pr is None:
        found_agent_pr = agent_repo.create_pull(
            title=AGENT_COMMIT_TITLE,
            body=AGENT_PR_BODY,
            head=AGENT_PR_BRANCH,
            base=AGENT_MASTER_BRANCH,
        )
        logger.info(f"Created {agent_repo.name} PR: {found_agent_pr.html_url}")

    if not args.dry_run and found_server_pr is not None:
        if found_agent_pr is not None:
            SERVER_PR_BODY += (
                "\n\n---\n"
                f"Accompanying `{agent_repo.name}` PR: " + found_agent_pr.html_url
            )
        found_server_pr.edit(
            title=SERVER_COMMIT_TITLE, body=SERVER_PR_BODY, state="open"
        )

    if not args.dry_run and found_agent_pr is not None:
        if found_server_pr is not None:
            AGENT_PR_BODY += (
                "\n\n---\n"
                f"Accompanying `{server_repo.name}` PR: " + found_server_pr.html_url
            )
        found_agent_pr.edit(title=AGENT_COMMIT_TITLE, body=AGENT_PR_BODY, state="open")


if __name__ == "__main__":
    main()
