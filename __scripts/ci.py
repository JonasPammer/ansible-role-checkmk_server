from __future__ import annotations

import argparse
import atexit
import difflib
import getpass
import os
import platform
from pathlib import Path
from time import sleep
from typing import Iterator

import yaml
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository

from .utils import add_argparse_silent_option
from .utils import add_argparse_verbosity_option
from .utils import console
from .utils import execute
from .utils import generate_yaml
from .utils import get_checkmk_raw_tags_since
from .utils import init_logger
from .utils import logger
from .utils import replace_text_between


PR_BRANCH: str = "checkmk_server_version-autoupdate"
MASTER_BRANCH: str = "feat-checkmk_server_version-autoupdate"


def _unidiff_output(expected: str, actual: str):
    """Returns a string containing the unified diff of two multiline
    strings."""
    diff: Iterator[str] = difflib.unified_diff(
        expected.splitlines(keepends=True), actual.splitlines(keepends=True)
    )

    return "".join(diff)


def _pop_git_stash_if(old: str, repo_path: Path) -> None:
    if old != "":
        logger.notice(
            "git contains a stash that has not been created by this script run. "
            "Please resolve by 'git stash pop'ing yourself! "
        )
        return
    if execute(["git", "stash", "list", "--porcelain"], repo_path).strip() != "":
        execute(["git", "stash", "pop"], repo_path)


def main() -> int:
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

    github_api: Github = Github(os.environ["GITHUB_TOKEN"])
    repo: Repository = github_api.get_repo("JonasPammer/ansible-role-checkmk_server")
    repo_path: Path = Path.cwd()

    current_defaults_yml = yaml.safe_load(Path("defaults/main.yml").read_text())
    current_checkmk_server_version = current_defaults_yml["checkmk_server_version"]

    # https://git-blame.blogspot.com/2013/06/checking-current-branch-programatically.html
    _git_branch_before = (
        execute(["git", "symbolic-ref", "--short", "-q", "HEAD"], repo_path)
        .replace("refs/heads/", "")
        .strip()
    )
    if _git_branch_before != f"{MASTER_BRANCH}":
        logger.fatal(
            "Checked-Out Branch must be '{MASTER_BRANCH}'! "
            f"Is: '{_git_branch_before}'. Aborting..."
        )
        exit(1)
    _git_stash_list_before = execute(
        ["git", "stash", "list", "--porcelain"], repo_path
    ).strip()

    tags_since = get_checkmk_raw_tags_since(current_checkmk_server_version, github_api)
    if len(tags_since) == 0:
        console.print(
            "There have been no new CheckMk versions since "
            f"'{current_checkmk_server_version}'."
            "'All good. Doing nothing'."
        )
        exit(0)
    next_checkmk_server_version = tags_since[0]
    console.print(
        f"There have been {len(tags_since)} new versions since "
        f"'{current_checkmk_server_version}'! "
        f"Next: '{next_checkmk_server_version.name}'"
    )

    def atexit_handler() -> None:
        logger.notice(
            "The program terminated unexpectedly! "
            "Checking out the branch we were previously on "
            "and popping stash..."
        )
        execute(["git", "checkout", _git_branch_before], repo_path)
        _pop_git_stash_if(_git_stash_list_before, repo_path)

    _git_status_before = execute(["git", "status", "--porcelain"], repo_path)
    if _git_status_before != "":
        logger.error("Working directory is not clean! Aborting...")
        exit(1)
    execute(["git", "stash"], repo_path)  # just to be safe

    __date = next_checkmk_server_version.commit.commit.committer.date
    __url = (
        f"https://github.com/tribe29/checkmk/compare/{next_checkmk_server_version.name}"
        f"...v{current_checkmk_server_version}"
    )
    COMMIT_TITLE: str = (
        "refactor: update default checkmk_server_version "
        f"to {next_checkmk_server_version.name} arrow_up:"
    )
    DESCRIPTION: str = (
        f"Release Date of [{next_checkmk_server_version.name}]({__url}): "
        f"{__date.strftime('%Y-%m-%d')}"
    )
    if len(tags_since) > 1:
        DESCRIPTION += (
            f"\n> **NOTE**: There have been **{len(tags_since)}** new versions since "
            f"{current_checkmk_server_version}. "
            f"After this PR has been merged, the github workflow will run again "
            f"and a new PR will open semi-immideatily. "
            f"Please **ensure to create a proper tag/release "
            f"for every merged ci.py PR**."
        )
    SCRIPT_MSG: str = (
        "Authored by `__scripts/ci.py` python script"
        f"on {platform.node()} by {getpass.getuser()} "
        f"({execute(['git', 'rev-parse', '--verify', 'HEAD'], repo_path).strip()})"
    )
    PR_BODY: str = (
        f"{SCRIPT_MSG} \n\n {DESCRIPTION} \n\n "
        "NOTE: This should result in a new minor version release of this role!"
    )

    # ENSURE PRISTINE BRANCH
    if f"/refs/heads/{PR_BRANCH}" in execute(
        ["git", "ls-remote", "--heads"], repo_path
    ):
        logger.notice(
            f"Branch '{PR_BRANCH}' already exists on remotes. "
            f"Note that this script will force-overwrite it "
            f"to accomodate potentially changed script behaviour."
        )
        sleep(5)
    else:
        # may possibly exist locally:
        execute(["git", "branch", "-D", PR_BRANCH], repo_path)
        execute(["git", "branch", PR_BRANCH], repo_path)

    execute(["git", "fetch"], repo_path)
    execute(["git", "checkout", PR_BRANCH], repo_path)
    atexit.register(atexit_handler)

    execute(["git", "reset", "--hard", f"{MASTER_BRANCH}"], repo_path)
    execute(["git", "clean", "-dfx"], repo_path)

    # MAKE CHANGES
    defaults_yml: Path = repo_path.joinpath("defaults/main.yml")
    defaults_yml_contents_old: str = defaults_yml.read_text()
    defaults_yml_contents_new: str = replace_text_between(
        defaults_yml_contents_old,
        "# ===== BEGIN generate_yaml MANAGED SECTION",
        "# ===== END generate_yaml MANAGED SECTION",
        f"\n\n{generate_yaml(next_checkmk_server_version.name)}\n",
    )
    _defaults_yml_contents_diff: str = _unidiff_output(
        defaults_yml_contents_old, defaults_yml_contents_new
    )
    logger.verbose("Unidiff of 'defaults/main.yml': \n" + _defaults_yml_contents_diff)
    defaults_yml.write_text(defaults_yml_contents_new)

    _git_status = execute(["git", "status", "--porcelain"], repo_path)
    if _git_status != "":
        execute(["git", "add", "defaults/main.yml"], repo_path)
        execute(["git", "commit", "-m", COMMIT_TITLE, "-m", SCRIPT_MSG], repo_path)
    if not args.dry_run:
        execute(
            ["git", "push", "--force", "--set-upstream", "origin", PR_BRANCH], repo_path
        )

    _pull_requests = repo.get_pulls()
    found_pr: PullRequest | None = None
    for pr in _pull_requests:
        if (
            pr.head.ref == PR_BRANCH
            and "refactor: update default checkmk_server_version" in pr.title
        ):
            if found_pr is None:
                logger.info(f"Found open ci.py PR {pr}.")
                found_pr = pr
                continue
            logger.warning(
                f"Found more than one open ci.py PRs ({found_pr}, {pr})?? "
                "Aborting..."
            )
            exit(1)

    if found_pr is not None:
        if next_checkmk_server_version.name not in found_pr.title:
            logger.warning(
                f"{pr} seems to have been created by ci.py "
                f"but it's title does not match "
                f"{next_checkmk_server_version.name}! Aborting..."
            )
            exit(1)
        if not args.dry_run:
            found_pr.edit(title=COMMIT_TITLE, body=PR_BODY, state="open")
    else:
        if not args.dry_run:
            pr = repo.create_pull(
                title=COMMIT_TITLE, body=PR_BODY, head=PR_BRANCH, base=MASTER_BRANCH
            )

    logger.verbose("Checking out previous branch and working tree again..")
    execute(["git", "checkout", _git_branch_before], repo_path)
    _pop_git_stash_if(_git_stash_list_before, repo_path)

    atexit.unregister(atexit_handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
