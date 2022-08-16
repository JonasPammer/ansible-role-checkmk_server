from __future__ import annotations

import argparse
import difflib
import getpass
import os
import platform
from pathlib import Path
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


def _unidiff_output(expected: str, actual: str):
    """Returns a string containing the unified diff of two multiline
    strings."""
    diff: Iterator[str] = difflib.unified_diff(
        expected.splitlines(keepends=True), actual.splitlines(keepends=True)
    )

    return "".join(diff)


def main() -> int:
    parser = argparse.ArgumentParser()
    add_argparse_verbosity_option(parser)
    add_argparse_silent_option(parser)
    args = parser.parse_args()
    init_logger(args.verbose, args.silent)

    github_api: Github = Github(os.environ["GITHUB_TOKEN"])
    repo: Repository = github_api.get_repo("JonasPammer/ansible-role-checkmk_server")
    repo_path: Path = Path.cwd()

    current_defaults_yml = yaml.safe_load(Path("defaults/main.yml").read_text())
    current_checkmk_server_version = current_defaults_yml["checkmk_server_version"]

    # https://git-blame.blogspot.com/2013/06/checking-current-branch-programatically.html
    _current_branch = execute(
        ["git", "symbolic-ref", "--short", "-q", "HEAD"], repo_path
    ).strip()
    if _current_branch == "refs/heads/master":
        logger.fatal(
            "Checked-Out Branch must be either 'master' or 'main'! "
            f"Is: '{_current_branch}'. Aborting..."
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
    next_checkmk_server_version = tags_since[0].name
    console.print(
        f"There have been {len(tags_since)} new versions since "
        f"'{current_checkmk_server_version}'! "
        f"Next: '{next_checkmk_server_version}'"
    )

    _git_branch_before = execute(
        ["git", "symbolic-ref", "-q", "HEAD"], repo_path
    ).replace("refs/heads/", "")
    _git_status_before = execute(["git", "status", "--porcelain"], repo_path)
    if _git_status_before != "":
        logger.error("Working directory is not clean! Aborting...")
        exit(1)
    execute(["git", "stash"], repo_path)  # just to be safe

    COMMIT_TITLE: str = (
        "refactor: update default checkmk_server_version "
        f"to {next_checkmk_server_version}"
    )
    SCRIPT_MSG: str = f"""
    Authored by `__scripts/ci.py` python script
    on {platform.node()} by {getpass.getuser()}
    ({execute(["git", "rev-parse", "--verify", "HEAD"], repo_path)})
    """
    PR_BODY: str = f"""
    NOTE: This should result in a new minor version release of this role!

    {SCRIPT_MSG}
    """

    # Create pristine branch
    branch_name: str = "ci-refactor-checkmk_server_version"
    if branch_name in execute(["git", "branch", "--list"], repo_path):
        logger.info(
            f"Branch {branch_name} already exists. "
            f"Note that this script will force-overwrite it "
            f"to accomodate potentially changed script behaviour."
        )
        pass
    execute(["git", "checkout", "-b", branch_name], repo_path)
    execute(["git", "branch", f"--set-upstream-to=origin/{branch_name}"], repo_path)
    execute(["git", "reset", "--hard", "origin/master"], repo_path)
    execute(["git", "clean", "-dfx"], repo_path)

    # make changes
    defaults_yml: Path = repo_path.joinpath("defaults/main.yml")
    defaults_yml_contents_old: str = defaults_yml.read_text()
    defaults_yml_contents_new: str = replace_text_between(
        defaults_yml_contents_old,
        "#===== BEGIN generate_yaml MANAGED SECTION",
        "#===== END generate_yaml MANAGED SECTION",
        f"\n\n{generate_yaml(next_checkmk_server_version)}\n",
    )
    _defaults_yml_contents_diff: str = _unidiff_output(
        defaults_yml_contents_old, defaults_yml_contents_new
    )
    logger.verbose(_defaults_yml_contents_diff)
    defaults_yml.write_text(defaults_yml_contents_new)

    execute(["git", "add"], repo_path)
    execute(["git", "commit", "-m", COMMIT_TITLE, "-m", SCRIPT_MSG], repo_path)
    execute(["git", "push", "--force"], repo_path)

    _pull_requests = repo.get_pulls()
    found_pr: PullRequest | None = None
    for pr in _pull_requests:
        if (
            pr.head == branch_name
            and "refactor: update default checkmk_server_version" not in pr.title
        ):
            if found_pr is None:
                found_pr = pr
                continue
            logger.warning(
                f"Found more than one open ci.py PRs ({found_pr}, {pr})?? "
                "Aborting..."
            )
            exit(1)

    if found_pr is not None:
        if next_checkmk_server_version not in found_pr.title:
            logger.warning(
                f"{pr} seems to have been created by ci.py "
                f"but it's title does not match "
                f"{next_checkmk_server_version}! Aborting..."
            )
            exit(1)
        found_pr.edit(title=COMMIT_TITLE, body=PR_BODY, state="open", base=branch_name)
    else:
        pr = repo.create_pull(
            title=COMMIT_TITLE, body=PR_BODY, head=branch_name, base="master"
        )

    logger.verbose("Checking out previous branch and working tree again..")
    execute(["git", "checkout", _git_branch_before], repo_path)
    execute(["git", "stash", "pop"], repo_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())