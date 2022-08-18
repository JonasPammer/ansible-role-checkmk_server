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

from .utils import add_argparse_silent_option
from .utils import add_argparse_verbosity_option
from .utils import console
from .utils import execute
from .utils import generate_yaml
from .utils import get_checkmk_raw_tags_since
from .utils import init_logger
from .utils import logger
from .utils import replace_text_between

# FIXME / TODO: *MASTER_BRANCH'es are only temporary. revert to 'master' when merged!
SERVER_MASTER_BRANCH: str = "feat-checkmk_server_version-autoupdate"
SERVER_PR_BRANCH: str = "checkmk_server_version-autoupdate"
AGENT_MASTER_BRANCH: str = "feat-checkmk_agent_version-autoupdate"
AGENT_PR_BRANCH: str = "checkmk_agent_version-autoupdate"


def _unidiff_output(expected: str, actual: str):
    """Returns a string containing the unified diff of two multiline
    strings."""
    diff: Iterator[str] = difflib.unified_diff(
        expected.splitlines(keepends=True), actual.splitlines(keepends=True)
    )

    return "".join(diff)


def _clone_repo_and_checkout_branch(
    repo: Repository, repo_path: Path, branch: str
) -> str:
    if not repo_path.joinpath(".git").exists():
        execute(["git", "clone", repo.clone_url], repo_path.parent)

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


def _checkout_pristine_pr_branch(
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
        execute(["git", "branch", "-D", pr_branch], repo_path)
        execute(["git", "branch", pr_branch], repo_path)

    execute(["git", "fetch"], repo_path)
    execute(["git", "checkout", pr_branch], repo_path)
    atexit.register(atexit_handler)

    execute(["git", "reset"], repo_path)
    execute(["git", "clean", "-dfx"], repo_path)
    for f in files:
        execute(["git", "checkout", "HEAD", "--", f], repo_path)
    return atexit_handler


def _commit_push_and_checkout_before(
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
    server_local_git_branch_before = _clone_repo_and_checkout_branch(
        server_repo, server_repo_path, SERVER_MASTER_BRANCH
    )

    agent_repo: Repository = github_api.get_repo(
        "JonasPammer/ansible-role-checkmk_agent"
    )
    agent_repo_path: Path = server_repo_path.joinpath("__scripts", agent_repo.name)
    # agent_local_git_branch_before = _clone_repo_and_checkout_branch(
    #     agent_repo, agent_repo_path, AGENT_MASTER_BRANCH
    # )

    server_defaults_yml: Path = server_repo_path.joinpath("defaults/main.yml")
    current_checkmk_server_version = yaml.safe_load(server_defaults_yml.read_text())[
        "checkmk_server_version"
    ]
    agent_defaults_yml: Path = agent_repo_path.joinpath("defaults/main.yml")
    current_checkmk_agent_version = yaml.safe_load(agent_defaults_yml.read_text())[
        "checkmk_agent_version"
    ]

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
    console.print(
        f"There have been {len(tags_since)} new versions since "
        f"'{current_checkmk_server_version}'! "
        f"Next: '{next_checkmk_server_version.name}'"
    )

    __origin = "(could not resolve ip address location)"
    try:
        _origin = json.load(
            request.urlopen("https://geolocation-db.com/json/&position=true")
        )
        __origin = _origin["city"]
    except (URLError, json.JSONDecodeError):
        pass
    __date = next_checkmk_server_version.commit.commit.committer.date
    __url = (
        f"https://github.com/tribe29/checkmk/compare/v{current_checkmk_server_version}"
        f"...v{next_checkmk_server_version.name}"
    )
    COMMIT_TITLE: str = (
        "refactor: update default checkmk_server_version "
        f"from {current_checkmk_server_version} "
        f"to {next_checkmk_server_version.name} :arrow_up:"
    )
    DESCRIPTION: str = (
        f"Release Date of [{next_checkmk_server_version.name}]({__url}): "
        f"{__date.strftime('%Y-%m-%d')}"
        f"\n\n"
        f"* Accompanying `ansible-role-checkmk_agent` PR: "
        f"https://github.com/JonasPammer/ansible-role-checkmk_agent/pull/TODO"
    )
    DESCRIPTION_NOTE = ""
    if len(tags_since) > 1:
        DESCRIPTION_NOTE = (
            f"\n\nNOTE: There have been **{len(tags_since)}** new versions since "
            f"{current_checkmk_server_version}. "
            f"*After this PR has been merged, the github workflow will run again "
            f"and a new PR will open semi-immideatily*. "
            f"Please **ensure to create a proper tag/release "
            f"for every merged ci.py PR**."
        )
    SCRIPT_MSG: str = (
        ":robot: Authored by `__scripts/ci.py` python script "
        f"on {platform.node()} by {getpass.getuser()} from {__origin} "
        f"(latest commit: "
        + execute(["git", "rev-parse", "--verify", "HEAD"], server_repo_path).strip()
        + ")"
    )
    PR_BODY: str = (
        f"{SCRIPT_MSG} \n\n {DESCRIPTION} {DESCRIPTION_NOTE} \n\n "
        "NOTE: This should result in a new minor version release of this role!"
    )

    server_files: list[str] = ["defaults/main.yml", "README.orig.adoc"]
    server_atexit_handler = _checkout_pristine_pr_branch(
        repo_path=server_repo_path,
        pr_branch=SERVER_PR_BRANCH,
        before_branch=server_local_git_branch_before,
        files=server_files,
    )

    # MAKE CHANGES
    server_defaults_yml_contents_old: str = server_defaults_yml.read_text()
    server_defaults_yml_contents_new: str = replace_text_between(
        server_defaults_yml_contents_old,
        "# ===== BEGIN generate_yaml MANAGED SECTION",
        "# ===== END generate_yaml MANAGED SECTION",
        f"\n\n{generate_yaml(next_checkmk_server_version.name)}\n",
    )
    _server_defaults_yml_contents_diff: str = _unidiff_output(
        server_defaults_yml_contents_old, server_defaults_yml_contents_new
    )
    logger.verbose(
        "Unidiff of 'defaults/main.yml': \n" + _server_defaults_yml_contents_diff
    )
    server_defaults_yml.write_text(server_defaults_yml_contents_new)

    server_readme: Path = server_repo_path.joinpath("README.orig.adoc")
    server_readme_contents_old: str = server_readme.read_text()
    server_readme_contents_new: str = replace_text_between(
        server_readme_contents_old,
        'checkmk_server_version: "',
        '"',
        next_checkmk_server_version.name.replace("v", ""),
    )
    _readme_contents_diff: str = _unidiff_output(
        server_readme_contents_old, server_readme_contents_new
    )
    logger.verbose("Unidiff of 'README.orig.adoc': \n" + _readme_contents_diff)
    server_readme.write_text(server_readme_contents_new)

    _commit_push_and_checkout_before(
        repo_path=server_repo_path,
        pr_branch=SERVER_PR_BRANCH,
        before_branch=server_local_git_branch_before,
        files=server_files,
        atexit_handler=server_atexit_handler,
        dry_run=args.dry_run,
        commit_title=COMMIT_TITLE,
        script_msg=SCRIPT_MSG,
        description=DESCRIPTION,
    )

    _pull_requests = server_repo.get_pulls()
    found_pr: PullRequest | None = None
    for pr in _pull_requests:
        if (
            pr.head.ref == SERVER_PR_BRANCH
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
            server_repo.create_pull(
                title=COMMIT_TITLE,
                body=PR_BODY,
                head=SERVER_PR_BRANCH,
                base=SERVER_MASTER_BRANCH,
            )


if __name__ == "__main__":
    main()
