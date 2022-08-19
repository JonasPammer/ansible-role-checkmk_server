"""Inform about new checkmk tags after a given version.

Invoke with `python3 -m __scripts.check_new_version`
"""
from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

import yaml
from github import Github

from .utils import get_checkmk_raw_tags_since
from .utils import logger


def main() -> None:
    github_api: Github = (
        Github(os.environ["GITHUB_TOKEN"]) if "GITHUB_TOKEN" in os.environ else Github()
    )
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--checkmk_server_version",
        required=False,
        help="use given version for the inquery "
        "instead of reading current value from `./defaults/main.yml`",
        type=str,
    )
    parser.add_argument(
        "-v", "--verbose", help="increase output verbosity", action="store_true"
    )
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    current_checkmk_server_version = args.checkmk_server_version

    if current_checkmk_server_version is None:
        current_defaults_yml = yaml.safe_load(
            Path("defaults/main.yml").read_text(encoding="utf8")
        )
        current_checkmk_server_version = current_defaults_yml["checkmk_server_version"]

    tags_since = get_checkmk_raw_tags_since(current_checkmk_server_version, github_api)
    if len(tags_since) != 0:
        print(
            f"There have been {len(tags_since)} new versions since "
            f"{current_checkmk_server_version}! "
            f"Next: {tags_since[0].name} | "
            f"Latest: {tags_since[len(tags_since)-1].name}"
        )
        print(
            f"Entire list of CheckMk tags "
            f"that come after {current_checkmk_server_version}: \n* "
            + "\n* ".join([t.name for t in tags_since])
        )
        exit(1)


if __name__ == "__main__":
    main()
