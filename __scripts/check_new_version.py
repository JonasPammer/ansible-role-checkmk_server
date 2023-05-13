from __future__ import annotations

import os
from pathlib import Path

import click
import yaml
from github import Github

from .utils import get_checkmk_raw_tags_since
from .utils import get_click_silent_option
from .utils import get_click_verbosity_option
from .utils import init_logger


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@click.option(
    "--from", "--checkmk_server_version", "checkmk_server_version",
    help="If given, this version is assumed as the current checkmk_server_version version "
    "and reading of `./defaults/main.yml` is skipped",
)
@get_click_verbosity_option()
@get_click_silent_option()
def main(checkmk_server_version: str, silent: bool, verbosity: int) -> None:
    """Manually Invoke get_checkmk_raw_tags_since."""
    init_logger(verbosity=verbosity, silent=silent)
    github_api: Github = (
        Github(os.environ["GITHUB_TOKEN"]) if "GITHUB_TOKEN" in os.environ else Github()
    )
    current_checkmk_server_version = checkmk_server_version

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


if __name__ == "__main__":
    main()
