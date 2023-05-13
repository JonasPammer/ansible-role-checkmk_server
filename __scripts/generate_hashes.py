"""Generator for _checkmk_server_download_checksum.

Invoke with `python3 -m __scripts.generate_hashes`
"""
from __future__ import annotations

import click

from .utils import generate_yaml
from .utils import get_click_silent_option
from .utils import get_click_verbosity_option
from .utils import init_logger


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@click.argument(
    "checkmk_server_version"
)
@get_click_verbosity_option()
@get_click_silent_option()
def main(checkmk_server_version: str, silent: bool, verbosity: int) -> int:
    """Manually Invoke generate_yaml."""
    init_logger(verbosity=verbosity, silent=silent)
    print(generate_yaml(checkmk_server_version))


if __name__ == "__main__":
    main()
