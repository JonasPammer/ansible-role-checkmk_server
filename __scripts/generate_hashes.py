"""Generator for _checkmk_server_download_checksum.

Invoke with `python3 -m __scripts.generate_hashes`
"""
from __future__ import annotations

import argparse
import logging

import yaml

from .utils import get_all_remote_sums
from .utils import logger


def main() -> int:
    retv = 0
    parser = argparse.ArgumentParser()
    parser.add_argument("checkmk_server_version", type=str)
    parser.add_argument(
        "-v", "--verbose", help="increase output verbosity", action="store_true"
    )
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # TODO: quote str's with "
    print(
        yaml.dump(
            {
                "checkmk_server_version": args.checkmk_server_version,
                "_checkmk_server_download_checksum": get_all_remote_sums(
                    args.checkmk_server_version
                ),
            },
        )
    )
    return retv


if __name__ == "__main__":
    raise SystemExit(main())
