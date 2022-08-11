"""Generator for _checkmk_server_download_checksum.

Invoke with `python3 -m __scripts.generate_hashes`
"""
from __future__ import annotations

import argparse
import logging

from .utils import generate_yaml
from .utils import logger


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkmk_server_version", type=str)
    parser.add_argument(
        "-v", "--verbose", help="increase output verbosity", action="store_true"
    )
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    print(generate_yaml(args.checkmk_server_version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
