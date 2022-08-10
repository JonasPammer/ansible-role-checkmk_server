"""Generator for _checkmk_server_download_checksum."""
from __future__ import annotations

import argparse
import hashlib
import logging
from urllib.error import HTTPError
from urllib.request import urlopen

import yaml


def hash(remote, algorithm="sha1"):
    if algorithm == "md5":
        hash = hashlib.md5()
    elif algorithm == "sha1":
        hash = hashlib.sha1()
    elif algorithm == "sha256":
        hash = hashlib.sha256()
    elif algorithm == "sha384":
        hash = hashlib.sha384()
    elif algorithm == "sha512":
        hash = hashlib.sha512()

    while True:
        data = remote.read(8192)
        if not data:
            break
        hash.update(data)

    return hash.hexdigest()


def get_remote_sum(url, algorithm="sha1"):
    try:
        remote = urlopen(url)
        return "sha1:" + hash(remote, algorithm)
    except HTTPError as e:
        if e.code != 404:
            raise e
        return "None"


def main() -> int:
    retv = 0
    parser = argparse.ArgumentParser()
    parser.add_argument("checkmk_server_version", type=str)
    parser.add_argument(
        "-v", "--verbose", help="increase output verbosity", action="store_true"
    )
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    deb_distros = {
        "Debian": [["stretch", "9"], ["buster", "10"], ["bullseye", "11"]],
        "Ubuntu": [
            ["xenial", "16.04"],
            ["bionic", "18.04"],
            ["focal", "20.04"],
            ["hirsute", "21.04"],
            ["impish", "21.10"],
            ["jammy", "22.04"],
        ],
    }
    rpm_distros = {"CentOS": {"7", "8"}}
    results = {}

    for distro, releases in deb_distros.items():
        logging.debug(distro + " " + str(releases))
        for release in releases:
            release_name = release[0]
            url = (
                f"https://download.checkmk.com/checkmk/"
                f"{args.checkmk_server_version}/check-mk-raw-"
                f"{args.checkmk_server_version}_0.{release_name}_amd64.deb"
            )
            logging.debug(url)
            _ = results[distro + "_" + release_name] = get_remote_sum(url)
            logging.debug(_)
    for distro in rpm_distros:
        logging.debug(distro + " " + str(rpm_distros[distro]))
        for release_name in rpm_distros[distro]:
            url = (
                f"https://download.checkmk.com/checkmk/"
                f"{args.checkmk_server_version}/check-mk-raw-"
                f"{args.checkmk_server_version}-el{release_name}-38.x86_64.rpm"
            )
            logging.debug(url)
            _ = results[distro + "_" + release_name] = get_remote_sum(url)
            logging.debug(_)

    # TODO: quote str's with "
    print(
        yaml.dump(
            {"_checkmk_server_download_checksum": results},
        )
    )
    return retv


if __name__ == "__main__":
    raise SystemExit(main())
