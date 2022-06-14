"""Generator for _checkmk_server_download_checksum."""
from __future__ import annotations

import argparse
import hashlib
import logging
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
    remote = urlopen(url)
    return hash(remote, algorithm)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("checkmk_server_version", type=str)
    parser.add_argument(
        "-v", "--verbose", help="increase output verbosity", action="store_true"
    )
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    deb_distros = {
        "Debian": ["stretch", "buster", "bullseye"],
        "Ubuntu": ["xenial", "bionic", "focal", "hirsute", "impish"],
    }
    rpm_distros = {"CentOS": {"7", "8"}}
    results = {}

    for distro, releases in deb_distros.items():
        logging.debug(distro + " " + str(releases))
        for release in releases:
            url = (
                f"https://download.checkmk.com/checkmk/"
                f"{args.checkmk_server_version}/check-mk-raw-"
                f"{args.checkmk_server_version}_0.{release}_amd64.deb"
            )
            logging.debug(url)
            _ = results[distro + "_" + release] = f"sha1:{get_remote_sum(url)}"
            logging.debug(_)
    for distro, releases in rpm_distros.items():
        logging.debug(distro + " " + str(releases))
        for release in releases:
            url = (
                f"https://download.checkmk.com/checkmk/"
                f"{args.checkmk_server_version}/check-mk-raw-"
                f"{args.checkmk_server_version}-el{release}-38.x86_64.rpm"
            )
            logging.debug(url)
            _ = results[distro + "_" + release] = f"sha1:{get_remote_sum(url)}"
            logging.debug(_)

    # TODO: quote str's with "
    print(
        yaml.dump(
            {"_checkmk_server_download_checksum": results},
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
