from __future__ import annotations

import hashlib
import logging
from urllib.error import HTTPError
from urllib.request import urlopen

DEBIAN_DISTROS = {
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
REDHAT_DISTROS = {"CentOS": {"7", "8"}}


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


def get_remote_sum(url: str, algorithm="sha1"):
    """
    :param url:
        Download URL of the File
    :param algorithm:
        hashlib algorithm to use. defaults to sha1 as recommended by ansible:

        https://docs.ansible.com/ansible/latest/collections/ansible/builtin/get_url_module.html#parameter-checksum

        ```
        If you worry about portability, only the sha1 algorithm
        is available on all platforms and python versions.
        ```

    :raises HTTPError:
        If `url` yieled a non-404 HTTP Response Status Code.
    :return:
        The hexdigest of the given file in ansible's <algorithm>:<checksum|url> format,
        or "None"if the url yieled a HTTP 404 Response Status Code.
    """
    try:
        logging.debug("Fetching " + url + "...")
        remote = urlopen(url)
        return "sha1:" + hash(remote, algorithm)
    except HTTPError as e:
        if e.code != 404:
            raise e
        return "None"


def get_all_remote_sums(checkmk_server_version: str) -> dict[str, str]:
    """Loop over `DEBIAN_DISTROS` / `REDHAT_DISTROS` and generate a dictionary
    containing all sha's for the given version.

    :param checkmk_server_version:
        plain checkmk server version (e.g. "2.1.0p9", not "v2.1.0p9")
    :return:
        A dictionary in which the key is "<distro>_<release name>"
        and the key is the result of `get_remote_sum`
        of the release in question (which may be the literal "None").
    """
    results = {}
    for distro, releases in DEBIAN_DISTROS.items():
        logging.debug(distro + " " + str(releases))
        for release in releases:
            release_name = release[0]
            url = (
                f"https://download.checkmk.com/checkmk/"
                f"{checkmk_server_version}/check-mk-raw-"
                f"{checkmk_server_version}_0.{release_name}_amd64.deb"
            )
            results[distro + "_" + release_name] = get_remote_sum(url)
    for distro in REDHAT_DISTROS:
        logging.debug(distro + " " + str(REDHAT_DISTROS[distro]))
        for release_name in REDHAT_DISTROS[distro]:
            url = (
                f"https://download.checkmk.com/checkmk/"
                f"{checkmk_server_version}/check-mk-raw-"
                f"{checkmk_server_version}-el{release_name}-38.x86_64.rpm"
            )
            results[distro + "_" + release_name] = get_remote_sum(url)
    return results
