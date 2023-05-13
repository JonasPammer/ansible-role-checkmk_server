from __future__ import annotations

import hashlib
import logging
import os
import pathlib
import stat
import subprocess
from argparse import ArgumentParser
from functools import lru_cache
from typing import Any
from typing import Callable
from typing import Sequence
from urllib.error import HTTPError
from urllib.request import urlopen

import verboselogs
import yaml
from github import Github
from github.Tag import Tag
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress
from rich.traceback import install as install_rich_traceback

console = Console(width=240, force_terminal=True if "PY_COLORS" in os.environ else None)
logger = verboselogs.VerboseLogger("ansible-roles")

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
REDHAT_DISTROS = {"RedHat": {"7", "8"}}


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


@lru_cache(maxsize=None)
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
        logger.debug("Fetching " + url + "...")
        remote = urlopen(url)
        return "sha1:" + hash(remote, algorithm)
    except HTTPError as e:
        if e.code != 404:
            raise e
        return "None"


@lru_cache(maxsize=None)
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
    checkmk_server_version = checkmk_server_version.replace("v", "")
    logger.info(
        "Fetching checksums of every distribution. "
        "This may take a while, as we need to download the files!"
    )
    results = {}

    progress: Progress = Progress()
    progress.start()
    progress_task = progress.add_task(
        "Fetch Checksums",
        total=len(DEBIAN_DISTROS["Debian"])
        + len(DEBIAN_DISTROS["Ubuntu"])
        + len(REDHAT_DISTROS["RedHat"]),
    )

    for distro, releases in DEBIAN_DISTROS.items():
        logger.debug(distro + " " + str(releases))
        for release in releases:
            release_name = release[0]
            progress.update(
                progress_task,
                advance=1,
                description=f"Fetching checksum for {release_name}",
            )
            url = (
                f"https://download.checkmk.com/checkmk/"
                f"{checkmk_server_version}/check-mk-raw-"
                f"{checkmk_server_version}_0.{release_name}_amd64.deb"
            )
            results[distro + "_" + release_name] = get_remote_sum(url)
    for distro in REDHAT_DISTROS:
        logger.debug(distro + " " + str(REDHAT_DISTROS[distro]))
        for release_name in REDHAT_DISTROS[distro]:
            progress.update(
                progress_task,
                advance=1,
                description=f"Fetching checksum for {release_name}",
            )
            url = (
                f"https://download.checkmk.com/checkmk/"
                f"{checkmk_server_version}/check-mk-raw-"
                f"{checkmk_server_version}-el{release_name}-38.x86_64.rpm"
            )
            results[distro + "_" + release_name] = get_remote_sum(url)

    progress.stop()
    return results


def generate_yaml(checkmk_server_version: str) -> str:
    # TODO: quote str's with "
    return yaml.dump(
        {
            "checkmk_server_version": checkmk_server_version.replace("v", ""),
            "_checkmk_server_download_checksum": get_all_remote_sums(
                checkmk_server_version
            ),
        },
    )


def get_checkmk_raw_tags_since(
    current_checkmk_server_version: str, github_api: Github
) -> list[Tag]:
    """Query https://github.com/tribe29/checkmk/tags and return list of valid
    tags that represent new releases that came out since
    `current_checkmk_server_version`.

    :param current_checkmk_server_version:
        plain checkmk server version (e.g. "2.1.0p9", not "v2.1.0p9")
    :param github_api:
        PyGithub object to use.
    :return:
        A list of `github.Tag`'s in which the last item is the latest tag and the
        first item is the tag that came directly after the given version.
        Only "real" v2* version tags are included in the list.
        Beta versions are skipped.
        The name of tags include a "v" at the beginning!
    """
    current_checkmk_server_version = current_checkmk_server_version.replace("v", "")

    tags_since = []
    for tag in github_api.get_repo("tribe29/checkmk").get_tags():
        # this needs to be done because
        # 1) there's alaways a transient tag "v9.9.9p9-rc9" and
        # 2) v1 is still maintained too but this role is developed with only v2 in mind
        if "v2" not in tag.name:
            continue
        if tag.name == f"v{current_checkmk_server_version}":
            break
        tags_since.append(tag)

    current_checkmk_server_version_base = ".".join(
        current_checkmk_server_version.split("p")[0].split(".")[0::1]
    )
    # skip betas and base of current version
    new_tags_since = []
    for tag in tags_since:
        if tag.name == f"v{current_checkmk_server_version_base}":
            continue
        if "b" in tag.name:
            continue
        new_tags_since.append(tag)

    new_tags_since = sorted(new_tags_since, key=lambda tag: tag.name)
    return new_tags_since


def replace_text_between(
    originalText: str,
    delimeterA: str,
    delimeterB: str,
    replacementText: str,
    offset: int = 0,
) -> str:
    if delimeterA not in originalText:
        logger.verbose(
            f"""
            originalText:\n---{originalText}\n---\n
            delimeterA:\n---{delimeterA}\n---
            """
        )
        raise ValueError("Given Text does not contain delimiterA!")
    if delimeterB not in originalText:
        logger.verbose(
            f"""
            originalText:\n---{originalText}\n---\n
            delimeterB:\n---{delimeterB}\n---
            """
        )
        raise ValueError("Given Text does not contain delimiterB!")
    leadingText: str = originalText.split(delimeterA)[offset]
    _afterLeadingText: str = delimeterA.join(
        originalText.split(delimeterA)[offset + 1 : :]
    )
    if delimeterA == delimeterB:
        offset += 1
    trailingText: str = delimeterB.join(
        _afterLeadingText.split(delimeterB)[offset + 1 : :]
    )

    return leadingText + delimeterA + replacementText + delimeterB + trailingText


def add_argparse_silent_option(parser: ArgumentParser) -> None:
    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Disable LOGGING to console (print's will still be made).",
    )


def add_argparse_verbosity_option(parser: ArgumentParser) -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="""
        Can be used up to 3 times (i.e., '-vvv') to
        incrementally increase verbosity of log output (VERBOSE -> DEBUG -> SPAM).
        File Log Output (if existant) is always DEBUG except when verbosity is over 3,
        in which scenario it also shows SPAM logs.
        """,
    )


# Copied from JonasPammer/ansible-roles
def get_log_levels_from_verbosity_or_silent_cli_argument(
    verbosity: int = 0, silent: bool = False
) -> tuple[int, int]:
    """
    :param verbosity:
      0:
        INFO    | VERBOSE
      1:
        VERBOSE | DEBUG
      2:
        DEBUG   | DEBUG
      3 and above:
        SPAM    | SPAM
    :param silent:
        Sets the returned console_log_level to be NOTSET
        (no-matter what `verbosity` level was given).
    :return:
        A tuple containing
        1) the determined console log level and
        2) the determined rotating log level.
    """

    console_log_level = logging.INFO
    rotate_log_level = verboselogs.VERBOSE
    if verbosity == 1:
        # Detailed information that should be understandable to experienced users
        # to provide insight in the software’s behavior;
        # a sort of high level debugging information.
        console_log_level = verboselogs.VERBOSE
        rotate_log_level = logging.DEBUG
    elif verbosity == 2:
        # Detailed information, typically of interest only when diagnosing problems.
        console_log_level = logging.DEBUG
    elif verbosity >= 3:
        # Way too verbose for regular debugging,
        # but nice to have when someone is getting desperate
        # in a late night debugging session and decides
        # that they want as much instrumentation as possible! :-)
        console_log_level = verboselogs.SPAM
        rotate_log_level = verboselogs.SPAM

    if silent:
        console_log_level = logging.NOTSET

    return console_log_level, rotate_log_level


# Copied from JonasPammer/ansible-roles
def init_logger(verbosity: int = 0, silent: bool = False) -> None:
    (
        console_log_level,
        rotate_log_level,
    ) = get_log_levels_from_verbosity_or_silent_cli_argument(verbosity, silent)
    logger.addHandler(
        RichHandler(
            level=logging.getLevelName(console_log_level), markup=True, console=console
        )
    )
    logger.setLevel(console_log_level)
    install_rich_traceback(show_locals=True)


# Copied from JonasPammer/ansible-roles
def execute(
    args: Sequence[str | os.PathLike[Any]],
    path: pathlib.Path,
    is_real_error: Callable[[subprocess.CalledProcessError], bool] | None = None,
) -> str:
    """Execute given command in the given directory with appropiate of logs,
    returing the output if all went ok.

    :param args:
        The actual command to execute.
    :param path:
        The `cwd` to execute the subproccess in.
    :param is_real_error:
        If the exit code was non-zero, this function is used to determine
        whether to throw and report about the thrown CalledProcessError
        or wheter to just log and return the output like normal.
        None is interpreted as "always True".
        None by default.
    :raises subproccess.CalledProcesssError:
        If the exit code was non-zero and `is_real_error`
        is either None or returns True,
        this function raises a CalledProcessError.
        The CalledProcessError object will have  the return code in the
        returncode attribute and output in the output attribute.
    :return: decoded output of command
    """
    cmd_str = " ".join([str(_) for _ in args])
    logger.verbose(f"Executing '{cmd_str}'...")

    result = None
    try:
        result = subprocess.check_output(
            args, cwd=path.absolute(), stderr=subprocess.PIPE
        )
        logger.verbose(result.decode())
        return result.decode()
    except subprocess.CalledProcessError as ex:
        if is_real_error is not None and not is_real_error(ex):
            logger.verbose(ex.stdout.decode())
            return ex.stdout.decode()
        logger.error(f"stdout: \n {ex.stdout.decode()}")
        logger.error(
            f"'{cmd_str}' for '{path}' returned non-zero exit status {ex.returncode}! "
            f"See above for more information."
        )
        raise ex


def on_rm_error(func, path, exc_info):
    # from https://stackoverflow.com/a/4829285
    os.chmod(path, stat.S_IWRITE)
    os.unlink(path)
