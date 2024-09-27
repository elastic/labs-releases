# coding: utf-8

import pathlib
import typing
import requests
import lief
import re
import yara

from nightmare import cast

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
}

URL_REGEX = re.compile(
    rb"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
)
BRACKET_RE = re.compile(r"(\w+)\[(\d+)\]")
PRINTABLE_STRING_REGEX = re.compile(rb"[\x20-\x7E]{4,}")
BASE64_REGEX = re.compile(
    rb"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
)


def __download_aux(
    url: str, is_json: bool, *args, **kwargs
) -> dict[str, typing.Any] | bytes:
    if not (response := requests.get(url, headers=HEADERS, *args, **kwargs)).ok:
        raise RuntimeError(f"Failed to download {url}, code:{response.status_code}")

    return response.json() if is_json else response.content


def convert_bytes_to_base64_in_dict(
    data: dict[str, typing.Any]
) -> dict[str, typing.Any]:
    """
    Recursively convert bytes value(s) to base64 in a dictionary.

    :param data: The dictionary to convert.
    :return: The converted dictionary.
    """

    t = type(data)
    if t == dict:
        for key, value in data.items():
            data[key] = convert_bytes_to_base64_in_dict(value)
        return data
    elif t == list:
        return [convert_bytes_to_base64_in_dict(x) for x in data]
    elif t == bytes:
        return cast.bytes_to_b64_str(data)
    else:
        return data


def download(url: str, *args, **kwargs) -> bytes:
    return typing.cast(bytes, __download_aux(url, False, *args, **kwargs))


def download_json(url: str, *args, **kwargs) -> dict[str, typing.Any]:
    return typing.cast(
        dict[str, typing.Any], __download_aux(url, True, *args, **kwargs)
    )


def get_data(data: bytes, offset: int, size: int = 0) -> bytes:
    if size:
        return data[offset : offset + size]
    else:
        return data[offset:]


def get_section_content(pe: lief.PE.Binary, section_name: str) -> None | bytes:
    """
    The function gets the section content from a lief._lief.PE.Binary object
    :param pe: is a lief._lief.PE.Binary
    :param section_name: is the section name
    """
    if not pe:
        return None
    for section in pe.sections:
        if section.name.lower() == section_name:
            return bytes(section.content)
    else:
        return None


def resolve_key_chain(j: dict[str, typing.Any], key_chain: str) -> typing.Any:
    o: typing.Any = j

    try:
        for key in key_chain.split("."):
            if m := BRACKET_RE.match(key):
                o = o[m.group(1)][int(m.group(2), 10)]
            else:
                o = o[key]
        return o
    except Exception:
        return None


def map_files_directory(
    path: pathlib.Path, function: typing.Callable[[pathlib.Path], typing.Any]
) -> list[tuple[pathlib.Path, typing.Any]]:
    """
    The function recursively walk directory and call provided parameter function on each file
    :param path: Root directory path
    :function: Function that'll be called on each file
    :return: List of tuple containing the file path and the result returned by the provided function
    """
    if not path.is_dir():
        raise RuntimeError("Path is not a directory")

    return [(x, function(x)) for x in path.rglob("*")]


def write_files(directory: pathlib.Path, files: dict[str, bytes]) -> None:
    """
    The function write files in the given directory
    :param directory: Directory where the files will be written
    :param files: Dictionnary of file name and associated
    """

    for filename, data in files.items():
        directory.joinpath(filename).write_bytes(data)


def is_base64(s: bytes) -> bool:
    return bool(BASE64_REGEX.fullmatch(s))


def is_url(s: bytes) -> bool:
    return bool(URL_REGEX.fullmatch(s))


def find_strings(section_data: bytes) -> list[bytes]:
    """
    This function builds up the a list of string candidates based on bytes from data.
    The strings are picked based on regular expression for printable characters
    """
    all_strings = []
    for match in PRINTABLE_STRING_REGEX.findall(section_data):
        all_strings.append(match)

    return all_strings


def yara_scan(data: bytes, compiled_rule: yara.Rules) -> int | None:
    """
    Scans the given data using a compiled YARA rule and returns the offset of the first match.

    :param data: The binary data to scan.
    :param compiled_rule: The compiled YARA rule to use for scanning.

    :return:
        int: The offset of the first match found by the YARA rule.
    """
    matches = compiled_rule.match(data=data)
    if not matches:
        return None
    return matches[0].strings[0].instances[0].offset


def get_pe_data_from_rva(pe: lief.PE, va: int, size=None) -> bytes:
    image_base = pe.optional_header.imagebase
    rva = va - image_base
    data = pe.get_content_from_virtual_address(rva, size)
    return data
