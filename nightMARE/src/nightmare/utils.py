# coding: utf-8

import pathlib
import typing
import requests
import lief

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
}


def __download_aux(
    url: str, is_json: bool, *args, **kwargs
) -> dict[str, typing.Any] | bytes:
    if not (response := requests.get(url, headers=HEADERS, *args, **kwargs)).ok:
        raise RuntimeError(f"Failed to download {url}, code:{response.status_code}")

    return response.json() if is_json else response.content


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
    The function get the section content from a lief._lief.PE.Binary object
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
        path = directory.joinpath(filename)
        with path.open("wb") as output:
            output.write(data)
