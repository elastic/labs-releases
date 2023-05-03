# coding: utf-8

import pathlib


def write_files(directory: pathlib.Path, files: dict[str, bytes]) -> None:
    for filename, data in files.items():
        path = directory.joinpath(filename)
        with path.open("wb") as output:
            output.write(data)
            print(path)
