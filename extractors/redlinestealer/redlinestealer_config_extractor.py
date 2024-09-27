# coding: "utf-8"

import argparse
import pathlib
import functools
import json

from nightmare.malware.redlinestealer import configuration
from nightmare import utils


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("RedLine Stealer configuration extractor")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=pathlib.Path, help="file")
    group.add_argument("-d", "--directory", type=pathlib.Path, help=" directory")
    parser.add_argument(
        "-o",
        "--outfile",
        type=pathlib.Path,
        required=True,
    )
    return parser.parse_args()


def extract_config(file: pathlib.Path) -> dict[str, str] | None:
    """
    Extracts configuration from a RedLine Stealer sample.


    :param file: The path to the RedLine Stealer sample.

    :return: The configuration extracted from the file if successful.
             None if extraction fails or encounters an exception.
    """
    try:
        return configuration.extract(file.read_bytes())
    except RuntimeError as e:
        print(e)
        return None


def process_redlinestealer_file(file: pathlib.Path) -> dict[str, str] | None:
    if not file.is_file():
        return None

    if not (config := extract_config(file)):
        print(f"Failed to extract config from {file}")
        return None

    return config


def main() -> None:
    args = parse_arguments()
    outfile = args.outfile

    configs = dict()

    if args.file:
        config = process_redlinestealer_file(args.file)
        if config:
            configs[args.file.as_posix()] = config

    elif args.directory:
        for filename, config in utils.map_files_directory(
            args.directory, functools.partial(process_redlinestealer_file)
        ):
            if config:
                configs.update({filename.as_posix(): config})

    if configs:
        outfile.write_text(json.dumps(configs))
        print("[+] Extracted configuration written to {}".format(outfile))

if __name__ == "__main__":
    main()
