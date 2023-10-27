# coding: "utf-8"

import argparse
import pathlib
import lief
import functools

from nightmare.malware.ghostpulse import payload
from nightmare import utils


def extract_payload(file: pathlib.Path) -> bytes | None:
    """
    Extracts payload from a GHOSTPULSE encrypted file.

    :param file: The path to the ghostpulse encrypted file.
    :return: The payload bytes extracted from the file if successful.
             None if extraction fails or encounters an exception.
    """
    try:
        with file.open("rb") as f:
            data = f.read()
        return payload.extract(data)
    except RuntimeError as e:
        print(e)
        return None


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("GHOSTPULSE payload extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f", "--file", type=pathlib.Path, help="GHOSTPULSE encrypted file path"
    )
    group.add_argument(
        "-d", "--directory", type=pathlib.Path, help="GHOSTPULSE directory"
    )
    parser.add_argument(
        "-o",
        "--outdir",
        type=pathlib.Path,
        help="GHOSTPULSE output directory",
        required=True,
    )
    return parser.parse_args()


def process_ghostpulse_file(file: pathlib.Path) -> bytes | None:
    if not file.is_file():
        return None

    if not (payload := extract_payload(file)):
        print(f"Failed to extract payload from {file}")
        return None

    return payload


def print_banner() -> None:
    print(
        r"""                                                                                                                                                         
 _____ _____ _____ _____ _____ _____ _____ __    _____ _____    _____ _____ __ __ __    _____ _____ ____     _____ __ __ _____ _____ _____ _____ _____ _____ _____ 
|   __|  |  |     |   __|_   _|  _  |  |  |  |  |   __|   __|  |  _  |  _  |  |  |  |  |     |  _  |    \   |   __|  |  |_   _| __  |  _  |     |_   _|     | __  |
|  |  |     |  |  |__   | | | |   __|  |  |  |__|__   |   __|  |   __|     |_   _|  |__|  |  |     |  |  |  |   __|-   -| | | |    -|     |   --| | | |  |  |    -|
|_____|__|__|_____|_____| |_| |__|  |_____|_____|_____|_____|  |__|  |__|__| |_| |_____|_____|__|__|____/   |_____|__|__| |_| |__|__|__|__|_____| |_| |_____|__|__|
                                                                                                                                                                   
"""
    )


def main() -> None:
    lief.logging.disable()
    print_banner()
    args = parse_arguments()
    outdir = args.outdir.resolve()

    payloads = dict()

    if args.file:
        payloads[
            args.file.joinpath(outdir, args.file.name + ".bin")
        ] = process_ghostpulse_file(args.file)

    elif args.directory:
        payloads.update(
            {
                filename.joinpath(outdir, filename.name + ".bin"): payload
                for (filename, payload) in utils.map_files_directory(
                    args.directory,
                    functools.partial(process_ghostpulse_file),
                )
                if payload
            }
        )

    outdir.mkdir(parents=True, exist_ok=True)
    utils.write_files(outdir, payloads)
    for x in payloads.keys():
        print("\nPayload written to {}".format(outdir.joinpath(x)))


if __name__ == "__main__":
    main()
