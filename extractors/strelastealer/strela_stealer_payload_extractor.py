# coding: "utf-8"

import argparse
import pathlib
import traceback

from nightmare.malware.strelastealer import payload as ss
from nightmare import utils


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.

    :return: Parsed command line arguments
    """

    parser = argparse.ArgumentParser("StrelaStealer payload extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f", "--file", type=pathlib.Path, help="StrelaStealer file path"
    )
    group.add_argument(
        "-d", "--directory", type=pathlib.Path, help="StrelaStealer directory"
    )
    parser.add_argument(
        "-o",
        "--outdir",
        type=pathlib.Path,
        help="StrelaStealer output directory",
        required=True,
    )

    return parser.parse_args()


def unpack_and_write(file_path: pathlib.Path, output_dir: pathlib.Path) -> None:
    try:
        with open(file_path, "rb") as file:
            content = ss.extract(file)
        output_path = (output_dir / file_path.name).with_suffix(".bin")
        utils.write_files(output_dir, {output_path: content})
        print(f"[+] Successfully extracted to {output_path}")

    except Exception as e:
        print(f"Failed to extract from {file_path}")
        traceback.print_exc()
        print()


def main() -> None:
    args = parse_arguments()
    if args.file:
        unpack_and_write(args.file, args.outdir)
    elif args.directory:
        utils.map_files_directory(
            args.directory, lambda file_path: unpack_and_write(file_path, args.outdir)
        )


if __name__ == "__main__":
    main()
