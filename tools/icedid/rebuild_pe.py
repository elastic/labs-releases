# coding: utf-8

import argparse
import pathlib

from nightmare.malware.icedid import custom_pe


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path, help="Input file")
    parser.add_argument("output", help="Output reconstructed PE")
    parser.add_argument(
        "-o", "--offset", type=int, help="Offset to real data, skip possible garbage"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    with args.input.open("rb") as input:
        data = input.read()

    if args.offset:
        data = data[args.offset :]

    custom_pe.CustomPE(data).to_pe().write(args.output)


if __name__ == "__main__":
    main()
