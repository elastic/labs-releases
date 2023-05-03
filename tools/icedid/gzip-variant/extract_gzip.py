# coding: utf-8

import argparse
import pathlib

from nightmare.malware.icedid import fake_gzip
from nightmare import utils


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path, help="Input file")
    parser.add_argument("output", type=pathlib.Path, help="Output directory")
    return parser.parse_args()


def print_info(x: fake_gzip.FakeGzip) -> None:
    print("=" * 80)
    print("Fake Gzip")
    print("=" * 80)
    print("{}\n".format(x))


def main() -> None:
    args = parse_arguments()

    with args.input.open("rb") as input:
        data = input.read()

    x = fake_gzip.FakeGzip(data)
    print_info(x)

    args.output.mkdir(exist_ok=True)
    utils.write_files(
        args.output,
        {
            "configuration.bin": x.configuration,
            x.core_filename: x.core,
            x.stage_2_filename: x.stage_2,
        },
    )


if __name__ == "__main__":
    main()
