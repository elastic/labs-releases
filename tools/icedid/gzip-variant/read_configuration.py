# coding: utf-8

import argparse
import pathlib

from nightmare.malware.icedid import configuration


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path, help="Input file")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    with args.input.open("rb") as f:
        x = configuration.GzipVariantConfiguration(f.read())

    print("=" * 80)
    print("Configuration")
    print("=" * 80)
    print(x)


if __name__ == "__main__":
    main()
