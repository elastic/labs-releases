import argparse
import pathlib

from nightmare.malware.icedid import compression


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path, help="Input file")
    parser.add_argument("output", type=pathlib.Path, help="Output file")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    with args.input.open("rb") as input:
        data = input.read()

    if not (decompressed_data := compression.decompress(data)):
        raise RuntimeError("Failed to decompress data")

    with args.output.open("wb") as output:
        output.write(decompressed_data)


if __name__ == "__main__":
    main()
