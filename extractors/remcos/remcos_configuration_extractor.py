# coding: utf-8

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

# REMCOS configuration extractor from Elastic Security Labs.

from __future__ import annotations

import argparse
import pathlib
import json
import base64
import typing
import traceback

from nightmare.malware.remcos import configuration
from nightmare import utils


def parse_arguments():
    """
    Parse command line arguments.

    :return: Parsed command line arguments
    """
    parser = argparse.ArgumentParser()

    subparser = parser.add_subparsers(
        description="Unpack/Repack mode", required=True, dest="mode"
    )
    unpack_parser = subparser.add_parser("unpack")
    repack_parser = subparser.add_parser("repack")

    unpack_group = unpack_parser.add_mutually_exclusive_group(required=True)
    unpack_group.add_argument("-f", "--file", type=pathlib.Path, help="Input file path")
    unpack_group.add_argument(
        "-d", "--directory", type=pathlib.Path, help="Input directory path"
    )

    repack_parser.add_argument(
        "-i", "--input", type=pathlib.Path, required=True, help="Input file path"
    )
    repack_parser.add_argument(
        "-o", "--output", type=pathlib.Path, required=True, help="Output file path"
    )

    return parser.parse_args()


def unpack_mode(input: pathlib.Path, output: pathlib.Path) -> None:
    """
    Unpacks the configuration from the input file and writes it to the output file.

    :param input: The path to the input PE containing the configuration.
    :param output: The path to the output file where the unpacked configuration will be written.
    """
    if not (
        encrypted_configuration := configuration.read_encrypted_configuration(input)
    ):
        raise RuntimeError(f"Failed to load encrypted configuration from {input}")

    key, raw_configuration = configuration.decrypt_encrypted_configuration(
        encrypted_configuration
    )
    output.write_text(
        json.dumps(
            {
                "configuration_encryption_key": base64.b64encode(key).decode("utf-8"),
                "configuration": configuration.unpack_configuration(raw_configuration),
            }
        )
    )


def repack_mode(input: pathlib.Path, output: pathlib.Path) -> None:
    """
    Repack the input file configuration in the the output file.

    :param input: The path to the input configuration file.
    :param output: The path to the output PE where the configuration will be repacked.
    """
    j = json.loads(input.read_text())

    configuration.patch_encrypted_configuration(
        output,
        configuration.encrypt_configuration(
            configuration.pack_configuration(j["configuration"]),
            base64.b64decode(j["configuration_encryption_key"].encode()),
        ),
    )


def pass_exception_unpack_mode(input: pathlib.Path, output: pathlib.Path) -> None:
    try:
        unpack_mode(input, output)
    except Exception as e:
        print(f"Failed to unpack configuration from {input}:")
        traceback.print_exc()
        print()


def main() -> None:
    args = parse_arguments()
    if args.mode == "unpack":
        if args.file:
            unpack_mode(args.file, args.file.with_suffix(".json"))
        else:
            utils.map_files_directory(
                args.directory,
                lambda x: pass_exception_unpack_mode(x, x.with_suffix(".json")),
            )

    else:
        repack_mode(args.input, args.output)


if __name__ == "__main__":
    main()
