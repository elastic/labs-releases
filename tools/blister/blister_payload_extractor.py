# coding: "utf-8"
import argparse
import pathlib
import lief
import pprint
import functools
import json

from nightmare.malware.blister import configuration
from nightmare import utils


def extract_configuration(file: pathlib.Path) -> configuration.Configuration | None:
    """
    Extracts configuration from a Blister sample.

    :param file: The path to the PE binary file.
    :return: The configuration object extracted from the binary if successful.
             None if extraction fails or encounters an exception.
    """
    try:
        with file.open("rb") as f:
            data = f.read()
        return configuration.extract_configuration(data)
    except Exception as e:
        print(e)
        return None


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("Blister config file extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=pathlib.Path, help="Blister file path")
    group.add_argument("-d", "--directory", type=pathlib.Path, help="Blister directory")
    parser.add_argument(
        "-o",
        "--outdir",
        type=pathlib.Path,
        help="Blister output directory",
        required=True,
    )
    return parser.parse_args()


def process_blister_sample(file: pathlib.Path, outdir: pathlib.Path) -> None:
    if not file.is_file():
        return
    if not (blister_config := extract_configuration(file)):
        print("Failed to extract configuration from {}".format(file))
        return
    pprint.pprint(blister_config.__dict__(), sort_dicts=False)
    outdir.mkdir(parents=True, exist_ok=True)
    payload_file_name = file.name + ".payload"
    utils.write_files(outdir, {payload_file_name: blister_config.blister_payload})
    print("\nPayload written to {}".format(str(outdir.joinpath(payload_file_name))))
    json_file_name = file.name + ".json"
    utils.write_files(
        outdir,
        {json_file_name: json.dumps(blister_config.__dict__()).encode("utf-8")},
    )
    print(
        "Payload configuration written to {}".format(
            str(outdir.joinpath(json_file_name))
        )
    )


def print_banner() -> None:
    print(
        r"""
  ____  _ _     _              _____            _                 _   ______      _                  _             
 |  _ \| (_)   | |            |  __ \          | |               | | |  ____|    | |                | |            
 | |_) | |_ ___| |_ ___ _ __  | |__) |_ _ _   _| | ___   __ _  __| | | |__  __  _| |_ _ __ __ _  ___| |_ ___  _ __ 
 |  _ <| | / __| __/ _ \ '__| |  ___/ _` | | | | |/ _ \ / _` |/ _` | |  __| \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
 | |_) | | \__ \ ||  __/ |    | |  | (_| | |_| | | (_) | (_| | (_| | | |____ >  <| |_| | | (_| | (__| || (_) | |   
 |____/|_|_|___/\__\___|_|    |_|   \__,_|\__, |_|\___/ \__,_|\__,_| |______/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
                                           __/ |                                                                   
                                          |___/                                                                                                                                   
"""
    )


def main() -> None:
    lief.logging.disable()
    print_banner()
    args = parse_arguments()
    outdir = args.outdir.resolve()
    f = functools.partial(process_blister_sample, outdir=outdir)

    if args.file:
        process_blister_sample(args.file, outdir)

    elif args.directory:
        utils.map_files_directory(args.directory, f)


if __name__ == "__main__":
    main()
