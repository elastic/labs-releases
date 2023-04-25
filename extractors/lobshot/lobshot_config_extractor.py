# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under 
# one or more contributor license agreements. Licensed under the Elastic License 2.0; 
# you may not use this file except in compliance with the Elastic License 2.0.

# LOBSHOT configuration extractor from Elastic Security Labs.

import argparse
import pathlib
import pefile
import re

IP_ADDRESS_REGEX = rb"^([0-9]{1,3}\.){3}[0-9]{1,3}$"
PORT_REGEX = rb"^[0-9]{1,5}$"


def retrieve_file_paths_in_directory(path: pathlib.Path) -> list[pathlib.Path]:
    if not path.is_dir():
        raise RuntimeError("Path is not a directory")

    return list(path.rglob("*"))


def perform_extraction_directory(
    file_paths: list[pathlib.Path],
) -> list[tuple[bytes, int | None, pathlib.Path]]:
    directory_results: list[tuple[bytes, int | None, pathlib.Path]] = list()
    for file in file_paths:
        rdata = parse_file(file)
        if rdata != None:
            candidates = generate_candidates(rdata)
            try:
                directory_results.append(decrypt_candidates(candidates, file))
            except RuntimeError:
                print(
                    "Configuration unsuccessful, could not extract IP/Port {}\n".format(
                        file
                    )
                )
                continue
    return directory_results


def perform_extraction_file(
    file_path: pathlib.Path,
) -> tuple[bytes, int | None, pathlib.Path]:
    rdata = parse_file(file_path)
    if not rdata:
        raise RuntimeError(".rdata section not found")

    candidates = generate_candidates(rdata)
    return decrypt_candidates(candidates, file_path)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("LOBSHOT config file extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=pathlib.Path, help="LOBSHOT file path")
    group.add_argument("-d", "--directory", type=pathlib.Path, help="LOBSHOT directory")
    return parser.parse_args()


def string_decryption(encrypted_data: bytes) -> bytes:
    buffer = bytearray([0 for _ in range(len(encrypted_data) // 2)])

    flag = False
    z = 0
    index = 0
    index2 = 2

    for i, x in enumerate(encrypted_data):
        try:
            y = encrypted_data[index + 1] - 0x61
            index += 2

            if flag:
                buffer[i] = 0x53 ^ z ^ (y | (16 * encrypted_data[index2] - 16)) & 0xFF
                index2 += 2
            else:
                flag = True
                z = y | (16 * (x - 1)) & 0xFF
        except (IndexError, ValueError):
            continue

    buffer = buffer[1:]
    return buffer


def parse_file(file_path: pathlib.Path) -> None | bytes:
    with open(file_path, "rb") as data:
        data = data.read()
        pe = pefile.PE(data=data)
        for section in pe.sections:
            if b"rdata" in section.Name:
                rdata = section.get_data()
                return rdata
        else:
            print(".rdata section not found in {}\n".format(file_path.name))
            return None


def generate_candidates(section_data: bytes) -> list[bytes]:
    candidates: list[bytes] = list()
    blocks = section_data.split(b"\x00")
    blocks = [x for x in blocks if x != b""]
    for block in blocks:
        if len(block) > 3 and not b"\\" in block:
            candidates.append(block)
    return candidates


def decrypt_candidates(
    candidates: list[bytes], file_path: pathlib.Path
) -> tuple[bytes, int | None, pathlib.Path]:
    result_ip = None
    result_port = None
    for string in candidates:
        decrypted_string = string_decryption(string)
        if re.search(IP_ADDRESS_REGEX, decrypted_string):
            result_ip = decrypted_string
        if re.search(PORT_REGEX, decrypted_string):
            result_port = int(decrypted_string)
    if not result_ip:
        raise RuntimeError(
            "Configuration unsuccessful, could not extract IP/Port {}\n".format(
                file_path.name
            )
        )

    return result_ip, result_port, file_path


def display_results(result: tuple[bytes, int | None, pathlib.Path]) -> None:
    print("FILE: {}".format(result[2].name))
    print("IP: {}".format(result[0].decode("utf-8")))
    print("Port: {}\n".format(result[1]))


def main() -> None:
    print(
        r"""
  _       ____   ____    _____  _    _   ____  _______      ____
 | |     / __ \ |  _ \  / ____|| |  | | / __ \|__   __|    /xxxx\
 | |    | |  | || |_) || (___  | |__| || |  | |  | |      |xxxxxx| 
 | |    | |  | ||  _ <  \___ \ |  __  || |  | |  | |      |xxxxxx|  
 | |____| |__| || |_) | ____) || |  | || |__| |  | |      \xxxxxx/  
 |______|\____/ |____/ |_____/ |_|  |_| \____/   |_|       \xxxx/
                                                            \--/
   _____                __  _          ______        _       ||             _               
  / ____|              / _|(_)        |  ____|      | |      ||            | |              
 | |      ___   _ __  | |_  _   __ _  | |__   __  __| |_  _ __  __ _   ___ | |_  ___   _ __ 
 | |     / _ \ | '_ \ |  _|| | / _` | |  __|  \ \/ /| __|| '__|/ _` | / __|| __|/ _ \ | '__|
 | |____| (_) || | | || |  | || (_| | | |____  >  < | |_ | |  | (_| || (__ | |_| (_) || |   
  \_____|\___/ |_| |_||_|  |_| \__, | |______|/_/\_\ \__||_|   \__,_| \___| \__|\___/ |_|   
                                __/ |                        ||
         ,odOO"bo,                                           ||   
       ,dOOOP'dOOOb,                                         ||
      ,O3OP'dOO3OO33,                                        ||
      P",ad33O333O3Ob                                        []
      ?833O338333P",d     
      `88383838P,d38'
      `Y8888P,d88P' 
       `"?8,8P"'                                                 
 """
    )

    args = parse_arguments()
    if args.file:
        ip_port_results = perform_extraction_file(args.file)
        if not ip_port_results:
            raise RuntimeError(
                "Configuration unsuccessful, could not extract IP/Port\n"
            )
        display_results(ip_port_results)

    elif args.directory:
        file_paths = retrieve_file_paths_in_directory(args.directory)
        ip_port_results_directory = perform_extraction_directory(file_paths)
        for result in ip_port_results_directory:
            if not result:
                raise RuntimeError(
                    "Configuration unsuccessful, could not extract IP/Port\n"
                )
            display_results(result)


if __name__ == "__main__":
    main()
