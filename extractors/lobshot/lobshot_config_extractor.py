import argparse
import pathlib
import lief
import typing

from nightmare.malware.lobshot import configuration
from nightmare import utils


def get_rdata_section_content(file_path: pathlib.Path) -> None | bytes:
    pe = lief.parse(str(file_path))
    if not pe:
        return None
    for section in pe.sections:
        if section.name.lower() == ".rdata":
            return bytes(section.content)
    else:
        return None


def extract_configuration(
    path: pathlib.Path,
) -> typing.Optional[tuple[bytes, int | None]]:
    rdata = get_rdata_section_content(path)
    if not rdata:
        print(".rdata section not found: {}\n".format(path))
        return None

    return configuration.parse(rdata)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("LOBSHOT config file extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=pathlib.Path, help="LOBSHOT file path")
    group.add_argument("-d", "--directory", type=pathlib.Path, help="LOBSHOT directory")
    return parser.parse_args()


def display_results(
    path: pathlib.Path, configuration: tuple[bytes, typing.Optional[int]]
) -> None:
    print("File: {}".format(path))
    print("IP: {}".format(configuration[0].decode("utf-8")))
    print("Port: {}\n".format(configuration[1]))


def print_banner() -> None:
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


def main() -> None:
    lief.logging.disable()

    print_banner()

    args = parse_arguments()
    if args.file:
        configuration = extract_configuration(args.file)
        if not configuration:
            print("Failed to extract configuration from {}".format(args.file))
            return
        display_results(args.file, configuration)

    if args.directory:
        for path, configuration in utils.map_files_directory(
            args.directory, extract_configuration
        ):
            if not configuration:
                print("Failed to extract configuration from {}".format(path))
                continue

            display_results(path, configuration)


if __name__ == "__main__":
    main()
