# coding: utf-8

from __future__ import annotations

import pathlib
import json
import copy
import argparse
import sys
import elasticsearch
import typing
import getpass
import dataclasses

from stix2 import pattern_visitor
from stix2 import patterns

T = typing.TypeVar("T")

Json = dict[str, T]
ECSIndicator = STIXIndicator = Json
ECSIndicators = STIXIndicators = list[Json]


@dataclasses.dataclass
class ElasticInformation:
    url: str
    auth: tuple[str, str]
    index: str


MARKING_TO_TLP = {
    "613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",
    "34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "826578e1-40ad-459f-bc73-ede076f81f37": "amber_strict",
    "5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}

STIX_ECS_WORD_MAPPING = {
    "hashes": "hash",
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
}

ECS_WORD_FIELD_MAPPING = {
    "domain-name": "domain",
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
}

# ctf -> Add an ECS type here to disable it
UNSUPPORTED_ECS_INDICATOR_TYPES = {
    "cryptographic-key",
}


class STIXToECSPatternParser(object):
    """
    A class to parse and convert a STIX pattern into ECS data.
    """

    def __init__(self, pattern: str) -> None:
        """
        Intialize the parser then parse and convert the given STIX pattern into ECS data.
        :param pattern: The STIX pattern to parse and convert.
        """

        self.__loot = list()
        self.__type = ""
        self.__field_name = ""
        self.__data: dict = dict()

        self.__visit(pattern_visitor.create_pattern_object(pattern))
        if not self.__loot:
            raise RuntimeError("No loot, parsing failed")

        self.__set_type()
        if not self.__type:
            raise RuntimeError("No type, parsing failed")

        self.__set_field_name()
        if not self.__field_name:
            raise RuntimeError("No field name, parsing failed")

        self.__set_data()
        if not self.__data:
            raise RuntimeError("No data, parsing failed")

    def __set_data(self) -> STIXToECSPatternParser:
        match self.__type:
            case "file":
                self.__set_file_data()
            case _:
                self.__set_other_data()
        return self

    def __set_field_name(self) -> STIXToECSPatternParser:
        self.__field_name = convert_ecs_word_to_field(self.__type)
        return self

    def __set_file_data(self) -> STIXToECSPatternParser:
        for x in self.__loot:
            if not x[1] in self.__data.keys():
                self.__data[x[1]] = dict()

            # ctf -> I.e property: "sha256:..., sha1:..., etc"
            # ctf -> Will break if property length is > 2, i.e "sha256:sha1:..."
            properties = x[2].split(":")
            match len(properties):
                case 1:
                    self.__data[x[1]] = properties[0]
                case 2:
                    self.__data[x[1]][properties[0]] = properties[1]
                case _:
                    raise NotImplemented(f"Properties length is > 2")

        return self

    def __set_other_data(self) -> STIXToECSPatternParser:
        # ctf -> Fragile, expect to break if pattern is more complex. Need counter example if any.
        self.__data = self.__loot[0][2]
        return self

    def __set_type(self) -> STIXToECSPatternParser:
        self.__type = self.__loot[0][0]
        for x in self.__loot[1:]:
            if x[0] != self.__type:
                raise RuntimeError(
                    f"Inconsistent types detected in pattern, must be {self.__type} but found {x[0]}"
                )

        return self

    def __visit(self, o) -> STIXToECSPatternParser:
        ot = type(o)

        match ot:
            case patterns.ObservationExpression:
                self.__visit(o.operand)
            case patterns.OrBooleanExpression | patterns.AndBooleanExpression:
                for op in o.operands:
                    self.__visit(op)
            case patterns.ParentheticalExpression:
                self.__visit(o.expression)
            case patterns.EqualityComparisonExpression:
                self.__visit_equality_comparison_expression(o)
            case _:
                raise NotImplemented(ot)
        return self

    def __visit_equality_comparison_expression(self, o) -> STIXToECSPatternParser:
        lhs = o.lhs
        rhs = o.rhs

        if not (t := type(lhs)) == patterns.ObjectPath:
            raise NotImplemented(t)

        if not (t := type(rhs)) == patterns.StringConstant:
            raise NotImplemented(t)

        self.__loot.append(
            (
                convert_stix_word_to_ecs_word(lhs.object_type_name),
                convert_stix_word_to_ecs_word(lhs.property_path[0].property_name),
                ":".join(
                    [
                        convert_stix_word_to_ecs_word(x.property_name)
                        for x in lhs.property_path[1:]
                    ]
                    + [rhs.value]
                ),
            )
        )

        return self

    @property
    def data(self) -> dict:
        """
        Get ECS data.
        """

        return copy.deepcopy(self.__data)

    @property
    def description(self) -> str:
        """
        Get ECS description.
        """

        if type(self.data) is dict and (hash := self.data.get("hash", None)):
            # ctf -> SHA256 may not be always available, in this case do we want to crash or take an other algo?
            observable = hash.get("sha256", None) or hash.get("sha1", None) or hash.get("md5", None)
            if not observable:
                raise RuntimeError("Missing SHA256, SHA1, or MD5 observable from set of hashes.")
        else:
            observable = self.data

        return f"Simple indicator of observable {{{observable}}}"

    @property
    def field_name(self) -> str:
        """
        Get ECS field name.
        """

        return self.__field_name

    @property
    def type(self) -> str:
        """
        Get ECS type.
        """

        return self.__type


def check_arguments(args: argparse.Namespace) -> bool:
    """
    The function check if the provided arguments are correctly used.
    :param args: The parsed arguments.
    :return: True if the arguments are corrects, False otherwise.
    """

    if args.recursive and not args.input.is_dir():
        print("argument -r only allowed if input is a directory")
        return False

    if args.elastic:
        for x in ["url", "index", "user"]:
            if not getattr(args, x):
                print(
                    f"argument --{x} is required to connect to the Elastic cluster (-e, --elastic)"
                )
                return False

    return True


def convert_ecs_word_to_field(word: str) -> str:
    """
    The function convert the given ECS word into an ECS field.
    :param word: The ECS word to convert to field.
    :return: The ECS field.
    """

    return ECS_WORD_FIELD_MAPPING.get(word, word)


def convert_stix_indicator_to_ecs_indicator(
    stix_indicator: dict, provider: str | None
) -> dict:
    """
    The function convert a STIX indicator into an ECS indicator.
    :param stix_indicator: The STIX indicator to be converted.
    :param provider: An optional provider string that will be used to override the parsed provider.
    :return: The ECS indicator.
    """

    parser = STIXToECSPatternParser(stix_indicator["pattern"])

    tmp = dict()
    tmp[parser.field_name] = parser.data
    tmp["type"] = parser.type
    tmp["description"] = parser.description

    if first_seen := stix_indicator.get("created", None):
        tmp["first_seen"] = first_seen

    if provider:
        tmp["provider"] = provider
    elif provider_ := stix_indicator.get("created_by_ref", None):
        tmp["provider"] = provider_

    if external_references := stix_indicator.get("external_references", None):
        tmp["reference"] = [x["url"] for x in external_references]

    if labels := stix_indicator.get("labels", None):
        tmp["tags"] = labels

    if modified := stix_indicator.get("modified", None):
        tmp["modified_at"] = modified

    if (markings := stix_indicator.get("object_marking_refs", None)) and (
        tlp := parse_tlp(markings)
    ):
        tmp["marking"] = {"tlp": tlp}

    return {"threat": {"indicator": tmp}}


def convert_stix_indicators_to_ecs_indicators(
    stix_indicators: list[dict], provider: str | None
) -> list[dict]:
    """
    The function convert a list of STIX indicators into a list of ECS indicators.
    :param stix_indicators: The list of STIX indicators to be converted.
    :param provider: An optional provider string that will be used to override the parsed provider.
    :return: The list of ECS indicators.
    """

    return [
        convert_stix_indicator_to_ecs_indicator(x, provider)
        for x in filter(is_stix_indicator, stix_indicators)
    ]


def convert_stix_word_to_ecs_word(word: str) -> str:
    """
    The function convert the given STIX word into an ECS word.
    :param word: The STIX word to convert into a ECS word.
    :return: The ECS word.
    """

    return STIX_ECS_WORD_MAPPING.get(word, word)


def flatten_list(l: list[list[T]]) -> list[T]:
    tmp = list()
    for x in l:
        tmp += x
    return tmp


def format_ecs_indicator_for_elastic(ecs_indicator: ECSIndicator) -> ECSIndicator:
    """
    The function format an ECS indicator for Elastic.
    :param ecs_indicator: The ECS indicator to be formatted.
    :return: The formatted ECS indicator.
    """

    result = copy.deepcopy(ecs_indicator)
    result["@timestamp"] = result["threat"]["indicator"]["first_seen"]
    result["event"] = {"category": "threat", "kind": "enrichment", "type": "indicator"}
    return result


def get_json_files(path: pathlib.Path, recursive: bool) -> list[pathlib.Path]:
    """
    The function generate the list of Json files at path, if the parameter is a file it returns [path].
    :param path: The root directory path where we want to get Json files or the path to a file.
    :param recursive: Enable recursive traversal of directory.
    :return: The list of found Json files or [path] if path is a file.
    """

    return (
        [path]
        if path.is_file()
        else list(path.rglob("*.json") if recursive else path.glob("*.json"))
    )


def get_password() -> str:
    """
    Get the predefined password.
    
    This function returns a predefined password without requiring user input.
    
    :return: The predefined password.
    """
    # Predefined password
    predefined_password = "your_predefined_password_here"
    return predefined_password

# Example usage of the get_password function
password = get_password()
print("Password has been set programmatically.")



def is_stix_indicator(stix_object: dict) -> bool:
    """
    The function check if a STIX object is an indicator.
    :param stix_object: The STIX object to be checked.
    :return: True if the STIX object is an indicator, False otherwise.
    """

    return stix_object["type"] == "indicator"


def is_supported_ecs_indicator(ecs_indicator: dict) -> bool:
    """
    The function check if a STIX object is an indicator.
    :param stix_object: The STIX object to be checked.
    :return: True if the STIX object is an indicator, False otherwise.
    """
    return (
        ecs_indicator["threat"]["indicator"]["type"]
        not in UNSUPPORTED_ECS_INDICATOR_TYPES
    )


def load_stix_objects_from_file(input_path: pathlib.Path) -> list[dict]:
    """
    The function load STIX objects from a file.
    :param input_path: The path of the file containing STIX objects.
    :return: A list of STIX objects.
    """

    with input_path.open("r") as f:
        objects = json.load(f).get("objects", None)

    if not objects:
        raise RuntimeError('"objects field doesn\'t exist"')

    return [dict(x) for x in objects]


def main() -> None:
    args = parse_arguments()

    files = get_json_files(args.input if args.input else args.directory, args.recursive)
    results = process_stix_files(files, args.provider)

    if not args.output and not args.elastic:
        print(json.dumps(flatten_list(results), indent=4))
    else:
        if args.output:
            write_ecs_files(zip(files, results), args.output)

        if args.elastic:
            write_ecs_to_elastic(
                flatten_list(results),
                ElasticInformation(args.url, (args.user, get_password()), args.index),
            )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        sys.argv[0],
        description="Convert STIX indicator(s) into ECS indicator(s)",
    )

    parser.add_argument(
        "-i",
        "--input",
        type=pathlib.Path,
        help="STIX input file or directory",
        required=True,
    )

    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        help="ECS output directory",
    )

    parser.add_argument(
        "-e", "--elastic", action="store_true", help="Write to Elastic cluster"
    )

    parser.add_argument(
        "--index",
        help="Elastic cluster's index where ECS indicators will be written, required with -e,--elastic",
    )

    parser.add_argument(
        "--url", help="The URL of the Elastic cluster, required with -e,--elastic"
    )

    parser.add_argument(
        "--user",
        help="The authentification username for connecting to the Elastic cluster, required with -e,--elastic",
    )

    parser.add_argument("-p", "--provider", help="Override ECS provider")

    parser.add_argument(
        "-r",
        "--recursive",
        help="Recursive processing when input is a directory",
        action="store_true",
    )

    args = parser.parse_args()
    if not check_arguments(args):
        parser.print_usage()
        exit(1)

    return args


def parse_tlp(markings: list[str]) -> str | None:
    """
    The function parse a TLP string from a list of marking definitions if any.
    :param markings: A list of marking definitions.
    :return: A TLP if found, None otherwise.
    """

    for x in markings:
        if tlp := MARKING_TO_TLP.get(x.replace("marking-definition--", ""), None):
            return tlp
    else:
        return None


def process_stix_file(input_file: pathlib.Path, provider: str | None) -> list[dict]:
    """
    The function load objects from a STIX file and generate a list of ECS indicators for each compatible STIX indicator object.
    :param input_file: Path of the file to be processed.
    :param provider: An optional provider string that will be used to override the parsed provider.
    :return: A list of ECS indicators.
    """

    return list(
        filter(
            is_supported_ecs_indicator,
            convert_stix_indicators_to_ecs_indicators(
                load_stix_objects_from_file(input_file), provider
            ),
        )
    )


def process_stix_files(
    input_files: list[pathlib.Path], provider: str | None
) -> list[list[dict]]:
    """
    The function will process a list of STIX files.
    :param input_files: The list of files to be processed.
    :param provider: An optional provider string that will be used to override the parsed provider.
    :return: A list containing ECS indicators for each processed file.
    """

    return [process_stix_file(x, provider) for x in input_files]


def write_ecs_files(
    ecs_files: typing.Iterable[tuple[pathlib.Path, ECSIndicators]],
    output_path: pathlib.Path,
) -> None:
    """
    The function write each set of indicators to their files in the given directory.
    :param ecs_files: The list of tuples containing the output file path and the associated set of indicators.
    :param output_path: The path of the directory where file will be written.
    """

    output_path.mkdir(exist_ok=True)
    for x in ecs_files:
        with output_path.joinpath(f"{x[0].stem}.ecs.ndjson").open("w") as f:
            f.write("\n".join(json.dumps(x) for x in x[1]))


def write_ecs_to_elastic(
    ecs_indicators: ECSIndicators,
    elastic_information: ElasticInformation,
) -> None:
    """
    The function write each ECS indicator to the given Elastic cluster and index.
    :param url: The Elastic cluster URL.
    :param auth: A tuple containing the username and password to connect to the cluster.
    :param index: The index where documents will be written.
    """

    elastic = elasticsearch.Elasticsearch(
        hosts=elastic_information.url, basic_auth=elastic_information.auth, verify_certs=False
    )

    if not elastic.ping():
        raise RuntimeError(
            f"Failed to connect to Elastic cluster at {elastic_information.url}"
        )

    for x in map(format_ecs_indicator_for_elastic, ecs_indicators):
        elastic.index(index=elastic_information.index, document=x)


if __name__ == "__main__":
    main()