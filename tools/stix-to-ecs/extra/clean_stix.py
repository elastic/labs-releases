# coding: utf-8

import argparse
import pathlib
import json
import typing

OPENCTI = "x_opencti_"
OLD_TLP = "clear"
NEW_TLP = "white"


def cleaning_callback(node: typing.Any) -> typing.Any:
    """
    The function clean (or correct) a Json node if possible according to the following rules:
        - "x_open_cti_*" -> "x_*".
        - "white" -> "clear".

    :param: The Json node to be processed.
    :return: The Json node post processing.
    """

    if type(node) is dict:
        for k in list(node.keys()):
            if k.startswith(OPENCTI):
                node[k.replace(OPENCTI, "x_")] = node.pop(k)

            if k == "name" or k == "tlp":
                if (tmp := node[k].lower()).endswith(OLD_TLP):
                    tmp = tmp.replace(OLD_TLP, NEW_TLP)
                    node[k] = tmp.upper() if node[k].isupper() else tmp

    return node


def clean_stix(stix: str) -> str:
    """
    The function clean a string containing STIX data.
    :param stix: STIX data to be cleaned.
    :return: Cleaned STIX data
    """

    return json.dumps(visit_json(json.loads(stix), cleaning_callback))


def main() -> None:
    args = parse_arguments()
    with args.input.open("r") as i:
        with args.output.open("w") as o:
            o.write(clean_stix(i.read()))


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clean a STIX document according to a set of hardcoded rules."
    )
    parser.add_argument(
        "-i", "--input", type=pathlib.Path, required=True, help="Input file path"
    )
    parser.add_argument(
        "-o", "--output", type=pathlib.Path, required=True, help="Output file path"
    )
    return parser.parse_args()


def visit_json(
    root_node: dict[str, typing.Any], callback: typing.Callable
) -> dict[str, typing.Any]:
    """
    The function visit a Json tree and apply the provided callback on each node.
    :param root_node: The Json root node.
    :param callback: The callback to be applyed on each node of the tree.
    :return: The Json root node
    """

    return visit_json_aux(root_node, callback)


def visit_json_aux(
    node: typing.Any,
    callback: typing.Callable,
) -> typing.Any:
    """
    The function apply the callback on the current node and recursively call this function on node's children.
    :param node: The current Json node.
    :param callback: The callback to be applyed on the current node.
    :return: The current node
    """

    node = callback(node)

    t = type(node)
    if t is dict:
        for k, v in node.items():
            node[k] = visit_json_aux(v, callback)

    elif t is list:
        for i, x in enumerate(node):
            node[i] = visit_json_aux(x, callback)

    return node


if __name__ == "__main__":
    main()
