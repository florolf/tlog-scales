import argparse
import logging

from .reader import TilesReader
from .utils import b64enc
from . import backend, tlog


def resolve_index(cp: tlog.Checkpoint, index: int) -> int:
    if index >= 0:
        return index
    else:
        return cp.size + index


def cmd_gen_proof(args) -> None:
    reader = TilesReader(backend.make_backend(args.location))

    cp = reader.get_checkpoint()

    index = resolve_index(cp, args.leaf_index)
    proof = reader.get_inclusion_proof(index, cp.size)

    print('c2sp.org/tlog-proof@v1')
    print(f'index {index}')
    for h in proof.node_hashes:
        print(b64enc(h))

    print('')

    print(cp.serialize(), end='')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tlog-tiles")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subcmd = subparsers.add_parser("gen-proof", help="Generate an inclusion proof for a leaf")
    subcmd.add_argument("location", help="Location of the log (URL or path)")
    subcmd.add_argument("leaf_index", type=int, help="Leaf index (negative for tree-size relative indexing, -1 -> last leaf)")
    subcmd.set_defaults(func=cmd_gen_proof)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    args.func(args)


if __name__ == "__main__":
    main()
