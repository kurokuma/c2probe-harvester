#!/usr/bin/env python3
"""Decode a file with a single-byte XOR key; never execute its contents."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


def xor_key(value):
    try:
        key = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use decimal or hexadecimal, e.g. 40 or 0x28") from exc
    if not 0 <= key <= 255:
        raise argparse.ArgumentTypeError("key must be in 0..255")
    return key


def decode_stream(source, destination, key):
    table = bytes(value ^ key for value in range(256))
    input_hash = hashlib.sha256()
    output_hash = hashlib.sha256()
    size = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        decoded = chunk.translate(table)
        destination.write(decoded)
        input_hash.update(chunk)
        output_hash.update(decoded)
        size += len(chunk)
    return {"bytes": size, "xor_key": f"0x{key:02x}",
            "input_sha256": input_hash.hexdigest(),
            "output_sha256": output_hash.hexdigest(), "executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="raw response body, without the protocol header")
    parser.add_argument("--key", required=True, type=xor_key, help="single-byte key, e.g. 0x28")
    parser.add_argument("--output", required=True, type=Path, help="new output file; no overwrite")
    args = parser.parse_args(argv)
    try:
        # Exclusive creation protects both existing outputs and the original input.
        with args.input.open("rb") as source, args.output.open("xb") as destination:
            result = decode_stream(source, destination, args.key)
        result.update(input=str(args.input.resolve()), output=str(args.output.resolve()))
        print(json.dumps(result, indent=2))
        return 0
    except OSError as exc:
        print(f"XOR decoding failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
