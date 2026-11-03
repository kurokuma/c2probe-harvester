#!/usr/bin/env python3
"""Decode a downloaded VVAS stage and carve embedded PE images to standalone files.

Turns a raw VVAS stage (e.g. ``sample.bin`` produced by ``download_sample.py``)
into clean, pefile-parseable PE files ready for static analysis
(rabin2/Ghidra/pefile).

The on-wire stage is obfuscated per session. Two obfuscation schemes are
recovered automatically, in order:

1. single-byte XOR (the common case; keys 40 / 54 observed in the wild);
2. repeating multi-byte XOR, recovered from the long zero-padding inside the
   embedded PE via column frequency analysis (the key byte at each position is
   simply the most common cipher byte in that column, because 0x00 dominates a
   PE). This handles variants whose body does not carve with a single byte.

A true stream cipher (RC4 and friends) leaves no repeating structure, so it
cannot be brute-forced blindly: when no key is found the stage's byte entropy is
reported so a high-entropy "likely stream cipher, needs the stager key" case can
be told apart from plain truncation.

No code is executed. Carved images are written with a ``.bin`` extension on
purpose so they cannot be launched by a double-click.

Usage:
    python scripts/extract_sample.py <stage.bin> --out <dir>
    python scripts/extract_sample.py <stage.bin> --out <dir> --xor-key 0x36
    python scripts/extract_sample.py <stage.bin> --out <dir> --xor-key-hex 1a2b3c4d
    python scripts/extract_sample.py <stage.bin> --out <dir> --max-keylen 64
"""

import argparse
import hashlib
import json
import re
from collections import Counter
from math import log2
from pathlib import Path

import pefile

MACHINES = {0x14C: "i386", 0x8664: "amd64"}
DEFAULT_MAX_KEYLEN = 48


def xor(data, key):
    """Single-byte XOR via a 256-entry translation table (fast)."""
    return data.translate(bytes(b ^ key for b in range(256)))


def xor_repeating(data, key):
    """XOR ``data`` with a repeating multi-byte ``key`` (1 byte uses translate)."""
    if len(key) == 1:
        return xor(data, key[0])
    n = len(data)
    keystream = (key * (n // len(key) + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")).to_bytes(n, "big")


def guess_repeating_key(raw, length):
    """Recover a length-``length`` repeating XOR key from zero-padding.

    Each key byte is the most common cipher byte in its column: XORing a region
    of 0x00 (PE section padding, which dominates a PE image) with a repeating
    key reproduces the key, so the modal byte per column is the key byte.
    """
    key = bytearray()
    for i in range(length):
        column = raw[i::length]
        if not column:
            return None
        key.append(Counter(column).most_common(1)[0][0])
    return bytes(key)


def declared_size(pe):
    ends = [pe.OPTIONAL_HEADER.SizeOfHeaders]
    for section in pe.sections:
        ends.append(section.PointerToRawData + section.SizeOfRawData)
    return max(ends)


def find_pes(decoded):
    """Return [(offset, pe)] for every MZ that parses as a known-machine PE."""
    images = []
    for match in re.finditer(b"MZ", decoded):
        offset = match.start()
        try:
            pe = pefile.PE(data=decoded[offset:], fast_load=True)
        except pefile.PEFormatError:
            continue
        if pe.FILE_HEADER.Machine in MACHINES:
            images.append((offset, pe))
    return images


def score_key(decoded, images):
    """Prefer keys where DLLs with a real export table are fully present."""
    score = 0
    for offset, pe in images:
        missing = max(0, declared_size(pe) - (len(decoded) - offset))
        score += (1000 if pe.is_dll() else 100)
        if missing:
            score -= 10
    return score


def entropy(data):
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * log2(c / total) for c in Counter(data).values())


def detect_key(raw, forced_byte=None, forced_hex=None, max_keylen=DEFAULT_MAX_KEYLEN):
    """Return (scheme, key_bytes, decoded, images) for the best key, or None.

    ``scheme`` is ``"xor1"`` for a single byte or ``"xorN"`` for an N-byte
    repeating key. A forced key is used as given (and still has to yield a PE).
    """
    if forced_hex is not None:
        key = bytes.fromhex(forced_hex)
        decoded = xor_repeating(raw, key)
        images = find_pes(decoded)
        return (f"xor{len(key)}", key, decoded, images) if images else None
    if forced_byte is not None:
        decoded = xor(raw, forced_byte)
        images = find_pes(decoded)
        return ("xor1", bytes([forced_byte]), decoded, images) if images else None

    # (score, -keylen, key_bytes, decoded, images); higher score wins, shorter key breaks ties.
    best = None

    def consider(key, decoded, images):
        nonlocal best
        if not images:
            return
        candidate = (score_key(decoded, images), -len(key), key, decoded, images)
        if best is None or candidate[:2] > best[:2]:
            best = candidate

    for key in range(256):
        decoded = xor(raw, key)
        consider(bytes([key]), decoded, find_pes(decoded))

    for length in range(2, max_keylen + 1):
        key = guess_repeating_key(raw, length)
        if key is None:
            continue
        decoded = xor_repeating(raw, key)
        consider(key, decoded, find_pes(decoded))

    if best is None:
        return None
    _, neg_len, key, decoded, images = best
    return (f"xor{len(key)}", key, decoded, images)


def exports(pe):
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    names = []
    if directory:
        for symbol in directory.symbols:
            if symbol.name:
                names.append(symbol.name.decode(errors="replace"))
    module = None
    if directory and directory.struct.Name:
        raw = pe.get_string_at_rva(directory.struct.Name)
        if raw:
            module = raw.decode(errors="replace")
    return module, names


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("stage", type=Path, help="raw VVAS stage, e.g. sample.bin")
    parser.add_argument("--out", type=Path, required=True, help="output directory (created)")
    parser.add_argument("--xor-key", type=lambda v: int(v, 0), help="force single-byte XOR key")
    parser.add_argument("--xor-key-hex", help="force a multi-byte repeating XOR key (hex)")
    parser.add_argument("--max-keylen", type=int, default=DEFAULT_MAX_KEYLEN,
                        help="max repeating-XOR key length to search (default %d)" % DEFAULT_MAX_KEYLEN)
    args = parser.parse_args(argv)

    raw = args.stage.read_bytes()
    found = detect_key(raw, args.xor_key, args.xor_key_hex, args.max_keylen)
    if not found:
        bits = entropy(raw)
        hint = ("high entropy, likely a stream cipher (e.g. RC4) — needs the stager's "
                "key derivation, not brute force" if bits >= 7.5 else
                "low/medium entropy — possibly truncated or an unmodelled wrapper")
        raise SystemExit(
            "no embedded PE found after single- and multi-byte XOR search "
            f"(stage entropy {bits:.2f} bits/byte: {hint})")
    scheme, key, decoded, images = found

    args.out.mkdir(parents=True, exist_ok=True)
    report = {"stage": str(args.stage), "stage_sha256": hashlib.sha256(raw).hexdigest(),
              "stage_size": len(raw), "stage_entropy": round(entropy(raw), 3),
              "key_scheme": scheme, "key_hex": key.hex(), "key_len": len(key),
              # xor_key stays an int for single-byte keys (back-compat), else null.
              "xor_key": key[0] if len(key) == 1 else None, "images": []}
    for offset, pe in images:
        try:
            pe.parse_data_directories()
        except Exception:
            pass
        size = declared_size(pe)
        available = len(decoded) - offset
        missing = max(0, size - available)
        image = decoded[offset:offset + min(size, available)]
        sha = hashlib.sha256(image).hexdigest()
        machine = MACHINES[pe.FILE_HEADER.Machine]
        module, names = exports(pe)
        try:
            imphash = pe.get_imphash()
        except Exception:
            imphash = None
        filename = f"{sha[:16]}_{machine}{'_truncated' if missing else ''}.bin"
        (args.out / filename).write_bytes(image)
        report["images"].append({
            "offset": offset, "machine": machine, "is_dll": pe.is_dll(),
            "export_module": module, "exports": names, "imphash": imphash,
            "declared_size": size, "carved_size": len(image), "missing_bytes": missing,
            "written": filename, "sha256": sha,
        })
    (args.out / "extract-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
