#!/usr/bin/env python3
"""Classify VVAS sample.bin files to explain why they did/didn't carve a PE.

For each <dir>/sample.bin under a root, decide one of:
  EMPTY          本文が単一バイトの定数(鍵で復号すると全ゼロ) = ペイロード未配置
  PE_OK          単バイト XOR 下に pefile 解析可能な PE(carve 可能)
  PE_DAMAGED     DOS スタブは在るが PE ヘッダ破損/切り詰めで pefile 解析不可
  ENC_OR_PACKED  単バイト XOR では PE 無し・高エントロピー(2層目暗号/パック)
  NON_PE_DATA    単バイト XOR では PE 無し・低〜中エントロピー(shellcode/設定等)

"単バイト XOR 下に DOS スタブが在るか" は鍵非依存の差分シグネチャで1パス検出する
(c[i]^c[i+1] は鍵が消えるため平文スタブの差分と一致する)。鍵も同時に復元する。
識別情報(sha256)で重複をまとめて出力。No code is executed.
"""
import argparse, glob, hashlib, os, re, sys
from collections import Counter
from math import log2

import pefile

STUB = b"This program cannot be run in DOS mode"
SIG = bytes(STUB[i] ^ STUB[i + 1] for i in range(len(STUB) - 1))
MACHINES = {0x14C: "i386", 0x8664: "amd64"}


def entropy(d):
    n = len(d)
    return round(-sum((c / n) * log2(c / n) for c in Counter(d).values()), 2) if n else 0.0


def xor(d, k):
    return d.translate(bytes(b ^ k for b in range(256)))


def find_stub_key(data):
    """Return (stub_pos, key) if a single-byte-XOR'd DOS stub exists, else None."""
    diff = bytes(x ^ y for x, y in zip(data, data[1:]))
    pos = diff.find(SIG)
    if pos < 0:
        return None
    return pos, data[pos] ^ STUB[0]


def parse_pe(decoded, mz):
    try:
        pe = pefile.PE(data=decoded[mz:], fast_load=True)
    except pefile.PEFormatError as e:
        return None, str(e)
    if pe.FILE_HEADER.Machine not in MACHINES:
        return None, "machine=0x%x" % pe.FILE_HEADER.Machine
    ends = [pe.OPTIONAL_HEADER.SizeOfHeaders]
    for s in pe.sections:
        ends.append(s.PointerToRawData + s.SizeOfRawData)
    return pe, max(ends)


def classify(data):
    counts = Counter(data)
    top_byte, top_n = counts.most_common(1)[0]
    ent = entropy(data)
    if len(counts) == 1:
        return "EMPTY", {"fill": top_byte, "entropy": ent}
    hit = find_stub_key(data)
    if hit:
        pos, key = hit
        dec = xor(data, key)
        mzs = [m.start() for m in re.finditer(b"MZ", dec[:pos + 2])]
        mz = mzs[-1] if mzs else max(0, pos - 0x80)
        pe, info = parse_pe(dec, mz)
        if pe:
            avail = len(dec) - mz
            missing = max(0, info - avail)
            return ("PE_OK" if missing == 0 else "PE_DAMAGED"), {
                "key": key, "mz": mz, "machine": MACHINES[pe.FILE_HEADER.Machine],
                "declared": info, "avail": avail, "missing": missing, "entropy": ent}
        return "PE_DAMAGED", {"key": key, "mz": mz, "stub_pos": pos,
                              "reason": info, "entropy": ent}
    # no single-byte-XOR PE present
    if ent >= 7.5:
        return "ENC_OR_PACKED", {"entropy": ent, "top_byte": top_byte,
                                 "top_frac": round(top_n / len(data), 3)}
    dec = xor(data, top_byte)  # assume top byte is the key (zero padding)
    strings = re.findall(rb"[\x20-\x7e]{5,}", dec)
    strings.sort(key=len, reverse=True)
    return "NON_PE_DATA", {"entropy": ent, "key_guess": top_byte,
                           "header": dec[:32].hex(),
                           "strings": [s.decode("latin1") for s in strings[:8]]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    args = ap.parse_args()
    rows = []
    for f in sorted(glob.glob(os.path.join(args.root, "*", "sample.bin"))):
        data = open(f, "rb").read()
        target = os.path.basename(os.path.dirname(f))
        cls, info = classify(data)
        rows.append((hashlib.sha256(data).hexdigest(), len(data), cls, info, target))

    groups = {}
    for sha, size, cls, info, target in rows:
        groups.setdefault(sha, {"size": size, "cls": cls, "info": info, "targets": []})
        groups[sha]["targets"].append(target)

    tally = Counter(g["cls"] for g in groups.values())
    print("=== %d sample.bin / %d unique ===" % (len(rows), len(groups)))
    print("tally(unique):", dict(tally))
    order = {"EMPTY": 0, "ENC_OR_PACKED": 1, "NON_PE_DATA": 2, "PE_DAMAGED": 3, "PE_OK": 4}
    for sha, g in sorted(groups.items(), key=lambda kv: (order.get(kv[1]["cls"], 9), -len(kv[1]["targets"]))):
        i = g["info"]
        tag = ""
        if g["cls"] == "EMPTY":
            tag = "fill=0x%02x" % i["fill"]
        elif g["cls"] in ("PE_OK", "PE_DAMAGED"):
            tag = "key=0x%02x %s decl=%s avail=%s miss=%s %s" % (
                i.get("key", 0), i.get("machine", "?"), i.get("declared"),
                i.get("avail"), i.get("missing"), i.get("reason", ""))
        elif g["cls"] == "ENC_OR_PACKED":
            tag = "ent=%s top=0x%02x(%s)" % (i["entropy"], i["top_byte"], i["top_frac"])
        elif g["cls"] == "NON_PE_DATA":
            tag = "ent=%s key?=0x%02x hdr=%s" % (i["entropy"], i["key_guess"], i["header"])
        print("\n[%-13s] n=%-2d size=%d %s sha=%s" % (g["cls"], len(g["targets"]), g["size"], tag, sha[:16]))
        if g["cls"] == "NON_PE_DATA" and i.get("strings"):
            print("   strings:", " | ".join(i["strings"]))
        print("   targets:", ", ".join(g["targets"]))


if __name__ == "__main__":
    main()
