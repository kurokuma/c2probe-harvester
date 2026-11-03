#!/usr/bin/env python3
"""Fingerprint the cipher of an encrypted VVAS stage. No code executed.

  python crypto_probe.py <enc.bin> [<cleartext_stage.bin> <xor_key>]

- 16-byte block duplication -> AES-ECB leaks identical ciphertext for identical
  plaintext (e.g. zero padding), so many repeated blocks => ECB.
- entropy per 8 KiB -> spot any low-entropy header/footer (plaintext leak).
- if a cleartext stage is given, XOR(enc, decoded_clear) = candidate keystream;
  if that keystream repeats at a small period it is (long) repeating-XOR; if it
  is random it is a real stream/block cipher (RC4/ChaCha/CBC/CTR).
"""
import collections, math, sys


def ent(d):
    if not d:
        return 0.0
    n = len(d)
    return -sum((v / n) * math.log2(v / n) for v in collections.Counter(d).values())


def block_dup(d, bs=16):
    blocks = [bytes(d[i:i + bs]) for i in range(0, len(d) - bs + 1, bs)]
    c = collections.Counter(blocks)
    repeated = sum(v for v in c.values() if v > 1)
    top = c.most_common(1)[0]
    return {"total": len(blocks), "unique": len(c), "repeated": repeated,
            "top_count": top[1], "top_block": top[0].hex()}


def main():
    enc = open(sys.argv[1], "rb").read()
    print("size", len(enc), "entropy", round(ent(enc), 3))
    print("block16", block_dup(enc))
    emap = [round(ent(enc[i:i + 8192]), 2) for i in range(0, len(enc), 8192)]
    print("entropy/8K min/max", min(emap), max(emap), "first4", emap[:4])
    print("head", enc[:32].hex())
    if len(sys.argv) > 2:
        clear = open(sys.argv[2], "rb").read()
        key = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
        clear = clear.translate(bytes(b ^ key for b in range(256)))
        n = min(len(enc), len(clear))
        ks = bytes(a ^ b for a, b in zip(enc[:n], clear[:n]))
        print("keystream entropy", round(ent(ks), 3), "block16", block_dup(ks))
        for p in (16, 32, 64, 128, 256, 512, 1024, 2048, 4096):
            m = min(20000, len(ks) - p)
            same = sum(ks[i] == ks[i + p] for i in range(m))
            print("  period %5d match%% %.1f" % (p, 100 * same / m))


if __name__ == "__main__":
    main()
