#!/usr/bin/env python3
"""Best-effort key recovery for an ECB-encrypted VVAS stage.

  python ecb_brute.py <enc.bin> <module1> [<module2> ...]

Harvests ASCII/UTF-16LE strings from the given (already-carved, decrypted)
modules, derives key candidates (raw, md5, sha256, hex-decoded), and tries
AES-128/256-ECB and SM4-ECB on the blob, flagging any decrypt whose first 4 KiB
contains an MZ header or the DOS stub. No malware is executed. A hit means the
stage key was reused as a constant in the payload; a miss means it is not there
(it lives in the first-stage VVAS loader, which we do not have).
"""
import hashlib, re, sys

from Crypto.Cipher import AES
try:
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT
    HAVE_SM4 = True
except Exception:
    HAVE_SM4 = False

STUB = b"This program cannot be run in DOS mode"
blob = open(sys.argv[1], "rb").read()
head = blob[:4096]

strings = set()
for mod in sys.argv[2:]:
    d = open(mod, "rb").read()
    for m in re.finditer(rb"[\x20-\x7e]{4,64}", d):
        strings.add(m.group())
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,64}", d):
        strings.add(m.group()[::2])
print("strings", len(strings), "sm4", HAVE_SM4)


def candidates():
    for s in strings:
        yield s, s[:16].ljust(16, b"\0")
        yield s, s[:32].ljust(32, b"\0")
        yield s, hashlib.md5(s).digest()
        yield s, hashlib.sha256(s).digest()
        yield s, hashlib.sha256(s).digest()[:16]
        if re.fullmatch(rb"[0-9a-fA-F]+", s) and len(s) in (32, 64):
            try:
                yield s, bytes.fromhex(s.decode())
            except Exception:
                pass


def aes_dec(k):
    try:
        return AES.new(k, AES.MODE_ECB).decrypt(head)
    except Exception:
        return b""


def sm4_dec(k):
    c = CryptSM4()
    c.set_key(k, SM4_DECRYPT)
    return c.crypt_ecb(head)


seen, hits, n = set(), [], 0
for s, k in candidates():
    if k in seen:
        continue
    seen.add(k)
    n += 1
    trials = [("aes%d" % (len(k) * 8), aes_dec(k))]
    if HAVE_SM4 and len(k) == 16:
        trials.append(("sm4", sm4_dec(k)))
    for name, dec in trials:
        if dec[:2] == b"MZ" or STUB in dec:
            hits.append((name, k.hex(), s[:40]))
            print("HIT", name, "key", k.hex(), "from", s[:40])

print("tested", n, "unique keys; hits", len(hits))
