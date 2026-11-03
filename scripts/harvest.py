#!/usr/bin/env python3
"""Mechanical ValleyRAT VVAS sample harvester.

For each C2 target in a list, run the VVAS probe + download, then carve the
embedded PE images into analyzable files. Writes a per-target summary.

Default is a DRY RUN (no network): pass --download to actually connect. A
per-target delay (default 10s) keeps the footprint modest when sweeping many
freshly discovered C2s. Keep collection within your authorization/RoE, run only
from an isolated VM, and never execute the carved samples.

Targets file: one target per line, ``ip port`` or ``ip:port``; blank lines and
lines starting with ``#`` are ignored.

    python scripts/harvest.py targets.txt --out harvest/ --download --delay 15
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RULE = ROOT / "probes/valleyrat/vvas.yaml"
RECIPE = ROOT / "recipes/body-from-total-length.yaml"


def parse_targets(path):
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\s:,]+", line)
        if len(parts) >= 2 and parts[1].isdigit():
            out.append((parts[0], int(parts[1])))
    return out


def run_one(host, port, outdir, timeout, total, do_download):
    dl = outdir / f"{host}_{port}"
    record = {"host": host, "port": port}
    cmd = [sys.executable, str(HERE / "download_sample.py"), "--rule", str(RULE),
           "--recipe", str(RECIPE), "--host", host, "--port", str(port),
           "--output", str(dl), "--timeout", str(timeout), "--total-timeout", str(total)]
    if do_download:
        cmd.append("--download")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    record["download_rc"] = proc.returncode
    sample = dl / "sample.bin"
    if not do_download:
        record["note"] = "dry-run (no network); pass --download to collect"
        return record
    if proc.returncode != 0 or not sample.exists():
        record["note"] = "no sample acquired"
        record["stderr"] = proc.stderr.strip()[-300:]
        return record
    ex = subprocess.run([sys.executable, str(HERE / "extract_sample.py"), str(sample),
                         "--out", str(dl / "carved")], capture_output=True, text=True)
    record["extract_rc"] = ex.returncode
    try:
        report = json.loads(ex.stdout)
        record["key_scheme"] = report.get("key_scheme")
        record["xor_key"] = report.get("xor_key")
        record["key_hex"] = report.get("key_hex")
        record["images"] = [{"machine": i["machine"], "export_module": i["export_module"],
                             "missing_bytes": i["missing_bytes"], "imphash": i["imphash"],
                             "sha256": i["sha256"], "written": i["written"]}
                            for i in report.get("images", [])]
    except json.JSONDecodeError:
        record["extract_error"] = ex.stderr.strip()[-300:]
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("targets", type=Path, help="ip port / ip:port per line")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--download", action="store_true", help="actually connect (off by default)")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--total-timeout", type=float, default=15)
    parser.add_argument("--delay", type=float, default=10, help="seconds between targets")
    args = parser.parse_args(argv)

    items = parse_targets(args.targets)
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, (host, port) in enumerate(items):
        row = run_one(host, port, args.out, args.timeout, args.total_timeout, args.download)
        rows.append(row)
        imgs = row.get("images", [])
        summary = f"{host}:{port} rc={row.get('download_rc')}"
        if imgs:
            summary += " %s key=%s PEs=%d" % (row.get("key_scheme"), row.get("key_hex"), len(imgs))
            for i in imgs:
                summary += "\n    %s %s missing=%d %s" % (
                    i["machine"], i["export_module"], i["missing_bytes"], i["sha256"][:16])
        else:
            summary += " " + row.get("note", "")
        print(summary, flush=True)
        (args.out / "harvest-summary.json").write_text(
            json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if args.download and index < len(items) - 1:
            time.sleep(args.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
