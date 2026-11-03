#!/usr/bin/env python3
"""Run a c2probe YAML and acquire bytes after a match. Default: offline dry-run."""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import sys

from probe_engine import (Engine, LIMIT, Network, ProbeError, integer, load_rule,
                          load_yaml, mapping, require)


def load_recipe(path, rule):
    if path is None:
        return {"artifact": {"mode": "stream", "prefix": "received"},
                "description": "raw response on the matched connection, through EOF"}, None
    recipe, digest = load_yaml(path)
    mapping(recipe, {"download_version", "artifact"}, {"description", "evidence", "steps"})
    require(recipe["download_version"] == 1, "unsupported download recipe version")
    validator = copy.deepcopy(rule.validator).steps(recipe.get("steps", []))
    artifact = recipe["artifact"]
    mapping(artifact, {"mode"}, {"source", "offset", "length", "prefix", "max_bytes"})
    require(artifact["mode"] in ("stream", "buffer"), "unknown acquisition mode")
    if "max_bytes" in artifact:
        integer(artifact["max_bytes"], 1)
    if "length" in artifact:
        validator.expr(artifact["length"])
    if "offset" in artifact:
        integer(artifact["offset"])
    if artifact["mode"] == "buffer":
        require("source" in artifact and "prefix" not in artifact, "buffer mode requires source, without prefix")
        validator.buffer(artifact["source"])
    else:
        require("source" not in artifact and "offset" not in artifact, "stream mode does not accept source/offset")
        if artifact.get("prefix", "") not in ("", "received"):
            validator.buffer(artifact["prefix"])
    recipe["recipe_path"] = str(Path(path).resolve())
    return recipe, digest


def acquire(engine, recipe, output, metadata, max_bytes):
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    # These are protocol bytes, not a claim that a complete executable was returned.
    (output / "probe-response.bin").write_bytes(bytes(engine.io.received))
    partial = output / "sample.bin.part"
    metadata.update({"status": "acquiring", "artifact_bytes": 0, "sample_validated": False,
                     "executed": False, "acquisition_description": recipe.get("description", ""),
                     "acquisition_evidence": recipe.get("evidence", "unspecified"),
                     "download_fields_separate_from_probe_fields": True})
    digest = hashlib.sha256()
    try:
        engine.execute(recipe.get("steps", []))
        require(engine.matched and not engine.rejected, "acquisition recipe match/reject gate failed")
        spec = recipe["artifact"]
        limit = min(max_bytes, spec.get("max_bytes", max_bytes))
        length = engine.expr(spec["length"]) if "length" in spec else None
        if length is not None:
            integer(length, 1, limit)
        metadata["artifact_mode"] = spec["mode"]
        metadata["expected_artifact_bytes"] = length
        with partial.open("xb") as stream:
            def write(block):
                require(metadata["artifact_bytes"] + len(block) <= limit, "artifact byte limit exceeded")
                stream.write(block)
                digest.update(block)
                metadata["artifact_bytes"] += len(block)

            if spec["mode"] == "buffer":
                source = engine.buffer(spec["source"])
                offset = spec.get("offset", 0)
                end = offset + length if length is not None else len(source)
                require(offset <= end <= len(source), "artifact slice exceeds buffer")
                write(source[offset:end])
            else:
                prefix = spec.get("prefix", "")
                initial = bytes(engine.io.received) if prefix == "received" else engine.buffer(prefix) if prefix else b""
                require(length is None or len(initial) <= length, "prefix is larger than declared artifact")
                write(initial)
                while length is None or metadata["artifact_bytes"] < length:
                    remaining = (length if length is not None else limit) - metadata["artifact_bytes"]
                    # Probe one extra byte at a boundary to distinguish EOF from truncation by the limit.
                    block = engine.io.read(min(65536, remaining) if remaining else 1)
                    if not block:
                        require(length is None or metadata["artifact_bytes"] == length, "truncated artifact")
                        break
                    write(block)
            require(metadata["artifact_bytes"] > 0, "no artifact bytes received")
        partial.rename(output / "sample.bin")
        metadata["status"] = "bytes_acquired_not_validated"
        metadata["sha256"] = digest.hexdigest()
    except (OSError, ProbeError, ValueError, EOFError) as exc:
        metadata["status"] = "incomplete"
        metadata["failure_phase"] = "acquisition"
        metadata["network_operation"] = getattr(engine.io, "operation", None)
        metadata["error"] = str(exc)
        metadata["partial_sha256"] = digest.hexdigest()
        raise
    finally:
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule", type=Path, help="any local c2probe DSL v1 YAML")
    parser.add_argument("--recipe", type=Path, help="optional protocol acquisition YAML")
    parser.add_argument("--probe-dir", type=Path, default=Path(__file__).resolve().parents[1] / "probes")
    parser.add_argument("--list", action="store_true", help="list rules and required parameters, without network")
    parser.add_argument("--download", action="store_true", help="run rule and acquire after match")
    parser.add_argument("--host", help="one literal IPv4/IPv6 address")
    parser.add_argument("--port", type=int)
    parser.add_argument("--output", type=Path, help="new directory; existing parent required")
    parser.add_argument("--probe-param", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--params-file", type=Path, help="YAML mapping, useful for secrets")
    parser.add_argument("--timeout", type=float, help="override rule connect/read timeouts in seconds")
    parser.add_argument("--total-timeout", type=float, default=30)
    parser.add_argument("--max-bytes", type=int, default=LIMIT, help="total receive and artifact byte ceiling")
    args = parser.parse_args(argv)
    if args.list:
        if args.download:
            parser.error("--list cannot be combined with --download")
        return args
    if args.rule is None:
        parser.error("--rule is required")
    if args.host:
        try:
            ipaddress.ip_address(args.host)
        except ValueError:
            parser.error("--host must be one literal IP address")
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be in 1..65535")
    for name in ("timeout", "total_timeout"):
        value = getattr(args, name)
        if value is not None and (not math.isfinite(value) or not 0 < value <= 300):
            parser.error(f"--{name.replace('_', '-')} must be in (0, 300]")
    if not 0 < args.max_bytes <= LIMIT:
        parser.error(f"--max-bytes must be in 1..{LIMIT}")
    if args.download and (not args.host or args.port is None or args.output is None):
        parser.error("--download requires --host, --port and --output")
    if args.output is not None:
        if args.output.exists() or args.output.is_symlink():
            parser.error("--output already exists")
        if not args.output.parent.is_dir():
            parser.error("--output parent must exist")
    return args


def run(argv=None):
    args = arguments(argv)
    transport = None
    engine = None
    metadata = {}
    phase = "validation"
    try:
        if args.list:
            rows = []
            for path in sorted(args.probe_dir.rglob("*.yaml")):
                data, digest = load_yaml(path)
                rows.append({"path": str(path), "name": data.get("name"),
                             "family": data.get("result", {}).get("family"),
                             "classification": data.get("result", {}).get("classification", "confirmed"),
                             "parameters": data.get("parameters", {}), "sha256": digest})
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return 0
        params = load_yaml(args.params_file)[0] if args.params_file else {}
        for item in args.probe_param:
            key, sep, value = item.partition("=")
            require(bool(key) and bool(sep) and key not in params, "invalid or repeated --probe-param")
            params[key] = value
        rule = load_rule(args.rule, params)
        recipe, recipe_digest = load_recipe(args.recipe, rule)
        scope = rule.document.get("scope", {})
        if args.host and scope.get("ips"):
            require(any(ipaddress.ip_address(args.host) in ipaddress.ip_network(net, strict=False)
                        for net in scope["ips"]), "target is outside rule IP scope")
        if args.port is not None and scope.get("ports"):
            require(args.port in scope["ports"], "target is outside rule port scope")
        metadata = {"rule_path": rule.path, "rule_sha256": rule.sha256,
                    "recipe_path": recipe.get("recipe_path"), "recipe_sha256": recipe_digest,
                    "target": {"ip": args.host, "port": args.port},
                    "time_utc": datetime.now(timezone.utc).isoformat(), "sample_validated": False,
                    "executed": False}
        if not args.download:
            metadata.update({"mode": "dry-run", "network_used": False,
                             "probe_name": rule.document["name"],
                             "operations": [next(iter(step)) for step in rule.document["steps"]],
                             "acquisition_operations": [next(iter(step)) for step in recipe.get("steps", [])],
                             "artifact": recipe["artifact"]})
            print(json.dumps(metadata, indent=2, ensure_ascii=False))
            return 0
        transport = Network(rule, args.host, args.port, args.timeout, args.total_timeout, args.max_bytes)
        phase = "connect"
        transport.connect()
        engine = Engine(transport)
        phase = "probe"
        engine.execute(rule.document["steps"])
        metadata.update(engine.result(rule))
        metadata["probe_status"] = metadata["status"]
        if not engine.matched or engine.rejected:
            metadata["acquisition_attempted"] = False
            print(json.dumps(metadata, indent=2, ensure_ascii=False))
            return 2
        metadata["acquisition_attempted"] = True
        phase = "acquisition"
        acquire(engine, recipe, args.output, metadata, args.max_bytes)
        print(json.dumps(metadata, indent=2, ensure_ascii=False))
        return 0
    except (ProbeError, OSError, ValueError, TypeError, KeyError, RecursionError, EOFError) as exc:
        operation = getattr(transport, "operation", None)
        if isinstance(exc, ConnectionRefusedError):
            status = "connection_refused"
        elif isinstance(exc, TimeoutError):
            status = "connect_timeout" if phase == "connect" else "read_timeout" if operation == "recv" else "operation_timeout"
        elif isinstance(exc, ConnectionResetError):
            status = "connection_reset"
        else:
            status = "definition_error" if phase == "validation" else "operation_error"
        context = {"status": status, "phase": phase, "operation": operation,
                   "target": f"{args.host}:{args.port}",
                   "probe_match": engine.matched if engine is not None else None,
                   "probe_step": engine.current_step if engine is not None else None,
                   "probe_operation": engine.current_operation if engine is not None else None,
                   "received_bytes": getattr(transport, "total_received", 0),
                   "artifact_bytes": metadata.get("artifact_bytes", 0), "error": str(exc)}
        print("failed: " + json.dumps(context, ensure_ascii=False), file=sys.stderr)
        return 1
    finally:
        if transport is not None:
            transport.close()


if __name__ == "__main__":
    raise SystemExit(run())
