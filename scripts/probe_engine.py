"""Data-driven interpreter for the c2probe DSL v1. No family-specific code."""

import base64
from dataclasses import dataclass
import gzip
import hashlib
import io
import ipaddress
import math
import re
import socket
import ssl
import time
import zlib
from pathlib import Path

import yaml


LIMIT = 32 * 1024 * 1024
MASK = (1 << 64) - 1
NUMBERS = {"u8": (1, "little"), **{
    f"u{bits}{suffix}": (bits // 8, order)
    for bits in (16, 32, 64) for suffix, order in (("le", "little"), ("be", "big"))
}}
ARITHMETIC = {"add", "sub", "xor", "and", "or", "shift_left", "shift_right"}
CONDITIONS = {"all", "any", "not", "eq", "ne", "lt", "gt", "bytes_eq",
              "bytes_contains", "bytes_regex", "buffer_starts_with"}
# Each operation declares required and optional keys; unknown semantics fail closed.
SCHEMAS = {
    "send": (set(), {"hex", "source"}),
    "literal": ({"name", "text"}, set()),
    "pack": ({"name", "type", "value"}, {"wrap"}),
    "concat": ({"name", "sources"}, set()),
    "recv_exact": ({"bytes", "save_as"}, set()),
    "recv_up_to": ({"max_bytes", "save_as"}, {"min_bytes"}),
    "recv_until": ({"delimiter_hex", "max_bytes", "save_as"}, set()),
    "recv_frame": ({"type", "min_bytes", "max_bytes", "save_as", "length_as"}, set()),
    "recv_http": ({"max_header_bytes", "max_body_bytes", "body_as", "header_as",
                   "status_as", "content_length_as"}, {"headers_only"}),
    "send_http": ({"method", "path"}, {"headers", "body_source"}),
    "reconnect": (set(), set()),
    "peer_certificate": ({"save_as"}, set()),
    "transform": ({"source", "name"}, {"ascii_hex_decode", "base64_decode", "base64_encode",
                                         "rc4", "gzip_decompress", "msgpack_string"}),
    "extract": ({"source", "name", "type", "offset"}, {"length"}),
    "compute": ({"name", "expr"}, set()),
}


class ProbeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def mapping(value, required=(), optional=()):
    require(isinstance(value, dict), "expected a mapping")
    require(set(required) <= value.keys() and not value.keys() - set(required) - set(optional),
            "missing or unsupported YAML keys")


def integer(value, low=0, high=LIMIT):
    require(type(value) is int and low <= value <= high, "integer is outside permitted bounds")
    return value


def unhex(value):
    require(isinstance(value, str), "hex value must be text")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ProbeError("invalid hex bytes") from exc
    require(len(result) <= LIMIT, "hex buffer too large")
    return result


class UniqueLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        require(not self.check_event(yaml.AliasEvent), "YAML aliases are unsupported")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            require(isinstance(key, str) and key not in result, "duplicate or non-text YAML key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_yaml(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, "YAML exceeds 1 MiB")
    try:
        data = yaml.load(raw, Loader=UniqueLoader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ProbeError("invalid or excessively nested YAML") from exc
    require(isinstance(data, dict), "YAML must be a mapping")
    return data, hashlib.sha256(raw).hexdigest()


def resolve_parameters(data, supplied):
    definitions = data.pop("parameters", {})
    mapping(definitions, optional=definitions)
    require(not supplied.keys() - definitions.keys(), "unknown probe parameter")
    resolved = {}
    for name, definition in definitions.items():
        mapping(definition, {"type"}, {"required", "secret", "default", "allowed_values",
                                      "min_length", "max_length", "decoded_min_length", "decoded_max_length"})
        value = supplied.get(name, definition.get("default"))
        if value is None:
            require(not definition.get("required"), f"missing probe parameter: {name}")
            continue
        require(isinstance(value, str) and (value or not definition.get("required")),
                f"invalid probe parameter: {name}")
        kind = definition["type"]
        valid = False
        if kind == "base64":
            try:
                decoded = base64.b64decode(value, validate=True)
                valid = bool(decoded) and definition.get("decoded_min_length", 1) <= len(decoded) <= definition.get("decoded_max_length", 4096)
            except ValueError:
                valid = False
        elif kind == "ip":
            try:
                ipaddress.ip_address(value)
                valid = True
            except ValueError:
                pass
        else:
            patterns = {"hex": r"(?:[0-9a-fA-F]{2})+", "decimal": r"[0-9]+",
                        "token": r"[A-Za-z0-9_.-]*", "http_host": r"[A-Za-z0-9.:\[\]-]+",
                        "http_path": r"/[^\s\x00-\x1f\x7f]*"}
            valid = kind in patterns and re.fullmatch(patterns[kind], value) is not None
        require(valid and definition.get("min_length", 0) <= len(value) <= definition.get("max_length", 4096)
                and ("allowed_values" not in definition or value in definition["allowed_values"]),
                f"invalid probe parameter: {name}")
        resolved[name] = value

    def substitute(value):
        if isinstance(value, str):
            def replacement(match):
                require(match[1] in resolved, f"missing probe parameter: {match[1]}")
                return resolved[match[1]]
            return re.sub(r"\$\{([^}]+)\}", replacement, value)
        if isinstance(value, list):
            return [substitute(item) for item in value]
        if isinstance(value, dict):
            return {key: substitute(item) for key, item in value.items()}
        return value
    return substitute(data)


def reference(value):
    require(isinstance(value, str) and bool(value.lstrip("$")), "invalid reference")
    return value[1:] if value.startswith("$") else value


class Validator:
    def __init__(self):
        self.buffers = set()
        self.registers = set()

    def buffer(self, name):
        require(reference(name) in self.buffers, "reference to undefined buffer")

    def expr(self, expression):
        if type(expression) is int:
            integer(expression, 0, MASK)
        elif isinstance(expression, str):
            require(expression.startswith("$") and reference(expression) in self.registers,
                    "reference to undefined integer")
        else:
            mapping(expression, optional=ARITHMETIC)
            require(len(expression) == 1, "expression needs exactly one operator")
            args = next(iter(expression.values()))
            mapping(args, {"left", "right"})
            self.expr(args["left"])
            self.expr(args["right"])

    def condition(self, condition):
        mapping(condition, optional=CONDITIONS | {"confidence", "status"})
        selected = condition.keys() & CONDITIONS
        require(len(selected) == 1, "condition needs exactly one operator")
        op = next(iter(selected))
        args = condition[op]
        if op in ("all", "any"):
            require(isinstance(args, list) and bool(args), "empty condition list")
            for child in args:
                self.condition(child)
        elif op == "not":
            self.condition(args)
        elif op in ("eq", "ne", "lt", "gt"):
            mapping(args, {"left", "right"})
            self.expr(args["left"])
            self.expr(args["right"])
        else:
            keys = {"bytes_eq": {"source", "offset", "hex"},
                    "bytes_contains": {"source", "hex"}, "bytes_regex": {"source", "pattern"},
                    "buffer_starts_with": {"source", "prefix"}}[op]
            mapping(args, keys)
            self.buffer(args["source"])
            if "hex" in args:
                unhex(args["hex"])
            if "offset" in args:
                integer(args["offset"])
            if op == "buffer_starts_with":
                self.buffer(args["prefix"])
            if op == "bytes_regex":
                try:
                    re.compile(args["pattern"].encode("utf-8"))
                except (re.error, AttributeError) as exc:
                    raise ProbeError("unsupported byte regex") from exc

    def steps(self, steps):
        require(isinstance(steps, list) and len(steps) <= 512, "invalid steps list")
        for step in steps:
            require(isinstance(step, dict) and len(step) == 1, "step needs exactly one operation")
            op, args = next(iter(step.items()))
            if op in ("match", "reject_if"):
                self.condition(args)
                if op == "reject_if":
                    require(isinstance(args.get("status"), str), "reject_if requires status")
                continue
            require(op in SCHEMAS, "unsupported DSL operation")
            mapping(args, *SCHEMAS[op])
            if "source" in args:
                self.buffer(args["source"])
            if op == "send":
                require(("hex" in args) != ("source" in args), "send needs hex or source")
                if "hex" in args:
                    unhex(args["hex"])
            if op in ("pack", "recv_frame"):
                require(args["type"] in NUMBERS, "unknown integer format")
            if op == "pack":
                self.expr(args["value"])
            if op == "compute":
                self.expr(args["expr"])
            if op == "literal":
                require(isinstance(args["text"], str), "literal must be text")
            if op == "concat":
                require(isinstance(args["sources"], list), "concat requires sources list")
                for source in args["sources"]:
                    self.buffer(source)
            for key in ("bytes", "min_bytes", "max_bytes", "max_header_bytes", "max_body_bytes", "offset", "length"):
                if key in args:
                    integer(args[key])
            if "max_bytes" in args:
                require(args.get("min_bytes", 1) <= args["max_bytes"], "invalid receive bounds")
            if op == "recv_until":
                require(bool(unhex(args["delimiter_hex"])), "empty delimiter")
            if op == "extract":
                require(args["type"] in set(NUMBERS) | {"crc32", "bufferlen", "asciidecimal"}, "unknown extraction")
                require(args["type"] not in ("crc32", "asciidecimal") or "length" in args,
                        "extraction requires length")
            if op == "send_http":
                validate_http_request(args)
                if "body_source" in args:
                    self.buffer(args["body_source"])
            if op == "transform":
                selected = set(args) - {"source", "name"}
                require(len(selected) == 1, "transform needs exactly one operation")
                kind = next(iter(selected))
                options = args[kind]
                if kind == "rc4":
                    mapping(options, {"key_base64"})
                    try:
                        key = base64.b64decode(options["key_base64"], validate=True)
                    except (ValueError, TypeError) as exc:
                        raise ProbeError("invalid RC4 key") from exc
                    require(0 < len(key) <= 4096, "invalid RC4 key size")
                elif kind == "gzip_decompress":
                    mapping(options, {"max_bytes"}, {"offset"})
                    integer(options["max_bytes"], 1)
                    integer(options.get("offset", 0))
                elif kind == "msgpack_string":
                    mapping(options, {"key"})
                else:
                    mapping(options)
            buffer_outputs = {"save_as"} if "save_as" in args else set()
            if op in ("literal", "pack", "concat", "transform"):
                buffer_outputs.add("name")
            if op == "recv_http":
                buffer_outputs |= {"body_as", "header_as"}
            register_outputs = {"name"} if op in ("extract", "compute") else set()
            if op == "recv_frame":
                register_outputs.add("length_as")
            if op == "recv_http":
                register_outputs |= {"status_as", "content_length_as"}
            for key in buffer_outputs:
                name = reference(args[key])
                require(name not in self.registers, "name used as both integer and buffer")
                self.buffers.add(name)
            for key in register_outputs:
                name = reference(args[key])
                require(name not in self.buffers, "name used as both integer and buffer")
                self.registers.add(name)
        return self


def validate_http_request(args):
    token = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    require(isinstance(args["method"], str) and re.fullmatch(token, args["method"]), "invalid HTTP method")
    require(isinstance(args["path"], str) and re.fullmatch(r"/[^\s\x00-\x1f\x7f]*", args["path"]), "invalid HTTP path")
    headers = args.get("headers", {})
    require(isinstance(headers, dict), "invalid HTTP headers")
    seen = set()
    for name, value in headers.items():
        require(re.fullmatch(token, name) and name.lower() not in seen, "invalid or duplicate HTTP header")
        seen.add(name.lower())
        require(isinstance(value, str) and not re.search(r"[\x00-\x1f\x7f]", value), "invalid HTTP header value")


@dataclass
class Rule:
    path: str
    sha256: str
    document: dict
    validator: Validator


def load_rule(path, parameters=None):
    data, digest = load_yaml(path)
    data = resolve_parameters(data, parameters or {})
    mapping(data, {"dsl_version", "name", "transport", "steps", "result"}, {"metadata", "scope"})
    require(data["dsl_version"] == 1, "unsupported DSL version")
    transport = data["transport"]
    mapping(transport, {"type"}, {"connect_timeout_ms", "read_timeout_ms", "insecure_tls", "server_name", "prelude_hex"})
    require(transport["type"] in ("tcp", "tls", "starttls"), "unsupported transport")
    for key in ("connect_timeout_ms", "read_timeout_ms"):
        integer(transport.get(key, 1000), 1, 300000)
    if transport["type"] == "starttls":
        require(bool(unhex(transport.get("prelude_hex", ""))), "STARTTLS requires a prelude")
    scope = data.get("scope", {})
    mapping(scope, optional={"ips", "ports"})
    for network in scope.get("ips", []):
        ipaddress.ip_network(network, strict=False)
    for port in scope.get("ports", []):
        integer(port, 1, 65535)
    result = data["result"]
    mapping(result, {"family", "protocol"}, {"classification", "confirmed", "confidence", "unmatched_confidence", "status", "unmatched_status", "fields"})
    require(result.get("confirmed", "$match") == "$match", "unsupported result.confirmed")
    require(result.get("classification", "confirmed") in ("confirmed", "probable", "observation"), "unknown classification")
    validator = Validator().steps(data["steps"])
    require(any("match" in step for step in data["steps"]), "rule needs a match step")
    for value in result.get("fields", {}).values():
        if isinstance(value, str) and value.startswith("$") and value != "$rejected":
            if value.startswith(("$hex:", "$text:")):
                validator.buffer(value.split(":", 1)[1])
            else:
                validator.expr(value)
    if transport["type"] == "tcp":
        require(not any("peer_certificate" in step for step in data["steps"]), "peer_certificate requires TLS")
    return Rule(str(Path(path).resolve()), digest, data, validator)


class Network:
    """One target, with explicit rule-directed reconnects and a shared time budget."""
    def __init__(self, rule, host, port, timeout=None, total_timeout=30, max_bytes=LIMIT):
        self.transport = rule.document["transport"]
        self.host, self.port = str(ipaddress.ip_address(host)), port
        self.connect_timeout = timeout or self.transport.get("connect_timeout_ms", 1000) / 1000
        self.read_timeout = timeout or self.transport.get("read_timeout_ms", 1000) / 1000
        self.deadline = time.monotonic() + total_timeout
        self.max_bytes = max_bytes
        self.received = bytearray()
        self.total_received = 0
        self.connection = None
        self.connections = 0
        self.operation = "not_connected"

    def budget(self, timeout):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("total network time budget exhausted")
        return min(timeout, remaining)

    def connect(self):
        self.close()
        self.received.clear()
        self.connections += 1
        require(self.connections <= 32, "reconnect limit exceeded")
        family = socket.AF_INET6 if ipaddress.ip_address(self.host).version == 6 else socket.AF_INET
        self.operation = "tcp_connect"
        self.connection = socket.socket(family, socket.SOCK_STREAM)
        self.connection.settimeout(self.budget(self.connect_timeout))
        self.connection.connect((self.host, self.port))
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        kind = self.transport["type"]
        if kind == "starttls":
            self.send(unhex(self.transport["prelude_hex"]))
        if kind in ("tls", "starttls"):
            self.operation = "tls_handshake"
            context = ssl.create_default_context()
            if self.transport.get("insecure_tls", False):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.connection.settimeout(self.budget(self.connect_timeout))
            self.connection = context.wrap_socket(self.connection, server_hostname=self.transport.get("server_name") or self.host)

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def send(self, data):
        self.operation = "send"
        require(len(data) <= LIMIT, "send buffer limit exceeded")
        self.connection.settimeout(self.budget(self.read_timeout))
        self.connection.sendall(data)

    def read(self, count, deadline=None):
        self.operation = "recv"
        timeout = self.budget(self.read_timeout)
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout <= 0:
                raise TimeoutError("receive operation timed out")
        self.connection.settimeout(timeout)
        data = self.connection.recv(count)
        self.total_received += len(data)
        require(self.total_received <= self.max_bytes, "total received byte limit exceeded")
        self.received.extend(data)
        return data

    def exact(self, count):
        integer(count)
        deadline = time.monotonic() + self.read_timeout
        output = bytearray()
        while len(output) < count:
            block = self.read(min(65536, count - len(output)), deadline)
            require(bool(block), "truncated response")
            output.extend(block)
        return bytes(output)

    def up_to(self, minimum, maximum):
        deadline = time.monotonic() + self.read_timeout
        output = bytearray()
        while len(output) < maximum:
            try:
                block = self.read(min(65536, maximum - len(output)), deadline)
            except TimeoutError:
                break
            if not block:
                break
            output.extend(block)
        require(len(output) >= minimum, "response shorter than minimum")
        return bytes(output)

    def until(self, delimiter, maximum):
        deadline = time.monotonic() + self.read_timeout
        output = bytearray()
        while len(output) < maximum:
            byte = self.read(1, deadline)
            require(bool(byte), "truncated delimited response")
            output.extend(byte)
            if output.endswith(delimiter):
                return bytes(output)
        raise ProbeError("response delimiter not found within limit")

    def certificate(self):
        require(isinstance(self.connection, ssl.SSLSocket), "certificate requires TLS")
        return hashlib.sha256(self.connection.getpeercert(binary_form=True)).digest()


def rc4(data, key):
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 255
        state[i], state[j] = state[j], state[i]
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        state[i], state[j] = state[j], state[i]
        result.append(byte ^ state[(state[i] + state[j]) & 255])
    return bytes(result)


def msgpack_string(data, wanted):
    require(bool(data) and 0x81 <= data[0] <= 0x8f, "expected MessagePack fixmap")
    offset = 1
    def read_string():
        nonlocal offset
        require(offset < len(data), "truncated MessagePack string")
        tag = data[offset]
        offset += 1
        if 0xa0 <= tag <= 0xbf:
            size = tag & 31
        elif tag == 0xd9:
            require(offset < len(data), "truncated MessagePack str8")
            size = data[offset]
            offset += 1
        else:
            raise ProbeError("unsupported MessagePack string layout")
        require(offset + size <= len(data), "truncated MessagePack value")
        value = data[offset:offset + size]
        offset += size
        return value
    found = None
    for _ in range(data[0] & 15):
        key, value = read_string(), read_string()
        if key == wanted.encode():
            found = value
    require(offset == len(data) and found is not None, "MessagePack key missing or trailing bytes")
    return found


class Engine:
    def __init__(self, transport):
        self.io = transport
        self.buffers = {}
        self.registers = {}
        self.matched = False
        self.rejected = False
        self.override = {}
        self.current_step = None
        self.current_operation = None

    def buffer(self, name):
        try:
            return self.buffers[reference(name)]
        except KeyError as exc:
            raise ProbeError("undefined buffer") from exc

    def put(self, name, value):
        require(len(value) <= LIMIT, "buffer limit exceeded")
        self.buffers[reference(name)] = value
        require(sum(map(len, self.buffers.values())) <= LIMIT * 2, "total buffer limit exceeded")

    def expr(self, expression):
        if type(expression) is int:
            return integer(expression, 0, MASK)
        if isinstance(expression, str):
            try:
                return self.registers[reference(expression)]
            except KeyError as exc:
                raise ProbeError("undefined integer") from exc
        op, args = next(iter(expression.items()))
        a, b = self.expr(args["left"]), self.expr(args["right"])
        if op == "add": value = a + b
        elif op == "sub": value = a - b
        elif op == "xor": value = a ^ b
        elif op == "and": value = a & b
        elif op == "or": value = a | b
        elif op == "shift_left": value = a << (b & 63)
        elif op == "shift_right": value = a >> (b & 63)
        else: raise ProbeError("unknown expression")
        return value & MASK

    def condition(self, condition):
        op = next(key for key in condition if key in CONDITIONS)
        args = condition[op]
        if op == "all": return all(self.condition(child) for child in args)
        if op == "any": return any(self.condition(child) for child in args)
        if op == "not": return not self.condition(args)
        if op in ("eq", "ne", "lt", "gt"):
            a, b = self.expr(args["left"]), self.expr(args["right"])
            return {"eq": a == b, "ne": a != b, "lt": a < b, "gt": a > b}[op]
        source = self.buffer(args["source"])
        if op == "bytes_eq":
            expected = unhex(args["hex"])
            offset = args["offset"]
            return source[offset:offset + len(expected)] == expected
        if op == "bytes_contains": return unhex(args["hex"]) in source
        if op == "bytes_regex": return re.search(args["pattern"].encode(), source) is not None
        if op == "buffer_starts_with": return source.startswith(self.buffer(args["prefix"]))
        raise ProbeError("unknown condition")

    def transform(self, source, kind, options):
        if kind == "ascii_hex_decode":
            require(re.fullmatch(b"(?:[0-9a-fA-F]{2})*", source), "invalid ASCII hex")
            return bytes.fromhex(source.decode())
        if kind == "base64_decode": return base64.b64decode(b"".join(source.split()), validate=True)
        if kind == "base64_encode": return base64.b64encode(source)
        if kind == "rc4": return rc4(source, base64.b64decode(options["key_base64"], validate=True))
        if kind == "gzip_decompress":
            with gzip.GzipFile(fileobj=io.BytesIO(source[options.get("offset", 0):])) as stream:
                result = stream.read(options["max_bytes"] + 1)
            require(len(result) <= options["max_bytes"], "gzip output exceeds limit")
            return result
        if kind == "msgpack_string": return msgpack_string(source, options["key"])
        raise ProbeError("unknown transform")

    def http(self, args):
        header = self.io.until(b"\r\n\r\n", args["max_header_bytes"])
        lines = header[:-4].split(b"\r\n")
        parts = lines[0].split(b" ", 2)
        require(len(parts) >= 2 and parts[0] in (b"HTTP/1.0", b"HTTP/1.1")
                and re.fullmatch(b"[0-9]{3}", parts[1]), "invalid HTTP status line")
        status = int(parts[1])
        require(100 <= status <= 599, "invalid HTTP status")
        fields = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            require(separator and re.fullmatch(b"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name), "invalid HTTP header")
            name = name.lower()
            require(name not in fields and name != b"transfer-encoding", "duplicate header or unsupported Transfer-Encoding")
            fields[name] = value.strip()
        length = fields.get(b"content-length")
        if length is not None:
            require(re.fullmatch(b"[0-9]+", length), "invalid Content-Length")
            length = int(length)
            # A HEAD/headers_only response declares the length a GET would return but
            # sends no body, so the body-size limit only applies when a body is read.
            require(args.get("headers_only", False) or length <= args["max_body_bytes"],
                    "HTTP body exceeds rule limit")
        body = b""
        if not args.get("headers_only", False):
            if length is not None:
                body = self.io.exact(length)
            elif args["max_body_bytes"]:
                # No Content-Length: read the body through EOF/timeout, but an empty
                # body is legitimate (e.g. 204/304 or a closed connection with no data).
                body = self.io.up_to(0, args["max_body_bytes"])
        self.put(args["header_as"], header)
        self.put(args["body_as"], body)
        self.registers[args["status_as"]] = status
        self.registers[args["content_length_as"]] = length or 0

    def execute(self, steps):
        for index, step in enumerate(steps):
            op, args = next(iter(step.items()))
            self.current_step, self.current_operation = index, op
            if op == "send":
                self.io.send(unhex(args["hex"]) if "hex" in args else self.buffer(args["source"]))
            elif op == "literal": self.put(args["name"], args["text"].encode())
            elif op == "pack":
                size, order = NUMBERS[args["type"]]
                value = self.expr(args["value"])
                require(args.get("wrap", False) or value < 1 << (size * 8), "pack value overflows")
                self.put(args["name"], (value & ((1 << (size * 8)) - 1)).to_bytes(size, order))
            elif op == "concat":
                sources = [self.buffer(name) for name in args["sources"]]
                require(sum(map(len, sources)) <= LIMIT, "concat buffer limit exceeded")
                self.put(args["name"], b"".join(sources))
            elif op == "recv_exact": self.put(args["save_as"], self.io.exact(args["bytes"]))
            elif op == "recv_up_to": self.put(args["save_as"], self.io.up_to(args.get("min_bytes", 1), args["max_bytes"]))
            elif op == "recv_until": self.put(args["save_as"], self.io.until(unhex(args["delimiter_hex"]), args["max_bytes"]))
            elif op == "recv_frame":
                size, order = NUMBERS[args["type"]]
                length = int.from_bytes(self.io.exact(size), order)
                require(args["min_bytes"] <= length <= args["max_bytes"], "invalid frame size")
                self.put(args["save_as"], self.io.exact(length))
                self.registers[args["length_as"]] = length
            elif op == "recv_http": self.http(args)
            elif op == "send_http":
                body = self.buffer(args["body_source"]) if "body_source" in args else b""
                headers = dict(args.get("headers", {}))
                if body and not any(name.lower() == "content-length" for name in headers):
                    headers["Content-Length"] = str(len(body))
                request = f"{args['method']} {args['path']} HTTP/1.1\r\n"
                for name, value in headers.items():
                    request += f"{name}: {self.io.host if value == '$target_ip' else value}\r\n"
                self.io.send((request + "\r\n").encode() + body)
            elif op == "reconnect": self.io.connect()
            elif op == "peer_certificate": self.put(args["save_as"], self.io.certificate())
            elif op == "transform":
                kind = next(key for key in args if key not in ("source", "name"))
                self.put(args["name"], self.transform(self.buffer(args["source"]), kind, args[kind]))
            elif op == "extract":
                source = self.buffer(args["source"])
                kind, offset = args["type"], args["offset"]
                if kind == "bufferlen": value = len(source)
                else:
                    length = NUMBERS[kind][0] if kind in NUMBERS else args["length"]
                    require(offset + length <= len(source), "extraction exceeds buffer")
                    part = source[offset:offset + length]
                    if kind == "crc32": value = zlib.crc32(part)
                    elif kind == "asciidecimal":
                        require(re.fullmatch(b"[0-9]+", part), "invalid ASCII decimal")
                        value = int(part)
                    else: value = int.from_bytes(part, NUMBERS[kind][1])
                self.registers[args["name"]] = integer(value, 0, MASK)
            elif op == "compute": self.registers[args["name"]] = self.expr(args["expr"])
            elif op == "reject_if":
                if self.condition(args):
                    self.matched, self.rejected = False, True
                    self.override = {"status": args["status"], "confidence": args.get("confidence", 0)}
                    return
            elif op == "match":
                self.matched = self.condition(args)
                self.override = {key: args[key] for key in ("status", "confidence") if key in args} if self.matched else {}
            else: raise ProbeError("unsupported step")

    def result(self, rule):
        spec = rule.document["result"]
        def field(value):
            if isinstance(value, str):
                if value == "$rejected": return self.rejected
                if value.startswith("$hex:"): return self.buffer(value[5:]).hex()
                if value.startswith("$text:"): return self.buffer(value[6:]).decode(errors="replace")
                if value.startswith("$"): return self.registers.get(reference(value), 0)
            return value
        return {
            "probe_name": rule.document["name"], "family": spec["family"], "protocol": spec["protocol"],
            "matched": self.matched, "rejected": self.rejected,
            "classification": spec.get("classification", "confirmed"),
            "confidence": self.override.get("confidence", spec.get("confidence", 0.95) if self.matched else spec.get("unmatched_confidence", 0)),
            "status": self.override.get("status", spec.get("status", "") if self.matched else spec.get("unmatched_status", "protocol_mismatch")),
            "probe_fields": {name: field(value) for name, value in spec.get("fields", {}).items()},
        }
