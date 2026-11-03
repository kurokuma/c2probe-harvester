"""Offline regression tests: no real socket is ever created."""

import base64
import contextlib
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import download_sample as app
from probe_engine import Engine, Network, ProbeError, Validator, load_rule, load_yaml, rc4

KEY = b"test-secret-key"


def parameters_for(path):
    data, _ = load_yaml(path)
    result = {}
    for name, spec in data.get("parameters", {}).items():
        if "default" in spec:
            result[name] = spec["default"]
        elif "allowed_values" in spec:
            result[name] = spec["allowed_values"][0]
        else:
            result[name] = {"ip": "192.0.2.1", "base64": base64.b64encode(KEY).decode(),
                            "hex": "a" * 32, "decimal": "1", "token": "test"}[spec["type"]]
    return result


def http(body=b"", status=200, content_type="application/octet-stream"):
    return (f"HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\n"
            f"Content-Type: {content_type}\r\n\r\n").encode() + body


class FakeNetwork(Network):
    def __init__(self, rule, responses, certificate=b"c" * 32, chunk=13):
        super().__init__(rule, "192.0.2.1", 1234)
        self.responses = responses
        self.cert = certificate
        self.chunk = chunk
        self.sent = []
        self.reader = None
        self.close_count = 0

    def connect(self):
        self.reader = io.BytesIO(self.responses[self.connections])
        self.connections += 1
        self.received.clear()

    def send(self, data):
        self.sent.append(data)

    def read(self, count, deadline=None):
        data = self.reader.read(min(count, self.chunk))
        self.total_received += len(data)
        if self.total_received > self.max_bytes:
            raise ProbeError("total received byte limit exceeded")
        self.received.extend(data)
        return data

    def certificate(self):
        return self.cert

    def close(self):
        self.close_count += 1


def fixture_for(path):
    """Test-only family fixtures; the application contains no family dispatch."""
    group, name = path.parent.name, path.stem
    cert = b"c" * 32
    if group == "agenttesla": return [b"220 synthetic FTP\r\n"], cert
    if group == "atlasrat":
        return [bytes.fromhex("48 89 5c 24 10") + bytes(7167) + b"MZsynthetic"], cert
    if group == "condi": return [bytes.fromhex("99 66 33")], cert
    if group == "darkcomet":
        encrypted = rc4(b"IDTYPE", KEY)
        return [encrypted.hex().encode() if name == "ascii-hex" else encrypted], cert
    if group == "dotnet-rat":
        key, value = (b"Packet", b"pong") if name == "asyncrat" else (b"Pac_ket", b"Po_ng")
        decoded = bytes([0x81, 0xa0 + len(key)]) + key + bytes([0xa0 + len(value)]) + value
        payload = struct.pack("<I", len(decoded)) + gzip.compress(decoded, mtime=0)
        return [struct.pack("<I", len(payload)) + payload], cert
    if group == "purelogs":
        return [http(b"OK", content_type="text/plain")], bytes.fromhex("9e254cab8c68944cea18a3ac5523fe491eb14f9447b352dca33729b64eaeeac3")
    if group == "purerat":
        digest = "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57" if name.startswith("direct") else "67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b"
        return [b""], bytes.fromhex(digest)
    if group == "redline":
        body = (b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
                b'<s:Body><CheckConnectResponse xmlns="http://tempuri.org/">'
                b'<CheckConnectResult>true</CheckConnectResult></CheckConnectResponse></s:Body></s:Envelope>')
        return [http(body, content_type="text/xml; charset=utf-8")], cert
    if group == "stealer-http":
        if name == "stealc":
            body = base64.b64encode(rc4(b'{"access_token":"' + b"a" * 64 + b'"}', KEY))
        else:
            body = b"a" * 64
        return [http(body, status=201)], cert
    if group == "stealer-route":
        count = 3 if name.startswith("amos") else 2
        return [http() for _ in range(count - 1)] + [http(status=404)], cert
    if name in ("n520", "tls-server-first-n520"):
        session = 0x12345678
        magic = session ^ (((session >> 16) ^ (session & 65535)) | 2779054080)
        header = struct.pack("<II", session, magic) + bytes(32)
        return [header + struct.pack("<I", zlib.crc32(header))], cert
    if name == "vvas": return [struct.pack("<I", 307214) + bytes(10) + b"s" * 307200], cert
    if name == "winos": return [struct.pack("<IIIH", 15, 1, 0, 202) + bytes([201 ^ 55])], cert
    if name in ("http-get", "https-get"): return [http(b"synthetic HTTP body")], cert
    if name == "server-first": return [b"synthetic banner"], cert
    if name == "tls-certificate": return [b""], cert
    raise AssertionError(f"missing fixture for {path}")


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.socket_guard = patch.object(socket, "socket", side_effect=AssertionError("real network forbidden"))
        self.socket_guard.start()
        self.addCleanup(self.socket_guard.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "capture"
        self.rule = load_rule(ROOT / "probes/valleyrat/vvas.yaml")

    def prepare(self, rule=None, response=None):
        rule = rule or self.rule
        if response is None:
            responses, cert = fixture_for(Path(rule.path))
        else:
            responses, cert = [response], b"c" * 32
        transport = FakeNetwork(rule, responses, cert)
        transport.connect()
        engine = Engine(transport)
        engine.execute(rule.document["steps"])
        return engine

    def test_all_28_upstream_rules_validate_and_match_synthetic_responses(self):
        paths = sorted((ROOT / "probes").rglob("*.yaml"))
        self.assertEqual(len(paths), 28)
        for path in paths:
            with self.subTest(rule=path.relative_to(ROOT)):
                rule = load_rule(path, parameters_for(path))
                engine = self.prepare(rule)
                self.assertTrue(engine.matched)
                self.assertFalse(engine.rejected)
                result = engine.result(rule)
                self.assertEqual(result["family"], rule.document["result"]["family"])
                self.assertEqual(result["classification"], rule.document["result"].get("classification", "confirmed"))

    def test_snapshots_match_github_git_blob_hashes(self):
        manifest = json.loads((ROOT / "upstream-manifest.json").read_text())
        for item in manifest["files"]:
            if not item["path"].startswith("probes/"):
                continue
            data = (ROOT / item["path"]).read_bytes()
            self.assertEqual(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(), item["git_blob"])

    def test_arbitrary_family_and_header_and_request_are_data_driven(self):
        rule_data = copy.deepcopy(self.rule.document)
        rule_data["metadata"] = {"family": "unseen", "protocol": "new_protocol"}
        rule_data["result"].update(family="unseen", protocol="new_protocol")
        rule_data["steps"][0]["send"]["hex"] = "aa bb cc dd"
        rule_data["steps"][1]["recv_exact"]["bytes"] = 7
        rule_data["steps"][2]["extract"].update(offset=1, type="u16be")
        rule_data["steps"][3]["match"] = {"all": [
            {"eq": {"left": "$stage_size", "right": 17}},
            {"bytes_eq": {"source": "response", "offset": 3, "hex": "41 42 43 44"}}]}
        import yaml
        path = Path(self.temp.name) / "unseen.yaml"
        path.write_text(yaml.safe_dump(rule_data))
        rule = load_rule(path)
        engine = self.prepare(rule, b"!\x00\x11ABCD" + b"z" * 17)
        self.assertTrue(engine.matched)
        self.assertEqual(engine.io.sent, [b"\xaa\xbb\xcc\xdd"])
        recipe, _ = app.load_recipe(ROOT / "recipes/length-from-register.yaml", rule)
        metadata = {}
        app.acquire(engine, recipe, self.output, metadata, 1024)
        self.assertEqual((self.output / "sample.bin").read_bytes(), b"z" * 17)

    def test_default_dry_run_does_not_write_or_connect(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = app.run(["--rule", self.rule.path, "--host", "192.0.2.1", "--port", "1234", "--output", str(self.output)])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(stdout.getvalue())["network_used"])
        self.assertFalse(self.output.exists())

    def test_list_reports_all_rules_and_required_parameters(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(app.run(["--list"]), 0)
        self.assertEqual(len(json.loads(stdout.getvalue())), 28)

    def test_successful_cli_records_rule_recipe_and_artifact_hash(self):
        responses, cert = fixture_for(Path(self.rule.path))
        network = FakeNetwork(self.rule, responses, cert)
        recipe_path = ROOT / "recipes/body-from-total-length.yaml"
        with patch.object(app, "Network", return_value=network), contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = app.run(["--rule", self.rule.path, "--recipe", str(recipe_path),
                            "--download", "--host", "192.0.2.1", "--port", "1234", "--output", str(self.output)])
        self.assertEqual(code, 0)
        published = json.loads(stdout.getvalue())
        stored = json.loads((self.output / "metadata.json").read_text())
        self.assertEqual(published, stored)
        self.assertEqual(stored["rule_sha256"], self.rule.sha256)
        self.assertEqual(stored["recipe_sha256"], hashlib.sha256(recipe_path.read_bytes()).hexdigest())
        self.assertTrue(stored["matched"])
        self.assertTrue(stored["acquisition_attempted"])
        self.assertFalse(stored["executed"])
        self.assertEqual(network.close_count, 1)

    def test_unknown_recipe_fails_before_connection(self):
        path = Path(self.temp.name) / "bad-recipe.yaml"
        path.write_text("download_version: 1\nsteps:\n  - unknown_op: {}\nartifact: {mode: stream}\n")
        with patch.object(app, "Network", side_effect=AssertionError("network forbidden")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(app.run(["--rule", self.rule.path, "--recipe", str(path),
                                      "--download", "--host", "192.0.2.1", "--port", "1234", "--output", str(self.output)]), 1)

    def test_fixed_length_recipe_preserves_hash_and_header(self):
        engine = self.prepare()
        recipe, _ = app.load_recipe(ROOT / "recipes/body-from-total-length.yaml", self.rule)
        metadata = engine.result(self.rule)
        app.acquire(engine, recipe, self.output, metadata, 1024 * 1024)
        payload = (self.output / "sample.bin").read_bytes()
        self.assertEqual(payload, b"s" * 307200)
        self.assertEqual(metadata["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertFalse(metadata["sample_validated"])
        self.assertEqual((self.output / "probe-response.bin").stat().st_size, 14)

    def test_raw_default_includes_inspected_prefix(self):
        engine = self.prepare()
        recipe, _ = app.load_recipe(None, self.rule)
        metadata = {}
        app.acquire(engine, recipe, self.output, metadata, 1024 * 1024)
        self.assertEqual((self.output / "sample.bin").read_bytes(), struct.pack("<I", 307214) + bytes(10) + b"s" * 307200)

    def test_buffer_recipe_does_not_include_http_header_or_read_again(self):
        rule = load_rule(ROOT / "probes/stealer-http/lumma.yaml", {"stealer.uid": "a" * 32})
        engine = self.prepare(rule)
        recipe, _ = app.load_recipe(ROOT / "recipes/save-response-body.yaml", rule)
        with patch.object(engine.io, "read", side_effect=AssertionError("unexpected read")):
            app.acquire(engine, recipe, self.output, {}, 1024)
        self.assertEqual((self.output / "sample.bin").read_bytes(), b"a" * 64)

    def test_additional_http_acquisition_is_recipe_driven(self):
        responses, cert = fixture_for(Path(self.rule.path))
        transport = FakeNetwork(self.rule, responses + [http(b"synthetic download")], cert)
        transport.connect()
        engine = Engine(transport)
        engine.execute(self.rule.document["steps"])
        recipe, _ = app.load_recipe(ROOT / "recipes/http-get-example.yaml", self.rule)
        app.acquire(engine, recipe, self.output, {}, 1024)
        self.assertEqual(transport.connections, 2)
        self.assertIn(b"GET /example/sample.bin HTTP/1.1\r\n", transport.sent[1])
        self.assertEqual((self.output / "sample.bin").read_bytes(), b"synthetic download")

    def test_mismatch_blocks_artifact_and_recipe_requests(self):
        network = FakeNetwork(self.rule, [bytes(14) + b"should not be read"])
        with patch.object(app, "Network", return_value=network), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.run(["--rule", self.rule.path, "--recipe", str(ROOT / "recipes/http-get-example.yaml"),
                                      "--download", "--host", "192.0.2.1", "--port", "1234", "--output", str(self.output)]), 2)
        self.assertFalse(self.output.exists())
        self.assertEqual(network.sent, [bytes.fromhex("33 32 00")])
        self.assertEqual(network.reader.tell(), 14)

    def test_early_certificate_rejection_sends_no_http_request(self):
        path = ROOT / "probes/purelogs/https-ping.yaml"
        rule = load_rule(path, parameters_for(path))
        transport = FakeNetwork(rule, [b""], certificate=bytes(32))
        transport.connect()
        engine = Engine(transport)
        engine.execute(rule.document["steps"])
        self.assertTrue(engine.rejected)
        self.assertFalse(engine.matched)
        self.assertEqual(transport.sent, [])

    def test_reflected_request_is_rejected(self):
        rule = load_rule(ROOT / "probes/valleyrat/winos.yaml")
        request = struct.pack("<IIIHB", 15, 0x12345678, 0, 202, 0x67)
        engine = self.prepare(rule, request)
        self.assertTrue(engine.rejected)

    def test_truncated_and_timed_out_acquisitions_remain_partial(self):
        for failure in ("truncated", "timeout"):
            with self.subTest(failure=failure):
                output = Path(self.temp.name) / failure
                engine = self.prepare(response=struct.pack("<I", 307214) + bytes(10) + b"partial")
                recipe, _ = app.load_recipe(ROOT / "recipes/length-from-register.yaml", self.rule)
                original = engine.io.read
                def read(count, deadline=None):
                    block = original(count, deadline)
                    if not block and failure == "timeout":
                        raise TimeoutError("synthetic timeout")
                    return block
                engine.io.read = read
                with self.assertRaises((ProbeError, TimeoutError)):
                    app.acquire(engine, recipe, output, {}, 1024 * 1024)
                self.assertFalse((output / "sample.bin").exists())
                self.assertEqual((output / "sample.bin.part").read_bytes(), b"partial")
                metadata = json.loads((output / "metadata.json").read_text())
                self.assertEqual(metadata["status"], "incomplete")
                self.assertEqual(metadata["artifact_bytes"], 7)

    def test_byte_limit_is_not_reported_as_complete(self):
        engine = self.prepare()
        recipe, _ = app.load_recipe(None, self.rule)
        with self.assertRaises(ProbeError):
            app.acquire(engine, recipe, self.output, {}, 20)
        self.assertFalse((self.output / "sample.bin").exists())

    def test_empty_server_is_not_a_sample(self):
        rule = load_rule(ROOT / "probes/observations/tls-certificate.yaml")
        engine = self.prepare(rule)
        recipe, _ = app.load_recipe(None, rule)
        with self.assertRaises(ProbeError):
            app.acquire(engine, recipe, self.output, {}, 1024)
        self.assertFalse((self.output / "sample.bin").exists())

    def test_unknown_operations_and_unresolved_references_fail_preflight(self):
        for step in ({"run_shell": {"command": "anything"}}, {"send": {"source": "$missing"}},
                     {"compute": {"name": "x", "expr": {"add": {"left": "$missing", "right": 1}}}},
                     {"send": {"hex": "00", "extra": True}}):
            with self.subTest(step=step), self.assertRaises(ProbeError):
                Validator().steps([step])

    def test_missing_parameters_and_scope_fail_before_network(self):
        with self.assertRaises(ProbeError):
            load_rule(ROOT / "probes/darkcomet/raw.yaml")
        path = ROOT / "probes/stealer-route/formbook-guloader.yaml"
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(app.run(["--rule", str(path), "--probe-param", "formbook.expected_ip=192.0.2.1",
                                      "--host", "192.0.2.2", "--port", "80", "--download", "--output", str(self.output)]), 1)

    def test_existing_output_not_overwritten(self):
        self.output.mkdir()
        marker = self.output / "sample.bin"
        marker.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            app.acquire(self.prepare(), app.load_recipe(None, self.rule)[0], self.output, {}, 1024)
        self.assertEqual(marker.read_bytes(), b"keep")

    def test_yaml_duplicate_keys_aliases_and_bad_parameters_rejected(self):
        for content in ("x: 1\nx: 2\n", "x: &x [1]\ny: *x\n"):
            path = Path(self.temp.name) / "invalid.yaml"
            path.write_text(content)
            with self.assertRaises(ProbeError):
                load_yaml(path)
        with self.assertRaises(ProbeError):
            load_rule(ROOT / "probes/darkcomet/raw.yaml", {"darkcomet.key_base64": "invalid key!"})

    def test_u64_wrapping_pack_and_transform_bounds(self):
        engine = Engine(None)
        self.assertEqual(engine.expr({"sub": {"left": 0, "right": 1}}), (1 << 64) - 1)
        self.assertEqual(engine.expr({"shift_left": {"left": 1, "right": 64}}), 1)
        with self.assertRaises(ProbeError):
            engine.execute([{"pack": {"name": "x", "type": "u8", "value": 256}}])
        with self.assertRaises(ProbeError):
            engine.transform(gzip.compress(b"x" * 100), "gzip_decompress", {"max_bytes": 10})

    def test_recv_until_and_ascii_decimal(self):
        network = FakeNetwork(self.rule, [b"17\r\nTAIL"], chunk=1)
        network.connect()
        engine = Engine(network)
        steps = [{"recv_until": {"delimiter_hex": "0d0a", "max_bytes": 8, "save_as": "number"}},
                 {"extract": {"source": "number", "name": "n", "type": "asciidecimal", "offset": 0, "length": 2}}]
        Validator().steps(steps)
        engine.execute(steps)
        self.assertEqual(engine.registers["n"], 17)
        self.assertEqual(network.read(4), b"T")

    def test_duplicate_http_headers_and_chunked_fail(self):
        rule = load_rule(ROOT / "probes/observations/http-get.yaml")
        for raw in (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"):
            with self.assertRaises(ProbeError):
                self.prepare(rule, raw)

    def test_tls_starttls_transport_order_uses_yaml_prelude_and_sni(self):
        rule = load_rule(ROOT / "probes/purerat/prelude-tls-cert.yaml",
                         parameters_for(ROOT / "probes/purerat/prelude-tls-cert.yaml"))
        connection = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value = connection
        with patch("probe_engine.socket.socket", return_value=connection), \
                patch("probe_engine.ssl.create_default_context", return_value=context):
            network = Network(rule, "192.0.2.1", 56001)
            network.connect()
        connection.connect.assert_called_once_with(("192.0.2.1", 56001))
        connection.sendall.assert_called_once_with(bytes.fromhex("04000000"))
        context.wrap_socket.assert_called_once_with(connection, server_hostname="192.0.2.1")

    def test_total_time_budget_enforced(self):
        network = Network(self.rule, "192.0.2.1", 1234)
        network.deadline = 0
        with self.assertRaises(TimeoutError):
            network.budget(1)

    def test_total_length_recipe_finishes_without_waiting_for_eof(self):
        # Live observation: the frame length includes the 14-byte header and the
        # server keeps the socket open after the body. Synthetic bytes only here.
        wire = struct.pack("<I", 307214) + bytes(10) + b"x" * 307200
        engine = self.prepare(response=wire)
        original = engine.io.read
        def read(count, deadline=None):
            block = original(count, deadline)
            if not block:
                raise TimeoutError("server keeps socket open")
            return block
        engine.io.read = read
        recipe, _ = app.load_recipe(ROOT / "recipes/body-from-total-length.yaml", self.rule)
        metadata = {}
        app.acquire(engine, recipe, self.output, metadata, 1024 * 1024)
        self.assertEqual(metadata["expected_artifact_bytes"], 307200)
        self.assertEqual((self.output / "sample.bin").read_bytes(), b"x" * 307200)
        self.assertEqual(engine.io.total_received, 307214)

    def test_refused_connection_diagnostic_identifies_connect_phase(self):
        network = FakeNetwork(self.rule, [])
        network.operation = "tcp_connect"
        with patch.object(network, "connect", side_effect=ConnectionRefusedError(111, "Connection refused")), \
                patch.object(app, "Network", return_value=network), contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = app.run(["--rule", self.rule.path, "--download", "--host", "192.0.2.1",
                            "--port", "1234", "--output", str(self.output)])
        diagnostic = json.loads(stderr.getvalue().removeprefix("failed: "))
        self.assertEqual(code, 1)
        self.assertEqual(diagnostic["status"], "connection_refused")
        self.assertEqual(diagnostic["phase"], "connect")
        self.assertEqual(diagnostic["received_bytes"], 0)
        self.assertFalse(self.output.exists())

    def test_acquisition_timeout_diagnostic_reports_successful_probe_and_bytes(self):
        wire = struct.pack("<I", 307214) + bytes(10) + b"x" * 307200
        network = FakeNetwork(self.rule, [wire])
        original = network.read
        def read(count, deadline=None):
            network.operation = "recv"
            block = original(count, deadline)
            if not block:
                raise TimeoutError("server keeps socket open")
            return block
        network.read = read
        with patch.object(app, "Network", return_value=network), contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = app.run(["--rule", self.rule.path, "--download", "--host", "192.0.2.1",
                            "--port", "1234", "--output", str(self.output)])
        diagnostic = json.loads(stderr.getvalue().removeprefix("failed: "))
        self.assertEqual(code, 1)
        self.assertEqual(diagnostic["phase"], "acquisition")
        self.assertEqual(diagnostic["status"], "read_timeout")
        self.assertTrue(diagnostic["probe_match"])
        self.assertEqual(diagnostic["received_bytes"], 307214)
        self.assertEqual(diagnostic["artifact_bytes"], 307214)
        metadata = json.loads((self.output / "metadata.json").read_text())
        self.assertEqual(metadata["probe_status"], "vvas_stage_header_match")
        self.assertEqual(metadata["failure_phase"], "acquisition")

    def test_headers_only_head_tolerates_declared_content_length(self):
        # A HEAD response advertises the body length a GET would return but sends
        # no body, so a non-zero Content-Length must not abort a headers_only probe.
        path = ROOT / "probes/stealer-route/formbook-guloader.yaml"
        rule = load_rule(path, {"formbook.expected_ip": "192.0.2.1"})
        route = b"HTTP/1.1 200 OK\r\nContent-Length: 5120\r\nContent-Type: text/html\r\n\r\n"
        control = b"HTTP/1.1 404 Not Found\r\nContent-Length: 1024\r\n\r\n"
        transport = FakeNetwork(rule, [route, control])
        transport.connect()
        with patch.object(transport, "exact", side_effect=AssertionError("body must not be read")), \
                patch.object(transport, "up_to", side_effect=AssertionError("body must not be read")):
            engine = Engine(transport)
            engine.execute(rule.document["steps"])
        self.assertTrue(engine.matched)
        self.assertFalse(engine.rejected)
        self.assertEqual(transport.connections, 2)

    def test_http_body_may_be_empty_without_content_length(self):
        # A bodyless response with no Content-Length (e.g. 204, or an immediate
        # close) must still be observable, not fail the minimum-body requirement.
        rule = load_rule(ROOT / "probes/observations/http-get.yaml")
        engine = self.prepare(rule, b"HTTP/1.1 204 No Content\r\n\r\n")
        self.assertTrue(engine.matched)
        self.assertEqual(engine.buffer("body"), b"")
        self.assertEqual(engine.registers["http_status"], 204)


if __name__ == "__main__":
    unittest.main()
