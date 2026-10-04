import copy
import json
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from verifiable_log import audit, canonical, merkle
from verifiable_log import range_proof, store as storage
from verifiable_log.range_audit import verify_range


def entries(count):
    return [canonical.dumps_canonical({"i": i}) for i in range(count)]


def disclosure(payloads, size, start, end):
    leaves = [merkle.leaf_hash(item) for item in payloads[:size]]
    return {
        "start": start,
        "end": end,
        "tree_size": size,
        "root_hash": merkle.root_hash(leaves).hex(),
        "records": [
            {"index": i, "canonical_json": payloads[i].decode("utf-8")}
            for i in range(start, end)
        ],
        "proof": [
            item.hex() for item in merkle.range_proof(leaves, start, end, size)
        ],
    }


class RangeProofMathTest(unittest.TestCase):
    def test_all_intervals_of_small_trees_verify(self):
        payloads = entries(40)
        leaves = [merkle.leaf_hash(item) for item in payloads]
        for size in range(1, len(payloads) + 1):
            root = merkle.root_hash(leaves[:size])
            for start in range(size):
                for end in range(start + 1, size + 1):
                    proof = merkle.range_proof(leaves, start, end, size)
                    self.assertTrue(
                        merkle.verify_range(
                            leaf_data=payloads[start:end],
                            start=start,
                            end=end,
                            tree_size=size,
                            proof=proof,
                            expected_root=root,
                        ),
                        (size, start, end),
                    )

    def test_independent_verifier_accepts_honest_disclosure(self):
        payloads = entries(33)
        # Perfect, imperfect, and awkward tree shapes plus edge intervals.
        cases = [
            (1, 0, 1),
            (2, 0, 2),
            (3, 1, 3),
            (8, 0, 8),
            (8, 3, 4),
            (16, 5, 11),
            (17, 0, 17),
            (17, 15, 17),
            (31, 0, 1),
            (31, 30, 31),
            (33, 2, 31),
            (33, 32, 33),
        ]
        for size, start, end in cases:
            value = disclosure(payloads, size, start, end)
            self.assertTrue(
                verify_range(value, start, end, size, value["root_hash"]),
                (size, start, end),
            )

    def test_proof_shape_matches_maximal_outside_subtrees(self):
        self.assertEqual(merkle.range_proof_ranges(3, 5, 12),
                         [(0, 2), (2, 1), (5, 1), (6, 2), (8, 4)])
        self.assertEqual(merkle.range_proof_ranges(0, 1, 1), [])
        self.assertEqual(merkle.range_proof_ranges(0, 8, 8), [])
        self.assertEqual(merkle.range_proof_ranges(4, 8, 8), [(0, 4)])


class RangeTamperTest(unittest.TestCase):
    def setUp(self):
        self.payloads = entries(12)
        self.size = 12
        self.start = 3
        self.end = 8
        self.value = disclosure(self.payloads, self.size, self.start, self.end)
        self.root = self.value["root_hash"]

    def check(self, value=None, start=None, end=None, size=None, root=None):
        return verify_range(
            self.value if value is None else value,
            self.start if start is None else start,
            self.end if end is None else end,
            self.size if size is None else size,
            self.root if root is None else root,
        )

    def mutated(self, func):
        value = copy.deepcopy(self.value)
        func(value)
        return value

    def test_honest_response_verifies(self):
        self.assertTrue(self.check())

    def test_missing_middle_record_rejected(self):
        def change(value):
            del value["records"][2]

        self.assertFalse(self.check(self.mutated(change)))

    def test_duplicated_record_rejected(self):
        def change(value):
            value["records"].insert(2, dict(value["records"][1]))

        self.assertFalse(self.check(self.mutated(change)))

    def test_reordered_records_rejected(self):
        def change(value):
            records = value["records"]
            records[0], records[1] = records[1], records[0]

        self.assertFalse(self.check(self.mutated(change)))

    def test_substituted_record_bytes_rejected(self):
        def change(value):
            value["records"][1]["canonical_json"] = '{"i":999}'

        self.assertFalse(self.check(self.mutated(change)))

    def test_wrong_record_index_rejected(self):
        def change(value):
            value["records"][1]["index"] = 9

        self.assertFalse(self.check(self.mutated(change)))

    def test_noncanonical_record_bytes_rejected(self):
        def change(value):
            value["records"][0]["canonical_json"] = '{ "i": 3 }'

        self.assertFalse(self.check(self.mutated(change)))

    def test_extra_proof_hash_rejected(self):
        def change(value):
            value["proof"].append(value["proof"][0])

        self.assertFalse(self.check(self.mutated(change)))

    def test_missing_proof_hash_rejected(self):
        def change(value):
            value["proof"].pop()

        self.assertFalse(self.check(self.mutated(change)))

    def test_flipped_proof_hash_rejected(self):
        def change(value):
            raw = bytearray(bytes.fromhex(value["proof"][0]))
            raw[0] ^= 1
            value["proof"][0] = bytes(raw).hex()

        self.assertFalse(self.check(self.mutated(change)))

    def test_unused_per_record_receipt_rejected(self):
        def change(value):
            for record in value["records"]:
                record["inclusion"] = []

        self.assertFalse(self.check(self.mutated(change)))

    def test_extra_response_field_rejected(self):
        def change(value):
            value["ok"] = True

        self.assertFalse(self.check(self.mutated(change)))

    def test_newer_tree_than_requested_rejected(self):
        bigger = disclosure(self.payloads + entries(1), 13, self.start, self.end)

        def change(value):
            value["tree_size"] = bigger["tree_size"]
            value["root_hash"] = bigger["root_hash"]
            value["proof"] = bigger["proof"]

        self.assertFalse(self.check(self.mutated(change)))

    def test_response_interval_mismatch_rejected(self):
        shifted = disclosure(self.payloads, self.size, 4, 9)
        self.assertFalse(self.check(shifted))

    def test_caller_interval_mismatch_rejected(self):
        self.assertFalse(self.check(start=2))
        self.assertFalse(self.check(end=9))
        self.assertFalse(self.check(size=11))

    def test_untrusted_root_rejected(self):
        other = disclosure(self.payloads, self.size - 1, 0, 1)["root_hash"]
        self.assertNotEqual(other, self.root)
        self.assertFalse(self.check(root=other))
        self.assertFalse(self.check(root="00" * 32))

    def test_malformed_arguments_rejected(self):
        self.assertFalse(self.check(root="not-hex"))
        self.assertFalse(self.check(start=-1))
        self.assertFalse(self.check(start=self.end))
        self.assertFalse(verify_range([], self.start, self.end, self.size, self.root))
        self.assertFalse(verify_range(None, self.start, self.end, self.size, self.root))


class RangeStoreTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = storage.Store(Path(self.directory.name))

    def tearDown(self):
        self.directory.cleanup()

    def test_response_honors_historical_tree_size(self):
        self.store.append_entries(entries(7))
        old_size, old_root = self.store.tree_head()
        self.store.append_entries(entries(5))

        value = range_proof.response(self.store, 2, 6, old_size)
        self.assertEqual(value["tree_size"], old_size)
        self.assertEqual(value["root_hash"], old_root.hex())
        self.assertEqual([r["index"] for r in value["records"]], [2, 3, 4, 5])
        self.assertEqual(set(value["records"][0]), {"index", "canonical_json"})
        self.assertTrue(verify_range(value, 2, 6, old_size, old_root.hex()))

        current_size, current_root = self.store.tree_head()
        value = range_proof.response(self.store, 2, 6)
        self.assertEqual(value["tree_size"], current_size)
        self.assertEqual(value["root_hash"], current_root.hex())
        self.assertTrue(verify_range(value, 2, 6, current_size, current_root.hex()))

    def test_unavailable_tree_size_rejected(self):
        self.store.append_entries(entries(4))
        with self.assertRaises(IndexError):
            range_proof.response(self.store, 0, 2, 5)
        with self.assertRaises(IndexError):
            range_proof.response(self.store, 2, 2)
        with self.assertRaises(IndexError):
            range_proof.response(self.store, 3, 9)


class RangeServiceCliTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data = Path(self.directory.name) / "data"
        self.process = None

    def tearDown(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=10)
            self._close_process_streams()
        self.directory.cleanup()

    def _close_process_streams(self):
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()

    def start_server(self):
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=10)
            self._close_process_streams()
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "verifiable_log",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--data",
                str(self.data),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        line = self.process.stdout.readline().strip()
        if not line:
            err = self.process.stderr.read() if self.process.stderr else ""
            raise AssertionError(f"server did not print a port: {err}")
        base = f"http://127.0.0.1:{int(line)}"
        for _ in range(50):
            try:
                audit.tree_head(base)
                return base
            except Exception:
                time.sleep(0.02)
        raise AssertionError("server did not become ready")

    def request(self, base, method, path, body=None):
        data = canonical.dumps_canonical(body) if body is not None else None
        request = urllib.request.Request(
            base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return canonical.loads(response.read())

    def run_audit(self, base, *args):
        return subprocess.run(
            [sys.executable, "-m", "verifiable_log", "audit", "range", base, *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_historical_range_audit_survives_append_and_restart(self):
        base = self.start_server()
        self.request(
            base, "POST", "/v1/records", {"records": [{"n": i} for i in range(7)]}
        )
        old_head = audit.tree_head(base)
        self.request(
            base, "POST", "/v1/records", {"records": [{"n": i} for i in range(7, 13)]}
        )

        value = self.request(base, "GET", "/v1/range?start=2&end=6&tree_size=7")
        self.assertEqual(
            set(value), {"start", "end", "tree_size", "root_hash", "records", "proof"}
        )
        self.assertEqual((value["start"], value["end"]), (2, 6))
        self.assertEqual(value["tree_size"], 7)
        self.assertEqual(value["root_hash"], old_head["root_hash"])
        self.assertEqual([r["index"] for r in value["records"]], [2, 3, 4, 5])
        self.assertEqual(set(value["records"][0]), {"index", "canonical_json"})

        # Restart must not change the meaning of the historical spot-check.
        base = self.start_server()
        value_again = self.request(base, "GET", "/v1/range?start=2&end=6&tree_size=7")
        self.assertEqual(value_again, value)

        audit_args = [
            "--start",
            "2",
            "--end",
            "6",
            "--tree-size",
            "7",
            "--root-hash",
            old_head["root_hash"],
        ]
        completed = self.run_audit(base, *audit_args)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        outcome = json.loads(completed.stdout)
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["records_checked"], 4)

        # A different trusted head must not verify against this disclosure.
        head_now = audit.tree_head(base)
        completed = self.run_audit(
            base, *audit_args[:-1], head_now["root_hash"]
        )
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stdout)["ok"])

        # The current tree head audits fine against the current tree.
        completed = self.run_audit(
            base,
            "--start",
            "2",
            "--end",
            "6",
            "--tree-size",
            str(head_now["tree_size"]),
            "--root-hash",
            head_now["root_hash"],
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["ok"])

    def test_range_endpoint_rejects_unavailable_tree(self):
        base = self.start_server()
        self.request(
            base, "POST", "/v1/records", {"records": [{"n": i} for i in range(4)]}
        )
        for query in (
            "/v1/range?start=0&end=3&tree_size=9",
            "/v1/range?start=2&end=9",
            "/v1/range?start=3&end=3",
        ):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.request(base, "GET", query)
            self.assertEqual(caught.exception.code, 404)


class MaliciousServiceTest(unittest.TestCase):
    """The audit CLI must not be convinced by a dishonest service."""

    def setUp(self):
        self.payloads = entries(9)
        self.size = 9
        self.start = 2
        self.end = 7
        self.honest = disclosure(self.payloads, self.size, self.start, self.end)
        self.root = self.honest["root_hash"]
        self.server = None

    def tearDown(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()

    def serve(self, value):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading

        body = canonical.dumps_canonical(value)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def audit_against(self, value):
        base = self.serve(value)
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "verifiable_log",
                "audit",
                "range",
                base,
                "--start",
                str(self.start),
                "--end",
                str(self.end),
                "--tree-size",
                str(self.size),
                "--root-hash",
                self.root,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_honest_service_passes(self):
        completed = self.audit_against(self.honest)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["ok"])

    def test_gap_in_disclosed_records_fails(self):
        value = copy.deepcopy(self.honest)
        del value["records"][2]  # middle record silently dropped
        completed = self.audit_against(value)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stdout)["ok"])

    def test_old_style_individual_receipts_fail(self):
        # A service answering with per-record inclusion receipts and an empty
        # shared proof (the historical misbehavior) must not verify.
        value = copy.deepcopy(self.honest)
        leaves = [merkle.leaf_hash(item) for item in self.payloads]
        for record in value["records"]:
            record["inclusion"] = [
                item.hex()
                for item in merkle.inclusion_proof(leaves, record["index"], self.size)
            ]
        value["proof"] = []
        completed = self.audit_against(value)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stdout)["ok"])

    def test_newer_tree_substituted_for_requested_head_fails(self):
        value = disclosure(self.payloads + entries(3), 12, self.start, self.end)
        self.assertNotEqual(value["root_hash"], self.root)
        completed = self.audit_against(value)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stdout)["ok"])

    def test_reordered_disclosure_fails(self):
        value = copy.deepcopy(self.honest)
        records = value["records"]
        records[1], records[3] = records[3], records[1]
        completed = self.audit_against(value)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
