import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from verifiable_log import audit, canonical, merkle, range_audit, range_proof, store


def naive_root(leaves):
    """Independent naive Merkle root for cross-checking."""
    if not leaves:
        return merkle.EMPTY_ROOT

    def sub(start, size):
        if size == 1:
            return leaves[start]
        k = 1 << (size.bit_length() - 1) if size & (size - 1) else size // 2
        return merkle.node_hash(sub(start, k), sub(start + k, size - k))

    return sub(0, len(leaves))


def _naive_subtree(leaves, start, size):
    if size == 1:
        return leaves[start]
    k = 1 << (size.bit_length() - 1) if size & (size - 1) else size // 2
    return merkle.node_hash(
        _naive_subtree(leaves, start, k),
        _naive_subtree(leaves, start + k, size - k),
    )


class RangeProofShapeTest(unittest.TestCase):
    def test_small_trees_and_all_intervals(self):
        for size in range(1, 80):
            entries = [canonical.dumps_canonical({"i": i}) for i in range(size)]
            hashes = [merkle.leaf_hash(e) for e in entries]
            self.assertEqual(merkle.root_hash(hashes), naive_root(hashes))
            for start in range(size):
                for end in range(start + 1, size + 1):
                    ranges = merkle.range_ranges(start, end, size)
                    # Disjoint maximal subtrees, inside [0,size) \\ [start,end).
                    covered = list(range(start, end))
                    outside = [
                        i
                        for lo, count in ranges
                        for i in range(lo, lo + count)
                    ]
                    self.assertEqual(sorted(outside), [i for i in range(size) if i not in covered])
                    self.assertEqual(outside, sorted(outside))  # left-to-right order
                    # Components are disjoint, positive, and ordered.
                    for lo, count in ranges:
                        self.assertGreaterEqual(lo, 0)
                        self.assertGreater(count, 0)
                        self.assertLessEqual(lo + count, size)
                        # Each anchor must hash to the independently computed
                        # subtree node (imperfect nodes are allowed, matching
                        # the consistency-proof convention).
                        self.assertEqual(
                            merkle.subtree_hash(hashes, lo, count),
                            _naive_subtree(hashes, lo, count),
                        )
                    proof = merkle.range_proof(hashes, start, end, size)
                    resp = _response_like(entries, start, end, size, proof)
                    root = merkle.root_hash(hashes).hex()
                    self.assertTrue(
                        range_audit.verify_range(resp, start, end, size, root),
                        (start, end, size),
                    )

    def test_full_range_has_empty_proof(self):
        for size in (1, 2, 3, 5, 7, 8, 13):
            entries = [canonical.dumps_canonical({"i": i}) for i in range(size)]
            hashes = [merkle.leaf_hash(e) for e in entries]
            proof = merkle.range_proof(hashes, 0, size, size)
            self.assertEqual(proof, [])
            resp = _response_like(entries, 0, size, size, proof)
            self.assertTrue(
                range_audit.verify_range(
                    resp, 0, size, size, merkle.root_hash(hashes).hex()
                )
            )

    def test_single_record_proof_verifies_and_matches_ranges(self):
        size = 11
        entries = [canonical.dumps_canonical({"i": i}) for i in range(size)]
        hashes = [merkle.leaf_hash(e) for e in entries]
        root = merkle.root_hash(hashes).hex()
        for index in range(size):
            ranges = merkle.range_ranges(index, index + 1, size)
            proof = merkle.range_proof(hashes, index, index + 1, size)
            self.assertEqual(
                proof,
                [merkle.subtree_hash(hashes, lo, count) for lo, count in ranges],
            )
            resp = _response_like(entries, index, index + 1, size, proof)
            self.assertTrue(range_audit.verify_range(resp, index, index + 1, size, root))

    def test_non_power_of_two_example(self):
        # size 7, interval [2,5): outside maximal subtrees are
        # [0,2), [5,6), [6,7).
        self.assertEqual(
            merkle.range_ranges(2, 5, 7), [(0, 2), (5, 1), (6, 1)]
        )


def _response_like(entries, start, end, size, proof):
    return {
        "start": start,
        "end": end,
        "tree_size": size,
        "root_hash": merkle.root_hash(
            [merkle.leaf_hash(e) for e in entries][:size]
        ).hex(),
        "records": [
            {"index": i, "canonical_json": entries[i].decode("utf-8")}
            for i in range(start, end)
        ],
        "proof": [h.hex() for h in proof],
    }


class RangeTamperTest(unittest.TestCase):
    def setUp(self):
        self.size = 13
        self.start, self.end = 3, 9
        entries = [canonical.dumps_canonical({"i": i}) for i in range(self.size)]
        hashes = [merkle.leaf_hash(e) for e in entries]
        self.entries = entries
        self.root = merkle.root_hash(hashes).hex()
        proof = merkle.range_proof(hashes, self.start, self.end, self.size)
        self.good = _response_like(entries, self.start, self.end, self.size, proof)

    def verify(self, resp, **kw):
        return range_audit.verify_range(
            resp, kw.get("start", self.start), kw.get("end", self.end),
            kw.get("size", self.size), kw.get("root", self.root),
        )

    def test_good_response_passes(self):
        self.assertTrue(self.verify(self.good))

    def test_missing_record_fails(self):
        resp = _clone(self.good)
        resp["records"].pop(2)
        self.assertFalse(self.verify(resp))
        # Length matches but an index is skipped (gap).
        resp = _clone(self.good)
        resp["records"].pop(2)
        resp["records"].append({"index": self.end, "canonical_json": self.entries[self.end].decode()})
        self.assertFalse(self.verify(resp))

    def test_duplicate_record_fails(self):
        resp = _clone(self.good)
        resp["records"].insert(3, resp["records"][3])
        self.assertFalse(self.verify(resp))
        # Same length: duplicate index while dropping another.
        resp = _clone(self.good)
        resp["records"][4] = {"index": 3, "canonical_json": self.entries[3].decode()}
        self.assertFalse(self.verify(resp))

    def test_reordered_records_fail(self):
        resp = _clone(self.good)
        first, second = resp["records"][0], resp["records"][1]
        resp["records"][0] = {"index": self.start, "canonical_json": second["canonical_json"]}
        resp["records"][1] = {"index": self.start + 1, "canonical_json": first["canonical_json"]}
        self.assertFalse(self.verify(resp))

    def test_substituted_record_bytes_fail(self):
        resp = _clone(self.good)
        resp["records"][0]["canonical_json"] = canonical.dumps_canonical({"i": 999}).decode()
        self.assertFalse(self.verify(resp))

    def test_wrong_declared_index_fails(self):
        resp = _clone(self.good)
        resp["records"][0]["index"] = self.start + 1
        self.assertFalse(self.verify(resp))

    def test_extra_record_fails(self):
        resp = _clone(self.good)
        resp["records"].append(
            {"index": self.end, "canonical_json": self.entries[self.end].decode()}
        )
        self.assertFalse(self.verify(resp))

    def test_noncanonical_bytes_fail(self):
        resp = _clone(self.good)
        resp["records"][0]["canonical_json"] = '{"i": 3,}'  # invalid JSON
        self.assertFalse(self.verify(resp))
        resp = _clone(self.good)
        resp["records"][0]["canonical_json"] = '{ "i":3 }'  # semantically equal, noncanonical
        self.assertFalse(self.verify(resp))

    def test_response_coordinates_must_match_request(self):
        for field, value in (("start", self.start + 1), ("end", self.end + 1),
                             ("tree_size", self.size - 1)):
            resp = _clone(self.good)
            resp[field] = value
            self.assertFalse(self.verify(resp), field)

    def test_response_root_must_match_anchor(self):
        resp = _clone(self.good)
        resp["root_hash"] = "00" * 32
        self.assertFalse(self.verify(resp))
        self.assertFalse(self.verify(self.good, root="00" * 32))

    def test_proof_tampering_fails(self):
        resp = _clone(self.good)
        target = bytearray.fromhex(resp["proof"][0])
        target[0] ^= 1
        resp["proof"][0] = target.hex()
        self.assertFalse(self.verify(resp))

    def test_missing_proof_hash_fails(self):
        resp = _clone(self.good)
        resp["proof"].pop()
        self.assertFalse(self.verify(resp))

    def test_extra_unused_proof_hash_fails(self):
        resp = _clone(self.good)
        resp["proof"].append(resp["proof"][-1])
        self.assertFalse(self.verify(resp))

    def test_proof_reordered_fails(self):
        resp = _clone(self.good)
        if len(resp["proof"]) >= 2:
            resp["proof"][0], resp["proof"][-1] = resp["proof"][-1], resp["proof"][0]
            self.assertFalse(self.verify(resp))

    def test_bad_types_rejected(self):
        self.assertFalse(range_audit.verify_range(None, self.start, self.end, self.size, self.root))
        self.assertFalse(self.verify(self.good, start=True))
        resp = _clone(self.good)
        resp["records"] = "nope"
        self.assertFalse(self.verify(resp))
        resp = _clone(self.good)
        resp["proof"] = ["zz"]
        self.assertFalse(self.verify(resp))

    def test_invalid_interval_arguments(self):
        for s, e, n in ((-1, 3, 5), (3, 3, 5), (4, 3, 5), (0, 6, 5), (0, 0, 0)):
            resp = self.good
            self.assertFalse(range_audit.verify_range(resp, s, e, n, self.root))


def _clone(value):
    import json
    return json.loads(json.dumps(value))


class RangeServiceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.s = store.Store(self.directory.name)
        self.entries = [canonical.dumps_canonical({"i": i}) for i in range(20)]
        self.s.append_entries(self.entries[:7])
        # Save a historical head after 7 records, then append more.
        self.hist_size, self.hist_root = self.s.tree_head()
        self.s.append_entries(self.entries[7:])

    def tearDown(self):
        self.directory.cleanup()

    def test_response_binds_requested_historical_tree(self):
        resp = range_proof.response(self.s, 2, 6, 7)
        self.assertEqual(resp["tree_size"], 7)
        self.assertEqual(resp["root_hash"], self.hist_root.hex())
        self.assertEqual([r["index"] for r in resp["records"]], [2, 3, 4, 5])
        self.assertTrue(
            range_audit.verify_range(resp, 2, 6, 7, self.hist_root.hex())
        )

    def test_current_tree_default(self):
        resp = range_proof.response(self.s, 0, 20)
        self.assertEqual(resp["tree_size"], 20)
        self.assertEqual(resp["proof"], [])
        size, root = self.s.tree_head()
        self.assertTrue(range_audit.verify_range(resp, 0, 20, size, root.hex()))

    def test_out_of_range_request_rejected(self):
        with self.assertRaises(IndexError):
            range_proof.response(self.s, 0, 8, 7)
        with self.assertRaises(IndexError):
            range_proof.response(self.s, 5, 5, 7)
        with self.assertRaises(IndexError):
            range_proof.response(self.s, 19, 21)

    def test_appended_records_do_not_change_historical_proof(self):
        first = range_proof.response(self.s, 1, 7, 7)
        self.s.append_entries([canonical.dumps_canonical({"more": True})])
        second = range_proof.response(self.s, 1, 7, 7)
        self.assertEqual(first, second)


class RangeCliTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data = Path(self.directory.name) / "data"
        self.process = None

    def tearDown(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=10)
            for stream in (self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
        self.directory.cleanup()

    def start_server(self, env=None):
        import os
        import time
        args = [sys.executable, "-m", "verifiable_log", "serve",
                "--host", "127.0.0.1", "--port", "0", "--data", str(self.data)]
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        self.process = subprocess.Popen(
            args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=full_env,
        )
        line = self.process.stdout.readline().strip()
        port = int(line)
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                audit.tree_head(base)
                return base
            except Exception:
                time.sleep(0.02)
        raise AssertionError("server did not start")

    def append(self, base, values):
        body = canonical.dumps_canonical({"records": values})
        import urllib.request
        req = urllib.request.Request(
            base + "/v1/records", data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return canonical.loads(resp.read())

    def get(self, base, path):
        import urllib.request
        with urllib.request.urlopen(base + path, timeout=10) as resp:
            return canonical.loads(resp.read())

    def run_audit(self, *argv):
        return audit.main(["range", *argv])

    def test_cli_range_success_and_tamper_failure(self):
        base = self.start_server()
        self.append(base, [{"i": i} for i in range(15)])
        old_head = self.get(base, "/v1/tree-head")
        self.append(base, [{"i": i} for i in range(15, 40)])

        # Historical interval against the saved head must still pass after
        # further appends.
        self.assertEqual(
            self.run_audit(
                base, "--start", "3", "--end", "12",
                "--tree-size", str(old_head["tree_size"]),
                "--root-hash", old_head["root_hash"],
            ),
            0,
        )

        # Current tree, non-aligned interval.
        self.assertEqual(
            self.run_audit(
                base, "--start", "0", "--end", "40",
                "--tree-size", "40",
                "--root-hash", self.get(base, "/v1/tree-head")["root_hash"],
            ),
            0,
        )

        # Anchor mismatch must fail with a non-zero exit.
        self.assertEqual(
            self.run_audit(
                base, "--start", "3", "--end", "12",
                "--tree-size", "15", "--root-hash", "00" * 32,
            ),
            1,
        )
        # An interval beyond the anchored tree cannot be served honestly.
        self.assertEqual(
            self.run_audit(
                base, "--start", "3", "--end", "16",
                "--tree-size", "15", "--root-hash", old_head["root_hash"],
            ),
            1,
        )

    def test_restart_preserves_historical_range(self):
        base = self.start_server()
        self.append(base, [{"i": i} for i in range(9)])
        head = self.get(base, "/v1/tree-head")
        self.process.terminate()
        self.process.wait(timeout=10)
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
        self.process = None

        base = self.start_server()
        self.append(base, [{"i": i} for i in range(9, 25)])
        self.assertEqual(
            self.run_audit(
                base, "--start", "2", "--end", "9",
                "--tree-size", str(head["tree_size"]),
                "--root-hash", head["root_hash"],
            ),
            0,
        )


if __name__ == "__main__":
    unittest.main()
