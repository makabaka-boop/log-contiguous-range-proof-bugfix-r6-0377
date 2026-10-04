"""Independent verifier for contiguous range disclosure.

This module deliberately shares no code with the service's Merkle
implementation.  Everything is re-derived from the caller's requested
interval, the caller's trusted tree head, and the untrusted response:

* the response must name exactly the requested start/end/tree size and the
  trusted root hash;
* records must cover [start, end) exactly, in order, with no gaps,
  duplicates, or reordering, and each must carry canonical record bytes;
* the shared proof must match the shape implied by the caller-supplied
  interval and tree size — no missing, extra, or unused hashes.
"""

import hashlib

from . import canonical

HASH_SIZE = 32
HEX_SIZE = 64

_RESPONSE_KEYS = {"start", "end", "tree_size", "root_hash", "records", "proof"}
_RECORD_KEYS = {"index", "canonical_json"}


def _leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split_point(count):
    if count <= 1:
        raise ValueError("cannot split a single leaf")
    if count & (count - 1) == 0:
        return count // 2
    return 1 << (count.bit_length() - 1)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _digest(value):
    if not isinstance(value, str) or len(value) != HEX_SIZE:
        raise ValueError("bad hash")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("bad hash") from exc
    if len(raw) != HASH_SIZE:
        raise ValueError("bad hash")
    return raw


def _payload(record):
    text = record["canonical_json"]
    if not isinstance(text, str):
        raise ValueError("record canonical_json must be a string")
    raw = text.encode("utf-8")
    if canonical.dumps_canonical(canonical.loads(raw)) != raw:
        raise ValueError("noncanonical disclosed record")
    return raw


def _outside_ranges(start, end, size):
    """Maximal subtree ranges wholly outside [start, end), left to right."""

    ranges = []

    def walk(lo, count):
        hi = lo + count
        if hi <= start or lo >= end:
            ranges.append((lo, count))
            return
        if start <= lo and hi <= end:
            return
        cut = _split_point(count)
        walk(lo, cut)
        walk(lo + cut, count - cut)

    walk(0, size)
    return ranges


def _subtree(leaves, lo, count):
    if count == 1:
        return leaves[lo]
    cut = _split_point(count)
    return _node(_subtree(leaves, lo, cut), _subtree(leaves, lo + cut, count - cut))


def verify_range(value, start, end, size, root):
    """Return True only if the response proves the exact requested interval.

    ``start``, ``end``, ``size`` and ``root`` (hex) are the caller's
    requested interval and trusted tree head; ``value`` is the untrusted
    service response.  Any missing, substituted, reordered, or extra
    material makes the check fail.
    """

    try:
        if not (_is_int(start) and _is_int(end) and _is_int(size)):
            return False
        if not 0 <= start < end <= size:
            return False
        expected_root = _digest(root)

        if not isinstance(value, dict) or set(value) != _RESPONSE_KEYS:
            return False
        if not _is_int(value["start"]) or value["start"] != start:
            return False
        if not _is_int(value["end"]) or value["end"] != end:
            return False
        if not _is_int(value["tree_size"]) or value["tree_size"] != size:
            return False
        if _digest(value["root_hash"]) != expected_root:
            return False

        records = value["records"]
        if not isinstance(records, list) or len(records) != end - start:
            return False
        leaves = []
        for offset, record in enumerate(records):
            if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
                return False
            index = record["index"]
            if not _is_int(index) or index != start + offset:
                return False
            leaves.append(_leaf(_payload(record)))

        proof_value = value["proof"]
        if not isinstance(proof_value, list):
            return False
        proof = [_digest(item) for item in proof_value]
        if len(proof) != len(_outside_ranges(start, end, size)):
            return False

        consumed = 0

        def walk(lo, count):
            nonlocal consumed
            hi = lo + count
            if hi <= start or lo >= end:
                item = proof[consumed]
                consumed += 1
                return item
            if start <= lo and hi <= end:
                return _subtree(leaves, lo - start, count)
            cut = _split_point(count)
            return _node(walk(lo, cut), walk(lo + cut, count - cut))

        calculated = walk(0, size)
        return consumed == len(proof) and calculated == expected_root
    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        StopIteration,
        RecursionError,
    ):
        return False
