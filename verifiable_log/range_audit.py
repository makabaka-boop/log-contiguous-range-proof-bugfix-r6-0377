"""Independent verifier for complete contiguous record disclosures.

The verifier has no dependency on service-side tree or proof generation: it
imports neither the service Merkle module nor the service proof builder.  The
proof *shape* (how many hashes, which subtree each one anchors, and where it
sits left-to-right) is derived solely from the caller-supplied interval and
tree size.  The service supplies only leaf bytes and sibling hashes, all of
which are treated as untrusted.

A successful verification simultaneously proves:

* the response names exactly the requested half-open interval [start, end);
* exactly ``end - start`` records were delivered, at the consecutive indices
  start..end-1, in order -- so a missing, duplicated, substituted, reordered,
  extra or short disclosure fails;
* each record's exact canonical bytes hash to a tree leaf;
* the single shared proof vector is exactly the derived shape -- neither
  missing hashes nor surplus unused proof material are accepted;
* the rebuilt root equals the caller's independently trusted tree head.
"""

import hashlib
from . import canonical


def leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def split(count):
    return 1 << ((count - 1).bit_length() - 1)


def digest(value):
    if not isinstance(value, str):
        raise ValueError("hash must be a hexadecimal string")
    decoded = bytes.fromhex(value)
    if len(decoded) != 32:
        raise ValueError("hash must be 32 bytes")
    return decoded


def _is_int(value):
    # bool is a subclass of int but is never a valid log coordinate.
    return isinstance(value, int) and not isinstance(value, bool)


def _ranges(start, end, size):
    """Verifier-derived maximal outside subtrees in left-to-right order."""
    result = []

    def walk(lo, count):
        hi = lo + count
        if hi <= start or lo >= end:
            result.append((lo, count))
            return
        if start <= lo and hi <= end:
            return
        cut = split(count)
        walk(lo, cut)
        walk(lo + cut, count - cut)

    walk(0, size)
    return result


def verify_range(value, start, end, size, root):
    try:
        if not _is_int(start) or not _is_int(end) or not _is_int(size):
            return False
        if not 0 <= start < end <= size:
            return False
        if not isinstance(value, dict):
            return False
        expected_root = digest(root)

        # Bind the response to the caller's requested coordinates and head;
        # response-declared values are never allowed to widen or shift them.
        for field, wanted in (
            ("start", start),
            ("end", end),
            ("tree_size", size),
        ):
            if not _is_int(value.get(field)) or value[field] != wanted:
                return False
        if value.get("root_hash") != root:
            return False

        records = value.get("records")
        if not isinstance(records, list) or len(records) != end - start:
            return False

        leaves = {}
        for offset, record in enumerate(records):
            if not isinstance(record, dict):
                return False
            index = record.get("index")
            if not _is_int(index) or index != start + offset:
                return False
            text = record.get("canonical_json")
            if not isinstance(text, str):
                return False
            raw = text.encode("utf-8")
            # The bytes under the leaf hash must be canonical JSON; otherwise a
            # semantically equal re-encoding could stand in for a record.
            if canonical.dumps_canonical(canonical.loads(raw)) != raw:
                return False
            leaves[index] = leaf(raw)

        proof = value.get("proof")
        if not isinstance(proof, list):
            return False
        hashes = [digest(item) for item in proof]
        consumed = 0

        def rebuild(lo, count):
            nonlocal consumed
            hi = lo + count
            if hi <= start or lo >= end:
                # A maximal outside subtree: its anchor must be supplied here,
                # in exactly this derived position.
                if consumed >= len(hashes):
                    raise ValueError("proof is too short")
                h = hashes[consumed]
                consumed += 1
                return h
            if start <= lo and hi <= end:
                if count == 1:
                    return leaves[lo]
                cut = split(count)
                return node(
                    rebuild(lo, cut),
                    rebuild(lo + cut, count - cut),
                )
            cut = split(count)
            return node(
                rebuild(lo, cut),
                rebuild(lo + cut, count - cut),
            )

        calculated = rebuild(0, size)
        # Every proof hash had to anchor a derived outside subtree; surplus,
        # unused proof material is rejected.
        if consumed != len(hashes):
            return False
        return calculated == expected_root
    except (KeyError, TypeError, ValueError, IndexError, UnicodeError, RecursionError):
        return False
