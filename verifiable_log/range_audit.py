"""Verifier has no dependency on server tree/proof generation."""

import hashlib
from . import canonical


def leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def split(count):
    return 1 << ((count - 1).bit_length() - 1)


def digest(text):
    if not isinstance(text, str) or len(text) != 64:
        raise ValueError("bad hash")
    value = bytes.fromhex(text)
    if len(value) != 32:
        raise ValueError("bad hash")
    return value


def payload(record):
    raw = record["canonical_json"].encode("utf-8")
    if canonical.dumps_canonical(canonical.loads(raw)) != raw:
        raise ValueError("noncanonical disclosed record")
    return raw


def verify_range(value, start, end, size, root):
    try:
        expected = digest(root)
        for record in value["records"]:
            path = iter(record["inclusion"])
            index = record["index"]

            def walk(lo, count):
                if count == 1:
                    return leaf(payload(record))
                cut = split(count)
                sibling = digest(next(path))
                if index < lo + cut:
                    return node(walk(lo, cut), sibling)
                return node(sibling, walk(lo + cut, count - cut))

            if walk(0, value["tree_size"]) != expected:
                return False
        return True
    except (KeyError, TypeError, ValueError, IndexError, StopIteration):
        return False
