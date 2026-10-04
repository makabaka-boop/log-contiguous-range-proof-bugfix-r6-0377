"""Server-side assembly of the range-disclosure wire response.

The response discloses every record in the half-open interval [start, end)
against the requested current or historical tree, plus a single shared
proof: the hashes of the maximal subtrees wholly outside the interval, in
left-to-right tree order.  Individual inclusion receipts are not emitted;
they are not the range proof.
"""

from . import merkle


def response(store, start, end, tree_size=None):
    with store._lock:
        current = store.tree_size
        size = current if tree_size is None else tree_size
        if not 0 <= start < end <= size <= current:
            raise IndexError("requested range or tree size is unavailable")
        leaves = store.hashes[:size]
        return {
            "start": start,
            "end": end,
            "tree_size": size,
            "root_hash": merkle.root_hash(leaves).hex(),
            "records": [
                {
                    "index": i,
                    "canonical_json": store.entries[i].decode("utf-8"),
                }
                for i in range(start, end)
            ],
            "proof": [
                item.hex()
                for item in merkle.range_proof(store.hashes, start, end, size)
            ],
        }
