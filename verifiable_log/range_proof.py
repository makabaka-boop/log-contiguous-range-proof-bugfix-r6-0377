from . import merkle


def response(store, start, end, tree_size=None):
    with store._lock:
        size = store.tree_size if tree_size is None else tree_size
        if not 0 <= start < end <= size <= store.tree_size:
            raise IndexError("range outside available tree")
        root = merkle.root_hash(store.hashes[:size])
        proof = merkle.range_proof(store.hashes, start, end, size)
        return {
            "start": start,
            "end": end,
            "tree_size": size,
            "root_hash": root.hex(),
            "records": [
                {
                    "index": i,
                    "canonical_json": store.entries[i].decode("utf-8"),
                }
                for i in range(start, end)
            ],
            "proof": [h.hex() for h in proof],
        }
