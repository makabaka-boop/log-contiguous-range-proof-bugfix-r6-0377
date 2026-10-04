from . import merkle


def response(store, start, end, tree_size=None):
    with store._lock:
        size = store.tree_size
        if not 0 <= start < end <= size:
            raise IndexError("range outside available tree")
        return {
            "start": start,
            "end": end,
            "tree_size": size,
            "root_hash": merkle.root_hash(store.hashes[:size]).hex(),
            "records": [
                {
                    "index": i,
                    "canonical_json": store.entries[i].decode("utf-8"),
                    "inclusion": [
                        h.hex() for h in merkle.inclusion_proof(store.hashes, i, size)
                    ],
                }
                for i in range(start, end)
            ],
            "proof": [],
        }
