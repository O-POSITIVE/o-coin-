"""The ONE place the proof-of-work hash function is defined — imported by
both blockchain.py (the node's own validation) and miner.py (an external
miner's local search loop). These two previously had independent copies
of the same logic, which is exactly the kind of thing that silently drifts
out of sync the moment one gets updated and the other doesn't (this
happened for real while switching from SHA-256 to Scrypt during
development — miner.py's copy got fixed manually, but nothing would have
caught it happening again the next time the algorithm changed). A miner
finding a "valid" nonce against the wrong hash function would have every
submission rejected by the node with no obvious reason why, which is a
miserable thing to debug from the miner side. One shared function makes
that whole bug class impossible instead of just "remembered to fix twice."
"""
import hashlib
import json

SCRYPT_N, SCRYPT_R, SCRYPT_P = 1024, 1, 1  # Litecoin/Dogecoin's real, proven parameters


def header_fields_to_hash(index, timestamp, merkle_root, previous_hash, target, nonce):
    """Real, ASIC-resistant proof-of-work hash. Scrypt instead of plain
    SHA-256 specifically because it's memory-hard — computing it requires
    allocating and shuffling a real working buffer per attempt, which
    narrows the advantage specialized mining hardware has over a regular
    computer, the same reason Litecoin and Dogecoin both use it. The
    header itself is used as both the "password" and the "salt" — salt's
    usual purpose (defeating precomputed rainbow tables across many
    different secrets) doesn't apply to hashing one public, already-known
    message, and reusing the header keeps the hash fully deterministic
    from the header alone."""
    s = json.dumps({
        "index": index, "timestamp": timestamp, "merkle_root": merkle_root,
        "previous_hash": previous_hash, "target": target, "nonce": nonce,
    }, sort_keys=True).encode()
    return hashlib.scrypt(s, salt=s, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32).hex()
