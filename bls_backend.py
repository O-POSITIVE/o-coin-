"""Pluggable BLS12-381 backend for the BFT layer — same proof-of-possession
scheme either way, but backed by a fast native library when one is
installed, falling back to pure-Python py_ecc otherwise.

WHY THIS EXISTS: py_ecc's BLS is a readable REFERENCE implementation in
pure Python — correct, but ~180 ms per signature verification on this
machine. Consensus verifies many signatures per round (every validator
checks every vote), so at that speed the crypto, not the network, is the
bottleneck; broadcasting votes (bft_node.py) makes it O(n^2) verifications
per view and the cost compounds. `milagro_bls_binding` is the Rust BLS
binding the Ethereum consensus ecosystem uses — the IDENTICAL IETF BLS
signature standard with the proof-of-possession (POP) ciphersuite py_ecc's
G2ProofOfPossession also implements — and it verifies in ~2.4 ms (~70x
faster) and signs in ~0.7 ms (~85x faster). Same math, same wire format,
vastly less time.

This module presents a py_ecc-G2ProofOfPossession-COMPATIBLE surface
(KeyGen/SkToPk/Sign/Verify/Aggregate/FastAggregateVerify) so the rest of
the BFT code (bft_validator, bft_consensus, bft_accountability, and the
tests) imports it as a drop-in `bls` with no call-site changes beyond the
import line. Secret keys stay plain ints externally (as py_ecc uses), so
BftValidatorKey.private_key / private_key_hex are unchanged; only this
module converts an int to the 32-byte big-endian form the native binding
wants, internally.

CONSISTENCY, not cross-interop, is what matters: every sign and every
verify in a single run must route through THIS module so they all use the
same backend. As long as they do, a run is internally consistent whichever
backend is active. (The two are also standard-compatible with each other,
but the code never relies on mixing them.)
"""
# py_ecc is always importable (pure Python, no build step) and provides a
# standards-compliant KeyGen that yields an in-range int secret key — used
# for key generation in BOTH modes, since the native binding has no KeyGen
# and rejects out-of-range secret-key bytes.
from py_ecc.bls import G2ProofOfPossession as _slow

try:
    import milagro_bls_binding as _fast
    BACKEND = "milagro"
except ImportError:  # native wheel not available (e.g. an unsupported Python) — stay correct, just slow
    _fast = None
    BACKEND = "py_ecc"


def KeyGen(seed: bytes) -> int:
    """Standards-compliant BLS KeyGen -> int secret key. Always via py_ecc
    (deterministic, in-range, valid for either backend)."""
    return _slow.KeyGen(seed)


def _sk_bytes(sk_int: int) -> bytes:
    return int(sk_int).to_bytes(32, "big")


if BACKEND == "milagro":
    def SkToPk(sk_int) -> bytes:
        return _fast.SkToPk(_sk_bytes(sk_int))

    def Sign(sk_int, message: bytes) -> bytes:
        return _fast.Sign(_sk_bytes(sk_int), message)

    def Verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
        # Match py_ecc semantics: never raise on a bad/malformed signature,
        # return False. Several call sites (e.g. on_receive_vote) rely on a
        # bool, not an exception, for a forged or wrong-length signature.
        try:
            return bool(_fast.Verify(pubkey, message, signature))
        except Exception:
            return False

    def Aggregate(signatures) -> bytes:
        return _fast.Aggregate(list(signatures))

    def FastAggregateVerify(pubkeys, message: bytes, signature: bytes) -> bool:
        try:
            return bool(_fast.FastAggregateVerify(list(pubkeys), message, signature))
        except Exception:
            return False

else:  # pure-Python fallback — identical interface, just slow
    def SkToPk(sk_int) -> bytes:
        return _slow.SkToPk(sk_int)

    def Sign(sk_int, message: bytes) -> bytes:
        return _slow.Sign(sk_int, message)

    def Verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return bool(_slow.Verify(pubkey, message, signature))
        except Exception:
            return False

    def Aggregate(signatures) -> bytes:
        return _slow.Aggregate(list(signatures))

    def FastAggregateVerify(pubkeys, message: bytes, signature: bytes) -> bool:
        try:
            return bool(_slow.FastAggregateVerify(list(pubkeys), message, signature))
        except Exception:
            return False


if __name__ == "__main__":
    import os, time
    sk = KeyGen(os.urandom(32))
    pk = SkToPk(sk)
    sig = Sign(sk, b"backend self-check")
    print(f"backend = {BACKEND}")
    print("pubkey bytes:", len(pk), " signature bytes:", len(sig))
    print("verify (correct):", Verify(pk, b"backend self-check", sig))
    print("verify (wrong msg):", Verify(pk, b"tampered", sig))
    t = time.time(); n = 200
    for _ in range(n):
        Verify(pk, b"backend self-check", sig)
    print(f"verify: {(time.time()-t)/n*1000:.3f} ms each")