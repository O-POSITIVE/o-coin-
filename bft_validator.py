"""A BFT validator's identity — a real BLS12-381 key pair, NOT the ECDSA
(SECP256k1) keys wallet.py uses for regular transactions. Different curve
family on purpose: the whole point of choosing BLS for this layer is
SIGNATURE AGGREGATION — combine any number of validators' individual
signatures on the same message into one constant-size (96-byte) signature,
which is what lets a Quorum Certificate stay cheap to store/transmit
regardless of committee size. ECDSA signatures can't be aggregated this
way, which is exactly why this is a separate key type from Wallet's.

Uses the G2ProofOfPossession scheme specifically (py_ecc.bls) — the same
scheme Ethereum's consensus layer actually uses for validator signatures,
not a simplified stand-in. "Proof of possession" matters here for a real
reason, not just following convention: naive BLS aggregation is vulnerable
to a rogue-key attack (an attacker who's never proven they hold a matching
private key can craft a public key that cancels out other validators'
signatures in the aggregate, forging apparent agreement that never
happened). PoP closes that by requiring every validator to separately
prove, once, that they actually hold the private key behind their public
key, before that key is ever trusted in an aggregate.

Deliberately a separate, tiny module (same reasoning as wallet.py) — this
is the one piece of the BFT layer a human might want standalone (generate
a validator identity, check a public key) without pulling in the rest of
the consensus logic.
"""
from py_ecc.bls import G2ProofOfPossession as bls


class BftValidatorKey:
    def __init__(self, private_key_int=None):
        # py_ecc's BLS secret keys are plain Python ints (mod the curve
        # order) — no dedicated key object the way ecdsa's SigningKey is.
        if private_key_int is not None:
            self.private_key = private_key_int
        else:
            self.private_key = bls.KeyGen(_random_seed())
        self.public_key = bls.SkToPk(self.private_key)  # 48-byte compressed G1 point

    def public_key_hex(self):
        return self.public_key.hex()

    def private_key_hex(self):
        return hex(self.private_key)

    def sign(self, message: bytes) -> bytes:
        return bls.Sign(self.private_key, message)

    def prove_possession(self) -> bytes:
        """A PoP is just this key signing its OWN public key — proof the
        signer genuinely holds the private key, not merely a public key
        pulled from someone else's aggregate. Every validator publishes
        this once, at registration; see verify_registration below."""
        return bls.Sign(self.private_key, self.public_key)

    @staticmethod
    def verify_registration(public_key_hex: str, pop_hex: str) -> bool:
        """Checked once, when a new validator joins the committee — NOT
        on every vote (that would be redundant; PoP establishes trust in
        the public key itself, which then gets reused for every future
        aggregate verification)."""
        try:
            pk = bytes.fromhex(public_key_hex)
            pop = bytes.fromhex(pop_hex)
            return bls.Verify(pk, pk, pop)
        except (ValueError, Exception):
            return False


def _random_seed() -> bytes:
    import os
    return os.urandom(32)


if __name__ == "__main__":
    # Quick standalone use: `python bft_validator.py` prints a brand new
    # validator identity plus a proof of possession ready to hand to
    # whoever maintains the committee's public registry.
    key = BftValidatorKey()
    pop = key.prove_possession()
    print("New BFT validator identity generated.")
    print("Public key (register this):  ", key.public_key_hex())
    print("Private key (never share):   ", key.private_key_hex())
    print("Proof of possession:         ", pop.hex())
    print("Self-check — PoP verifies:   ", BftValidatorKey.verify_registration(key.public_key_hex(), pop.hex()))
