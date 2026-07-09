"""An O-Coin wallet — a real SECP256k1 key pair (the same curve Bitcoin
uses), with an address derived from the public key the same way real
chains do it: hash the public key, use the hash as the address. Whoever
holds the private key is the only one who can ever sign a valid spend
from that address — nobody else, including the node software itself, can
move coins out of a wallet they don't hold the key for.

Deliberately a separate, tiny, dependency-light module — this is the one
piece of the whole chain a human might actually want to use standalone
(generate a wallet, check an address, sign something) without pulling in
Flask or the rest of the node.
"""
import hashlib

from ecdsa import SECP256k1, SigningKey


class Wallet:
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            self.private_key = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        else:
            self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def private_key_hex(self):
        return self.private_key.to_string().hex()

    def public_key_hex(self):
        return self.public_key.to_string().hex()

    @property
    def address(self):
        # Truncated to 40 hex chars (160 bits) purely for a shorter,
        # friendlier-looking address — same idea as Bitcoin/Ethereum
        # hashing a public key down to a shorter address rather than
        # using the raw (much longer) public key as the address itself.
        return hashlib.sha256(self.public_key.to_string()).hexdigest()[:40]

    def sign(self, message: str) -> bytes:
        return self.private_key.sign(message.encode())

    @staticmethod
    def address_from_public_key_hex(public_key_hex: str) -> str:
        return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:40]


if __name__ == "__main__":
    # Quick standalone use: `python wallet.py` prints a brand new wallet.
    w = Wallet()
    print("New O-Coin wallet generated.")
    print("Address:      ", w.address)
    print("Private key:  ", w.private_key_hex(), "  (never share this)")
    print("Public key:   ", w.public_key_hex())
