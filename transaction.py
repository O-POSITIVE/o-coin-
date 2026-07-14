"""A signed transfer of O-Coin from one address to another.

Real cryptographic signing, same curve family Bitcoin uses (SECP256k1) —
nobody can forge a transaction moving coins out of an address they don't
hold the private key for, the same guarantee real cryptocurrencies make.
Not a simulation: is_valid() actually verifies the signature against the
sender's public key, and separately checks that public key actually
hashes to the claimed sender address, so you can't sign as yourself while
claiming to be someone else's address either.

sender == "0" is the one special case: a coinbase transaction, the
network paying a mining reward (+ collected fees) to whoever found the
block. It has no signature because nobody is spending an existing
balance — the coins are being newly created, the same way
Bitcoin/Dogecoin/every PoW chain mints new coins as the mining reward.

Fees exist for exactly one reason: to keep the network fast and cheap ON
PURPOSE, not by accident. A real chain's transactions all compete for
limited space in each block; when a miner has to choose which pending
transactions to include, a fee is what lets that choice be "highest fee
first" instead of arbitrary. MIN_FEE is set low deliberately — this is
meant to feel like Dogecoin's famously cheap, fast transactions, not
Ethereum's often-expensive gas market. See blockchain.py's difficulty
retargeting for the other half of "fast": fees is the price-per-transfer
lever, retargeting is the block-time lever.
"""
import hashlib
import json
import time

from ecdsa import SECP256k1, VerifyingKey, BadSignatureError

# A flat fee, not a percentage — percentage fees punish larger transfers
# for no real reason (the actual cost a miner incurs including one more
# transaction in a block is the same regardless of the amount being
# sent). Deliberately tiny: this whole chain exists in the spirit of
# Dogecoin's cheap, casual, "just send it" transactions.
MIN_FEE = 0.01


class Transaction:
    def __init__(self, sender, recipient, amount, fee=None, public_key=None, signature=None, timestamp=None, op=None, op_data=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.fee = fee if fee is not None else (0 if sender == "0" else MIN_FEE)
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.public_key = public_key  # hex-encoded sender public key, present on every non-coinbase tx
        self.signature = signature    # hex-encoded signature, present on every non-coinbase tx
        # Optional, default None (Track A, Phase A2) — a plain transfer
        # (op=None) must sign/hash EXACTLY as it always has, or every
        # already-broadcast signature in chain history would stop
        # verifying. op is a short op-name string ("transfer_asset", pool
        # ops, etc. — see blockchain.py); op_data is whatever dict that op
        # needs. Both ride inside the signed message (see
        # to_signing_string) specifically so nobody can intercept a
        # broadcast op transaction and rewrite its op_data before it's
        # mined without invalidating the signature, same reasoning as fee.
        self.op = op
        self.op_data = op_data

    def to_signing_string(self):
        # Deliberately excludes public_key/signature themselves — this is
        # exactly the message that got signed, and including them would be
        # circular (signing over your own signature). fee IS included —
        # it must be, or someone could intercept a broadcast transaction
        # and lower/raise its fee before it reaches a miner, without
        # invalidating the signature.
        fields = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "fee": self.fee,
            "timestamp": self.timestamp,
        }
        # op/op_data only enter the signed message when actually set — a
        # plain transfer (op=None, the only kind that existed before Phase
        # A2) produces the IDENTICAL 5-key JSON this always produced, so
        # every transaction ever signed before this field existed still
        # verifies unchanged. This is the one thing that makes the whole
        # schema extension backward-compatible rather than a silent hard
        # fork on every historical signature.
        if self.op is not None:
            fields["op"] = self.op
            fields["op_data"] = self.op_data
        return json.dumps(fields, sort_keys=True)

    def sign(self, wallet):
        """wallet is a Wallet instance (see wallet.py) — must belong to
        this transaction's sender, or the resulting signature will fail
        is_valid()'s address-matching check even though the signature
        itself is technically well-formed."""
        self.public_key = wallet.public_key_hex()
        self.signature = wallet.sign(self.to_signing_string()).hex()

    def is_valid(self):
        if self.sender == "0":
            # Coinbase is reward-only — every real one built by blockchain.py
            # (mining/pool/staking reward txs) never sets op, so this is a
            # no-op for anything legitimate; it just closes off "sender=0
            # AND carries a user-directed op" as a combination nothing
            # should ever construct.
            return self.op is None
        if self.amount <= 0:
            return False
        if self.fee < MIN_FEE:
            return False
        if not self.signature or not self.public_key:
            return False
        # The public key must actually hash to the address claiming to be
        # the sender — without this check, anyone could sign with THEIR
        # OWN real key pair while writing someone else's address in the
        # `sender` field, and the raw signature check below would still
        # pass (it's a valid signature — just not proof of authorization
        # from the claimed sender).
        pub_bytes = bytes.fromhex(self.public_key)
        if hashlib.sha256(pub_bytes).hexdigest()[:40] != self.sender:
            return False
        try:
            vk = VerifyingKey.from_string(pub_bytes, curve=SECP256k1)
            return vk.verify(bytes.fromhex(self.signature), self.to_signing_string().encode())
        except (BadSignatureError, ValueError):
            return False

    def total_cost(self):
        """What the sender's balance actually needs to cover — the
        transfer amount plus the fee they're paying the miner."""
        return self.amount + self.fee

    def hash(self):
        return hashlib.sha256(self.to_signing_string().encode()).hexdigest()

    def to_dict(self):
        return {
            "sender": self.sender, "recipient": self.recipient, "amount": self.amount,
            "fee": self.fee, "timestamp": self.timestamp,
            "public_key": self.public_key, "signature": self.signature,
            "op": self.op, "op_data": self.op_data,
        }

    @staticmethod
    def from_dict(d):
        return Transaction(
            d["sender"], d["recipient"], d["amount"], d.get("fee"),
            d.get("public_key"), d.get("signature"), d.get("timestamp"),
            d.get("op"), d.get("op_data"),
        )
