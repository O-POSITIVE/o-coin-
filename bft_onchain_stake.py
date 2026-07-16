"""Grounds BFT accountability (bft_accountability.py) in REAL O-Coin stake,
closing the "abstract integer bond" gap in SlashingRegistry with actual
on-chain numbers — Step 2 of the accountable-finality work (Step 1 was
the cross-view/ConflictingCommitEvidence rule).

SCOPE — read this before wiring this into anything live:

  READING real stake is fully real and fully general: OnChainBondedCommittee
  maps each BFT validator index to a real O-Coin address and reads its bond
  via blockchain.py's own stake_weight_of() — the EXACT weighting function
  the live PoS staking system already uses (reused, not reinvented). That
  works against ANY Blockchain instance, including, read-only, the real
  deployed chain.

  EXECUTING a slash here is a DEMONSTRATION of the mechanism, not a
  shippable feature. slash_on_chain() verifies the evidence against the BFT
  committee (never trusts an accusation alone — same rule
  bft_accountability.SlashingRegistry already holds itself to), then
  directly zeroes the culprit's balance in a Blockchain instance's
  self.balances index. That is deliberately NOT a signed Transaction —
  a Byzantine validator obviously never signs away their own stake — and
  it is NOT wired into blockchain.py's accept_block or any consensus rule.
  Shipping this for real would need a genuine new op (e.g. "bft_slash")
  with its own activation height, validated and gated exactly like every
  Track A op, reviewed and activated as its own deliberate step — not
  this one. Only ever run this against a fresh, local, in-memory
  Blockchain() built for testing (as blockchain.py's own __init__ does no
  file/network I/O) — never against node.py's real persisted chain.

Stays fully isolated the same way bft_consensus.py / bft_accountability.py
already are: this file imports FROM blockchain.py (read/write on a
LOCAL test instance) but blockchain.py and node.py import nothing from
here, and no live PoW/PoS behavior changes as a result of this file
existing.
"""

from blockchain import Blockchain
from bft_accountability import SlashingRegistry


class OnChainBondedCommittee:
    """Maps each BFT committee index to a real O-Coin address. In a live
    integration this is what BFT voting weight would eventually be
    computed from (mirroring how PoS stake weight already works) instead
    of one-validator-one-vote — not implemented here, since bft_consensus's
    Committee/QuorumCertificate are one-validator-one-vote by design and
    changing that is a separate, larger decision than this step."""

    def __init__(self, validator_addresses):
        """validator_addresses: list[str] of 40-hex O-Coin addresses, one
        per BFT committee index (index i's bond comes from
        validator_addresses[i])."""
        self.validator_addresses = list(validator_addresses)

    def bond_of(self, validator_index, blockchain: Blockchain):
        """Real, live stake weight for one validator — floored to a whole
        coin, exactly matching stake_weight_of's own semantics (see that
        method's docstring for why floats never enter a consensus-relevant
        weight)."""
        return blockchain.stake_weight_of(self.validator_addresses[validator_index])

    def all_bonds(self, blockchain: Blockchain):
        return {i: self.bond_of(i, blockchain) for i in range(len(self.validator_addresses))}


def slash_on_chain(evidence, bonded_committee: OnChainBondedCommittee, blockchain: Blockchain, bft_committee):
    """DEMONSTRATION ONLY — see module docstring's SCOPE section.

    Verifies `evidence` against `bft_committee` first (an unverified
    accusation burns nothing, same guarantee SlashingRegistry.apply
    already provides), then, for each proven culprit, zeroes that
    validator's real OCN balance directly in `blockchain.balances`.

    Returns {validator_index: amount_burned} — only entries that were
    actually nonzero and actually burned appear."""
    if not evidence.verify(bft_committee):
        return {}
    culprits = evidence.culprits() if hasattr(evidence, "culprits") else [evidence.validator_index]
    burned = {}
    for idx in culprits:
        address = bonded_committee.validator_addresses[idx]
        key = (address, "OCN")
        amount = blockchain.balances.get(key, 0)
        if amount <= 0:
            continue
        blockchain.balances[key] = 0
        burned[idx] = amount
    return burned


class OnChainSlashingRegistry(SlashingRegistry):
    """Drop-in replacement for SlashingRegistry whose bonds are REAL O-Coin
    stake (read live from `blockchain`) instead of the abstract
    `bond_per_validator` integer every validator starts with in the base
    class. `.apply()` behavior (verify-then-slash, idempotent, returns
    culprits -> amount burned) is unchanged — only where the bond number
    and the burn itself come from changes."""

    def __init__(self, committee, bonded_committee: OnChainBondedCommittee, blockchain: Blockchain):
        super().__init__(committee, bond_per_validator=0)
        self.bonded_committee = bonded_committee
        self.blockchain = blockchain
        self.bond = bonded_committee.all_bonds(blockchain)

    def apply(self, evidence) -> int:
        """Same contract as SlashingRegistry.apply (verify-then-slash,
        idempotent per validator, returns the total amount burned) — the
        only difference is the burn is a real balance zeroed on
        `self.blockchain` rather than an abstract integer bond."""
        if not evidence.verify(self.committee):
            return 0
        culprits = evidence.culprits() if hasattr(evidence, "culprits") else [evidence.validator_index]
        already_slashed = set(self.slashed)
        burned_by_index = slash_on_chain(evidence, self.bonded_committee, self.blockchain, self.committee)
        total = 0
        for idx, amount in burned_by_index.items():
            if idx in already_slashed:
                continue
            self.slashed.add(idx)
            self.bond[idx] = 0
            total += amount
        return total
