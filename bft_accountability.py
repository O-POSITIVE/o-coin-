"""Accountable finality for the BFT layer — the part that turns "safe" into
"safe AND the culprits are catchable."

Background: bft_consensus.py already gives SAFETY — with at most f Byzantine
validators (of n=3f+1), two conflicting blocks can never both finalize,
because the honest replicas' equivocation guard (voted_views) refuses to
sign a second conflicting vote in a view. But safety alone says nothing
about what happens if MORE than f validators are Byzantine: in that regime
the protocol's safety guarantee is void, two conflicting blocks CAN be
finalized, and — without accountability — you'd have no way to know WHO did
it or to punish them. A committee that can betray you with impunity isn't
much of a security model.

ACCOUNTABLE SAFETY (the Casper-FFG idea, adapted to this HotStuff layer)
closes that: it's the theorem that any safety violation is not just
detectable but ATTRIBUTABLE — you can point at >= f+1 specific validators
and hold, in hand, cryptographic proof they broke a rule. Here's the
overlap argument that makes it true for the equivocation offense:

  Two conflicting blocks finalizing at the same view V requires two
  Quorum Certificates for different blocks at V. Each QC needs >= 2f+1
  signers. Two sets of 2f+1 out of n=3f+1 must overlap in at least
  (2f+1)+(2f+1) - (3f+1) = f+1 validators. Every validator in that
  overlap signed BOTH conflicting votes at view V — i.e. equivocated —
  and their two signatures ARE the proof. So a safety break leaves at
  least f+1 validators provably guilty. That is the whole point.

This module builds: the verifiable EVIDENCE of an offense, a MONITOR that
extracts it from the vote stream, and a SLASHING registry that burns a
proven offender's stake. Everything is independently checkable against the
committee's public keys — a slashing never rests on trusting the accuser,
only on the accused's own signatures.

SCOPE (stated honestly, no overclaiming on consensus code): this file
builds TWO accountability rules, covering the two distinct ways a same-view
OR cross-view safety break can happen:

1. EQUIVOCATION (EquivocationEvidence, below) — one validator signs two
   different blocks at the SAME view. The clean, foundational, same-view
   offense.

2. CONFLICTING COMMITS (ConflictingCommitEvidence, further below) — a
   validator contributes to TWO separately-COMMITTED (real 3-chain, per
   the exact rule bft_consensus.py's _try_advance_lock_and_commit
   implements) but mutually conflicting histories, at possibly DIFFERENT
   views, without ever equivocating at any single view. This is the
   cross-view generalization.

A note on why #2 takes the shape it does, not a direct port of Casper
FFG's "surround vote" rule: FFG's rule works because votes explicitly carry
a signed (source, target) checkpoint pair, and an honest client's source
only ever advances when a NEW checkpoint becomes justified by public
evidence. Porting that literally here would mean adding a signed
"source view" field to bft_consensus.py's Vote message — a change to
already-tested, load-bearing core protocol code, not something to do
casually. Working through it carefully (see the reasoning that led here):
that literal port also turns out to be UNSOUND for this specific protocol
as a same-validator-nested-votes check, because bft_consensus.py's OWN
"liveness escape hatch" (_safe_to_vote's qc_is_newer branch) deliberately
lets an honest replica abandon a merely-LOCKED-but-not-yet-COMMITTED block
in favor of a legitimately newer QC — completely normal view-change
behavior, which a naive nested-vote check would misflag as an offense.
The fix is to only treat conflicting contributions as guilty when the
OLDER side was actually COMMITTED (fully 3-chained), which is exactly the
property the protocol's own safety guarantee protects — hence
ConflictingCommitEvidence requires a full, independently-checkable
3-chain witness on each side, not a bare vote pair. This needs NO change
to bft_consensus.py at all — it works entirely from public QCs and blocks
that already exist.

Isolated exactly like bft_consensus.py: imports only from the BFT layer,
nothing from blockchain.py/node.py, and nothing there imports this.
"""
from py_ecc.bls import G2ProofOfPossession as bls

from bft_consensus import Vote, Committee, BftBlock, QuorumCertificate, GENESIS_BLOCK_HASH, _vote_message


class EquivocationEvidence:
    """Irrefutable proof that ONE validator signed two DIFFERENT blocks at
    the SAME view. The two signed votes are the entire proof — anyone can
    verify it against the committee's public keys, with zero trust in
    whoever produced the evidence. This is the object a real deployment
    would gossip to every node and record on-chain to justify a slash."""

    def __init__(self, validator_index: int, view: int, vote_a: Vote, vote_b: Vote):
        self.validator_index = validator_index
        self.view = view
        self.vote_a = vote_a
        self.vote_b = vote_b

    def verify(self, committee: Committee) -> bool:
        """True only if this is a genuine, self-consistent equivocation:
        both votes are from the SAME validator at the SAME view, for
        DIFFERENT blocks, and BOTH signatures really verify against that
        validator's public key. Any of those failing => not valid evidence,
        and crucially => an honest validator (who signs at most one block
        per view) can never have valid evidence built against them."""
        a, b = self.vote_a, self.vote_b
        # Structural self-consistency: the evidence must actually describe
        # one validator equivocating in one view over two distinct blocks.
        if not (a.voter_index == b.voter_index == self.validator_index):
            return False
        if not (a.view == b.view == self.view):
            return False
        if a.block_hash == b.block_hash:
            return False  # same block twice is not a conflict — voting once, re-sent, is legal
        # The load-bearing part: both must be REAL signatures by the accused.
        # Forging either would require the accused's private key, which is
        # exactly why an honest validator can't be framed.
        try:
            pk = bytes.fromhex(committee.pubkeys[self.validator_index])
            sig_a = bytes.fromhex(a.signature_hex)
            sig_b = bytes.fromhex(b.signature_hex)
        except (IndexError, ValueError, TypeError):
            return False
        try:
            ok_a = bls.Verify(pk, _vote_message(a.block_hash, a.view), sig_a)
            ok_b = bls.Verify(pk, _vote_message(b.block_hash, b.view), sig_b)
        except Exception:
            return False
        return ok_a and ok_b

    def to_dict(self):
        return {
            "validator_index": self.validator_index, "view": self.view,
            "vote_a": self.vote_a.to_dict(), "vote_b": self.vote_b.to_dict(),
        }

    @staticmethod
    def from_dict(d):
        return EquivocationEvidence(
            d["validator_index"], d["view"],
            Vote.from_dict(d["vote_a"]), Vote.from_dict(d["vote_b"]),
        )


class ThreeChainWitness:
    """Independently-checkable proof that block0 was COMMITTED, by
    reproducing — from public data alone — the EXACT structural conditions
    bft_consensus.py's _try_advance_lock_and_commit checks internally
    (block0 <- block1(justify=QC(block0)) <- block2(justify=QC(block1)) <-
    a QC that justifies block2 at consecutive views). Anyone holding the
    three blocks and three QCs can verify this themselves; nothing here
    trusts that any replica's internal state was computed honestly."""

    def __init__(self, qc0: QuorumCertificate, block0: BftBlock,
                 qc1: QuorumCertificate, block1: BftBlock,
                 qc2: QuorumCertificate, block2: BftBlock):
        self.qc0, self.block0 = qc0, block0
        self.qc1, self.block1 = qc1, block1
        self.qc2, self.block2 = qc2, block2

    def verify(self, committee: Committee) -> bool:
        # Each QC must be a real, valid quorum certificate...
        if not (self.qc0.verify(committee) and self.qc1.verify(committee) and self.qc2.verify(committee)):
            return False
        # ...each certifying exactly the block it's paired with...
        if not (self.qc0.block_hash == self.block0.hash and self.qc0.view == self.block0.view):
            return False
        if not (self.qc1.block_hash == self.block1.hash and self.qc1.view == self.block1.view):
            return False
        if not (self.qc2.block_hash == self.block2.hash and self.qc2.view == self.block2.view):
            return False
        # ...block1 genuinely extends block0, justified by qc0 specifically...
        if self.block1.parent_hash != self.block0.hash:
            return False
        j0 = QuorumCertificate.from_dict(self.block1.justify) if self.block1.justify else None
        if j0 is None or j0.block_hash != self.block0.hash or j0.view != self.block0.view:
            return False
        # ...block2 genuinely extends block1, justified by qc1 specifically...
        if self.block2.parent_hash != self.block1.hash:
            return False
        j1 = QuorumCertificate.from_dict(self.block2.justify) if self.block2.justify else None
        if j1 is None or j1.block_hash != self.block1.hash or j1.view != self.block1.view:
            return False
        # ...and the views run with NO gaps — a stalled/skipped view anywhere
        # in the chain means this specific 3-chain never actually completed,
        # exactly matching the real commit rule's "consecutive" check.
        if not (self.block1.view == self.block0.view + 1 and self.block2.view == self.block1.view + 1):
            return False
        return True

    def to_dict(self):
        return {
            "qc0": self.qc0.to_dict(), "block0": self.block0.to_dict(),
            "qc1": self.qc1.to_dict(), "block1": self.block1.to_dict(),
            "qc2": self.qc2.to_dict(), "block2": self.block2.to_dict(),
        }

    @staticmethod
    def from_dict(d):
        return ThreeChainWitness(
            QuorumCertificate.from_dict(d["qc0"]), BftBlock.from_dict(d["block0"]),
            QuorumCertificate.from_dict(d["qc1"]), BftBlock.from_dict(d["block1"]),
            QuorumCertificate.from_dict(d["qc2"]), BftBlock.from_dict(d["block2"]),
        )


def _valid_chain_from_genesis(chain, tip_hash):
    """chain: list[BftBlock], claimed genesis-to-tip. True only if it's a
    genuine, unbroken, hash-linked chain starting at the real genesis block
    and ending at tip_hash — used to independently confirm two committed
    blocks are NOT on the same branch (one an ancestor of the other, which
    would just be normal chain progress, not a conflict)."""
    if not chain or chain[0].hash != GENESIS_BLOCK_HASH:
        return False
    for i in range(1, len(chain)):
        if chain[i].parent_hash != chain[i - 1].hash:
            return False
    return chain[-1].hash == tip_hash


class ConflictingCommitEvidence:
    """Proof that TWO DIFFERENT blocks were each genuinely COMMITTED (each
    backed by its own valid ThreeChainWitness) despite being on mutually
    conflicting branches — the actual catastrophic safety failure chained
    HotStuff exists to prevent. Requires each side's full chain (genesis to
    committed tip) so the "conflicting, not just later" check is itself
    independently verifiable rather than merely asserted.

    The overlap guarantee: qc0_a and qc0_b are each real quorum certificates
    (>=2f+1 signers) drawn from the SAME n=3f+1 committee, so by simple
    pigeonhole they share >= (2f+1)+(2f+1)-(3f+1) = f+1 signer indices —
    every one of whom contributed to BOTH conflicting commits. culprits()
    returns exactly that overlap."""

    def __init__(self, witness_a: ThreeChainWitness, chain_a, witness_b: ThreeChainWitness, chain_b):
        self.witness_a = witness_a
        self.chain_a = chain_a  # list[BftBlock], genesis -> witness_a.block0
        self.witness_b = witness_b
        self.chain_b = chain_b  # list[BftBlock], genesis -> witness_b.block0

    def verify(self, committee: Committee) -> bool:
        if not (self.witness_a.verify(committee) and self.witness_b.verify(committee)):
            return False
        b0_a, b0_b = self.witness_a.block0, self.witness_b.block0
        if b0_a.hash == b0_b.hash:
            return False  # same committed block — not a conflict
        if not _valid_chain_from_genesis(self.chain_a, b0_a.hash):
            return False
        if not _valid_chain_from_genesis(self.chain_b, b0_b.hash):
            return False
        hashes_a = {b.hash for b in self.chain_a}
        hashes_b = {b.hash for b in self.chain_b}
        # If either committed block is an ancestor of the other, that's just
        # normal chain growth (b later legitimately extends a), NOT a
        # conflict — reject rather than falsely accuse.
        if b0_a.hash in hashes_b or b0_b.hash in hashes_a:
            return False
        return True

    def culprits(self):
        """Validator indices proven to have contributed to BOTH conflicting
        committed histories — the >= f+1 overlap the theorem guarantees.
        Meaningless (and not to be trusted) unless verify() is True first."""
        return sorted(set(self.witness_a.qc0.signer_indices) & set(self.witness_b.qc0.signer_indices))


class AccountabilityMonitor:
    """Watches every vote the network produces (any node can run one — it
    needs nothing secret, only the public committee). The moment it sees a
    validator vote for a second, different block in a view it already voted
    in, it emits verifiable EquivocationEvidence. This is the mechanism
    that makes finality ACCOUNTABLE rather than merely safe: under a
    safety-breaking >f Byzantine committee, the f+1 overlap validators each
    produce exactly this pattern, so each is caught here."""

    def __init__(self, committee: Committee):
        self.committee = committee
        # (voter_index, view) -> the FIRST vote seen from that voter in that
        # view. A second vote for a different block against this entry is an
        # equivocation.
        self._first_vote = {}
        # validator_index -> its evidence (one is enough to slash; we keep
        # the first proven instance per validator and don't pile on).
        self.evidence = {}

    def observe(self, vote: Vote):
        """Feed every vote seen on the wire through here. Returns fresh
        EquivocationEvidence the first time a given validator is caught,
        else None. Verifies the incoming vote's own signature before
        trusting it — a garbage/forged 'vote' must not be able to frame
        the validator it names (same all-or-nothing reasoning as
        on_receive_vote in bft_consensus)."""
        try:
            pk = bytes.fromhex(self.committee.pubkeys[vote.voter_index])
            sig = bytes.fromhex(vote.signature_hex)
        except (IndexError, ValueError):
            return None
        try:
            if not bls.Verify(pk, _vote_message(vote.block_hash, vote.view), sig):
                return None  # not a real vote by that validator — ignore, can't frame anyone
        except Exception:
            return None

        key = (vote.voter_index, vote.view)
        prior = self._first_vote.get(key)
        if prior is None:
            self._first_vote[key] = vote
            return None
        if prior.block_hash == vote.block_hash:
            return None  # same vote again (re-broadcast) — not an offense

        # Two verified, different-block votes from one validator in one view.
        if vote.voter_index in self.evidence:
            return None  # already caught this one; don't emit duplicates
        ev = EquivocationEvidence(vote.voter_index, vote.view, prior, vote)
        self.evidence[vote.voter_index] = ev
        return ev

    def submit_conflicting_commits(self, evidence: "ConflictingCommitEvidence"):
        """Unlike equivocation (streamed vote-by-vote, since a single pair
        of votes is enough), a conflicting-commit is checked when SUBMITTED
        as a complete witness — reconstructing two full 3-chains from a live
        vote stream is a heavier, application-specific job (a real
        deployment would have replicas self-report their own committed
        3-chains, or a watcher reconstruct them from block gossip) that
        doesn't belong inside a simple per-vote observer. Returns the list
        of newly-recorded culprit indices (empty if the evidence doesn't
        verify or every named culprit was already caught)."""
        if not evidence.verify(self.committee):
            return []
        fresh = []
        for idx in evidence.culprits():
            if idx not in self.evidence:
                self.evidence[idx] = evidence
                fresh.append(idx)
        return fresh

    def all_evidence(self):
        return list(self.evidence.values())


class SlashingRegistry:
    """Tracks each validator's staked bond and burns it on proven
    misbehavior. In this isolated layer 'stake' is just an integer bond and
    'slashing' zeroes it + flags the validator; a real deployment would tie
    these to actual on-chain O-Coin stake (the same balance-weighted stake
    the live PoS chain already tracks) and eject the validator from the
    committee. A slash NEVER happens on an accusation alone — evidence must
    verify against the committee first, so a buggy or malicious monitor
    cannot cause an unjust slash."""

    def __init__(self, committee: Committee, bond_per_validator: int = 1000):
        self.committee = committee
        self.bond = {i: bond_per_validator for i in range(committee.n)}
        self.slashed = set()

    def apply(self, evidence) -> int:
        """Verify the evidence independently, then slash EVERY validator it
        names (one for EquivocationEvidence; possibly several — the >=f+1
        overlap — for ConflictingCommitEvidence). Returns the total amount
        burned (0 if the evidence didn't verify or every named validator was
        already slashed). Idempotent per validator — the same offender can't
        be double-burned by re-submitting evidence, whether the same or a
        different piece of evidence names them again."""
        if not evidence.verify(self.committee):
            return 0
        culprits = evidence.culprits() if hasattr(evidence, "culprits") else [evidence.validator_index]
        burned = 0
        for v in culprits:
            if v in self.slashed:
                continue
            burned += self.bond.get(v, 0)
            self.bond[v] = 0
            self.slashed.add(v)
        return burned

    def total_slashed(self):
        return len(self.slashed)
