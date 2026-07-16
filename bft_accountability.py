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

SCOPE (stated honestly, no overclaiming on consensus code): this covers
EQUIVOCATION-based accountability — one validator signing two different
blocks at the same view. That's the clean, unambiguous, foundational
offense and the direct cause of same-view conflicting finalization. The
FULL accountable-safety theorem for chained HotStuff also has to handle
cross-view "surround"-style violations (a validator voting in a way that
conflicts with its own earlier lock across views); that second rule is
real, well-defined, and a documented next step — NOT claimed as done here.
The tests demonstrate the equivocation guarantee empirically, the same
prove-it-adversarially standard the rest of this layer holds itself to.

Isolated exactly like bft_consensus.py: imports only from the BFT layer,
nothing from blockchain.py/node.py, and nothing there imports this.
"""
from py_ecc.bls import G2ProofOfPossession as bls

from bft_consensus import Vote, Committee, _vote_message


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

    def apply(self, evidence: EquivocationEvidence) -> int:
        """Verify the evidence independently, then slash. Returns the amount
        burned (0 if the evidence didn't verify or the validator was already
        slashed). Idempotent per validator — the same offender can't be
        double-burned by re-submitting evidence."""
        if not evidence.verify(self.committee):
            return 0
        v = evidence.validator_index
        if v in self.slashed:
            return 0
        burned = self.bond.get(v, 0)
        self.bond[v] = 0
        self.slashed.add(v)
        return burned

    def total_slashed(self):
        return len(self.slashed)
