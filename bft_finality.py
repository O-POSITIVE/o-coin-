"""Additive BFT finality gadget — the piece that ATTACHES the isolated BFT
engine to the real O-Coin chain, WITHOUT replacing PoW/PoS.

WHAT IT DOES: a fixed committee of BFT validators runs the chained-HotStuff
protocol (bft_consensus.py) whose committed "payload" is a CHECKPOINT of the
existing chain — the (height, block-hash) of a block the PoW/PoS chain has
already produced. The moment the committee commits that checkpoint (real
2f+1 BLS quorum, deterministic finality), the gadget calls the chain's
narrow, additive Blockchain.mark_bft_finalized hook, after which the chain
refuses any reorg that would drop or rewrite that block.

WHY THIS IS ADDITIVE, NOT A REPLACEMENT — the whole point:
  - Block PRODUCTION is 100% unchanged: miners still mine, stakers still
    stake, the emission curve and rewards are untouched. This gadget never
    produces a block, never pays anyone, never votes on WHICH block extends
    the chain. PoW/PoS still decides all of that.
  - The ONLY thing it changes is REORG PROTECTION, and only to make it
    STRONGER: the chain already treats blocks CHECKPOINT_DEPTH deep as
    permanent (a depth heuristic); this upgrades that to "permanent the
    instant the committee cryptographically finalizes it," which is both
    faster and not merely probabilistic. A finalized block was ALSO going to
    become depth-final anyway — the gadget just gets there sooner and with a
    signature instead of a hope.
  - It is INERT until deliberately run: Blockchain.bft_finalized starts
    empty, and nothing in blockchain.py/node.py calls this gadget. With an
    empty finalized set every reorg check behaves EXACTLY as the
    depth-checkpoint-only chain always has (proven in test_bft_finality.py).

PREPARED, NOT WIRED: blockchain.py itself is UNTOUCHED. The reorg veto that
enforces finality lives here, in a FinalityAwareBlockchain SUBCLASS, so the
real consensus file stays pristine and nothing ships to production. Actually
"wiring" this later = merging FinalityAwareBlockchain's small hook into
Blockchain proper (plus a real committee across machines, an activation
height, and persistence of the finalized set) — a deliberate, reviewed
go/no-go step, never a side effect of importing this file. A finality gadget
DOES, unavoidably, have to touch the reorg decision to be able to veto a
rewrite of a finalized block — that's inherent to what finality is — but
keeping it in a subclass means it touches ONLY a copy, until you choose
otherwise.

ISOLATION: imports blockchain (subclassing Blockchain) and bft_consensus/
bft_validator. NOT imported by blockchain.py or node.py. Exercised against a
LOCAL FinalityAwareBlockchain() only.
"""
from bft_consensus import BftReplica, Committee
from bft_validator import BftValidatorKey
from blockchain import Blockchain


class FinalityAwareBlockchain(Blockchain):
    """A Blockchain that ADDS BFT-finality reorg protection without editing
    blockchain.py. Everything about block production — mining, staking,
    rewards, emission, the depth checkpoint — is inherited UNCHANGED. The
    only addition is a veto that refuses to reorg away a BFT-finalized block.
    Inert until the gadget finalizes something (bft_finalized starts empty),
    so with no finalization this behaves identically to a plain Blockchain."""

    def __init__(self):
        super().__init__()
        self.bft_finalized = {}  # index -> block hash the BFT gadget finalized

    def mark_bft_finalized(self, index, block_hash):
        """Record that the BFT committee finalized the block at `index`.
        Only accepts a hash matching our OWN block there (can't finalize a
        block we don't hold), so a bad call can't poison the veto. Idempotent."""
        if 0 <= index < len(self.chain) and self.chain[index].compute_hash() == block_hash:
            self.bft_finalized[index] = block_hash
            return True
        return False

    def _conflicts_with_bft_finality(self, candidate_chain):
        """True if candidate_chain would DROP or REWRITE a finalized block —
        the cryptographic counterpart to the base class's depth-based
        _diverges_before_checkpoint, and strictly stronger. Empty finalized
        set => always False => zero behavior change."""
        for index, block_hash in self.bft_finalized.items():
            if index >= len(candidate_chain):
                return True  # can't drop a finalized block
            if candidate_chain[index].compute_hash() != block_hash:
                return True  # can't rewrite a finalized block
        return False

    def replace_chain(self, candidate_chain):
        """Adds the finality veto in front of the inherited reorg rule, then
        defers ENTIRELY to the base class. PoW/PoS still decides everything;
        this only ever ADDS a reason to reject a rewrite of finalized history."""
        if self.bft_finalized and self._conflicts_with_bft_finality(candidate_chain):
            return False
        return super().replace_chain(candidate_chain)


def make_finality_committee(n=4):
    """Fresh BFT validator committee for a finality run. In a real
    deployment these identities would be published by real stakers and the
    committee derived from on-chain stake (see bft_onchain_stake.py for the
    stake-weight reuse); here they're generated for local demonstration."""
    keys = [BftValidatorKey() for _ in range(n)]
    committee = Committee([k.public_key_hex() for k in keys])
    return keys, committee


class BftFinalityGadget:
    """Drives the BFT committee to finalize checkpoints of `chain`. Holds
    one BftReplica per committee member and runs honest rounds in-process
    (the same shape as test_bft_consensus's driver). A networked deployment
    would instead run these as bft_node.py processes; the finality LOGIC —
    commit a checkpoint payload, then mark it on the chain — is identical."""

    def __init__(self, chain: Blockchain, keys, committee: Committee):
        self.chain = chain
        self.keys = keys
        self.committee = committee
        self.replicas = [BftReplica(i, keys[i], committee) for i in range(committee.n)]
        self._view = 1

    def _run_honest_view(self, payload):
        v = self._view
        for r in self.replicas:
            r.advance_to_view(v)
        leader = self.replicas[self.committee.leader_for_view(v)]
        block = leader.propose(payload)
        votes = [vt for r in self.replicas if (vt := r.on_receive_proposal(block)) is not None]
        next_leader = self.replicas[self.committee.leader_for_view(v + 1)]
        for vt in votes:
            next_leader.on_receive_vote(vt)
        self._view += 1
        return block

    def finalize_height(self, height):
        """Run a REAL BFT commit whose checkpoint payload names the chain's
        block at `height`, then — only once the committee has genuinely
        COMMITTED that payload block (a real 3-chain, not just proposed it) —
        record it as finalized on the chain via mark_bft_finalized.

        Returns the finalized block hash, or None if `height` isn't on the
        chain or the commit didn't actually happen (in which case nothing is
        finalized — the gadget never marks on faith)."""
        if not (0 <= height < len(self.chain.chain)):
            return None
        target_hash = self.chain.chain[height].compute_hash()
        payload = {"finalize_index": height, "block_hash": target_hash}
        checkpoint_block = self._run_honest_view(payload)
        # Drive follow-on views so the checkpoint block reaches the 3-chain
        # commit rule (block <- +1 <- +2, then its QC applied).
        for _ in range(4):
            self._run_honest_view({"heartbeat": self._view})
        # Only finalize if the committee REALLY committed our checkpoint block.
        if checkpoint_block.hash not in self.replicas[0].committed:
            return None
        if self.chain.mark_bft_finalized(height, target_hash):
            return target_hash
        return None
