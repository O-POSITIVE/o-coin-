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

ATTACHED BUT DORMANT: the reorg veto now lives in Blockchain proper
(blockchain.py: mark_bft_finalized / _conflicts_with_bft_finality / the
replace_chain check), so the attachment is real and wired. It is INERT
because nothing runs a committee against the live chain yet — Blockchain
.bft_finalized stays empty until this gadget is deliberately pointed at the
production chain with a chosen committee. Turning it ON = choosing a real
cross-machine committee (ideally >=4 validators) and running this gadget's
finalize loop against the live node; that activation step is intentionally
NOT wired into node.py.

A finality gadget UNAVOIDABLY has to touch the reorg decision to veto a
rewrite of a finalized block — that's inherent to what finality is — but the
touch is minimal, additive, and dormant-by-default (empty finalized set =>
identical behavior to before).

ISOLATION: imports blockchain (uses the now-built hook) and bft_consensus/
bft_validator. NOT imported by blockchain.py or node.py.
"""
from bft_consensus import BftReplica, Committee
from bft_validator import BftValidatorKey
from blockchain import Blockchain


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
