"""Tests for the additive BFT finality gadget (bft_finality.py) and its
inert-by-default reorg veto, now ATTACHED in Blockchain proper (dormant
until a committee finalizes something). Proves the claims that matter for
the 'additive, not a replacement' decision:

  1. INERT BY DEFAULT — with no finalization, every reorg check behaves
     byte-for-byte as the depth-checkpoint-only chain always has.
  2. REAL commit — the gadget only finalizes a checkpoint the BFT committee
     genuinely COMMITTED, and only a hash the chain actually holds.
  3. STRICTLY STRONGER — once a block is BFT-finalized, a reorg that would
     rewrite it is rejected EVEN WHEN the depth checkpoint alone would have
     allowed it. That's the whole added value, and it's additive: block
     production/rewards are never touched.

Uses a real local Blockchain() with real scrypt-PoW-mined blocks.
"""
import copy

from blockchain import Blockchain
from bft_finality import BftFinalityGadget, make_finality_committee


def mined_chain(n_blocks, miner="f" * 40):
    chain = Blockchain()
    for _ in range(n_blocks):
        chain.mine_block(miner)
    return chain


print("=== Scenario 1: INERT BY DEFAULT — no finalization changes nothing ===")
chain = mined_chain(5)
assert chain.bft_finalized == {}, "a fresh chain must have an empty finalized set"
# A candidate that rewrites a recent block: longer, and diverges at index 3.
candidate = list(chain.chain) + [chain.chain[-1]]  # longer by one (content irrelevant here)
candidate[3] = copy.deepcopy(candidate[3])
candidate[3].nonce += 1  # different hash at index 3
assert chain._conflicts_with_bft_finality(candidate) is False, \
    "with an empty finalized set, the BFT reorg veto must NEVER fire (fully inert)"
# And the depth checkpoint doesn't catch this divergence either (short chain,
# checkpoint boundary is at genesis) — so today's chain would let it through.
assert chain._diverges_before_checkpoint(candidate) is False, \
    "sanity: at this length the depth checkpoint does NOT protect block 3"
print("  OK — empty finalized set is completely inert; reorg logic identical to before")


print("\n=== Scenario 2: REAL commit finalizes the correct hash, rejects bad marks ===")
chain = mined_chain(5)
keys, committee = make_finality_committee(n=4)
gadget = BftFinalityGadget(chain, keys, committee)
target = chain.chain[3].compute_hash()
finalized = gadget.finalize_height(3)
print(f"  gadget.finalize_height(3) -> {finalized[:12] if finalized else None}...")
assert finalized == target, "the gadget must finalize exactly the chain's block-3 hash, via a real BFT commit"
assert chain.bft_finalized == {3: target}, "the chain must record exactly that finalized checkpoint"
# mark_bft_finalized must refuse a hash we don't hold, and an out-of-range index.
assert chain.mark_bft_finalized(3, "de" * 32) is False, "must refuse to finalize a hash we don't hold at that index"
assert chain.mark_bft_finalized(999, target) is False, "must refuse an out-of-range index"
assert chain.bft_finalized == {3: target}, "rejected marks must not alter the finalized set"
print("  OK — real BFT commit finalized block 3; bogus marks refused")


print("\n=== Scenario 3: STRICTLY STRONGER — finality blocks a reorg the depth check allows ===")
# Same short chain: the depth checkpoint boundary is at genesis, so a reorg
# rewriting block 3 is NOT caught by _diverges_before_checkpoint. Once block
# 3 is BFT-finalized, the finality veto DOES catch it — new protection.
chain = mined_chain(5)
keys, committee = make_finality_committee(n=4)
gadget = BftFinalityGadget(chain, keys, committee)
gadget.finalize_height(3)

attacker = list(chain.chain) + [chain.chain[-1]]  # longer chain
attacker[3] = copy.deepcopy(attacker[3])
attacker[3].nonce += 7  # rewrites the finalized block 3
assert chain._diverges_before_checkpoint(attacker) is False, \
    "the depth checkpoint alone does NOT protect block 3 at this chain length"
assert chain._conflicts_with_bft_finality(attacker) is True, \
    "BFT finality MUST reject a reorg that rewrites the finalized block 3"
# Isolate that it's specifically finality doing the work: clear it and the
# veto stops firing (proving the added protection is exactly the gadget's).
saved = dict(chain.bft_finalized)
chain.bft_finalized = {}
assert chain._conflicts_with_bft_finality(attacker) is False, "cleared finality => veto no longer fires"
chain.bft_finalized = saved
# A candidate that DDROPS the finalized block (too short to include it) is also vetoed.
too_short = list(chain.chain[:3])  # doesn't even reach index 3
assert chain._conflicts_with_bft_finality(too_short) is True, "dropping a finalized block must be rejected"
print("  OK — BFT finality vetoes a rewrite/drop of block 3 that the depth checkpoint would have permitted")


print("\n=== Scenario 4: finality NEVER blocks the honest chain ===")
chain = mined_chain(5)
keys, committee = make_finality_committee(n=4)
gadget = BftFinalityGadget(chain, keys, committee)
gadget.finalize_height(2)
gadget.finalize_height(3)
# The honest chain extended by a new block agrees with every finalized index.
honest_extension = list(chain.chain) + [chain.chain[-1]]
assert chain._conflicts_with_bft_finality(honest_extension) is False, \
    "a candidate that agrees with all finalized checkpoints must pass the finality veto"
print("  OK — honest extensions that respect finalized checkpoints are never vetoed")

print("\n=== Scenario 5: DORMANT on the live path — a real reorg still works untouched ===")
# The production state: a Blockchain that never runs the gadget. A genuinely
# longer, valid competing chain must still replace ours exactly as before —
# proving the attached-but-dormant hook changes nothing when unused.
base = Blockchain()
for _ in range(3):
    base.mine_block("a" * 40)
assert base.bft_finalized == {}, "live chain never touched by the gadget => empty finalized set"

# Build a real, valid, strictly-longer competing chain from a fork of block 1.
rival = Blockchain()
rival.chain = list(base.chain[:2])  # share genesis + block 1
rival._rebuild_balance_index()
for _ in range(3):  # now mine it longer than base (2 -> 5 vs base's 4)
    rival.mine_block("b" * 40)
assert len(rival.chain) > len(base.chain)
replaced = base.replace_chain(rival.chain)
assert replaced is True, "with no finalization, a longer valid chain must replace ours exactly as before"
print(f"  OK — dormant hook is invisible: longer valid chain replaced ours ({replaced}); reorg path unchanged")

print("\n=== ALL FINALITY-GADGET SCENARIOS PASSED ===")
