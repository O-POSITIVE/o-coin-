"""Adversarial tests for bft_onchain_stake.py — proves the bridge between
BFT accountability evidence and REAL O-Coin balances actually holds, using
a real (local, in-memory, throwaway) Blockchain() instance: real PoW-mined
coinbase rewards, real stake_weight_of()/get_balance() reads, and a real
slash that a completely independent get_balance() call afterward confirms.

Same standard as test_bft_accountability.py: force the actual mechanism to
run (mine real blocks, construct real forged/genuine evidence) rather than
asserting behavior from a description of it.
"""
import bls_backend as bls

from blockchain import Blockchain
from wallet import Wallet
from bft_validator import BftValidatorKey
from bft_consensus import BftBlock, BftReplica, Vote, Committee, QuorumCertificate, _vote_message
from bft_accountability import EquivocationEvidence, ThreeChainWitness, ConflictingCommitEvidence, AccountabilityMonitor
from bft_onchain_stake import OnChainBondedCommittee, OnChainSlashingRegistry, slash_on_chain

N = 4  # f = 1, quorum = 2f+1 = 3


def make_committee():
    keys = [BftValidatorKey() for _ in range(N)]
    committee = Committee([k.public_key_hex() for k in keys])
    return keys, committee


def make_vote(key, index, block_hash, view):
    sig = key.sign(_vote_message(block_hash, view))
    return Vote(block_hash, view, index, sig.hex())


def run_partition_view(committee, keys, replicas_by_index, view, payload):
    for r in replicas_by_index.values():
        r.advance_to_view(view)
    leader_idx = committee.leader_for_view(view)
    if leader_idx in replicas_by_index:
        block = replicas_by_index[leader_idx].propose(payload)
    else:
        any_present = next(iter(replicas_by_index.values()))
        block = BftBlock(view, any_present.high_qc.block_hash, payload,
                          keys[leader_idx].public_key_hex(), justify=any_present.high_qc.to_dict())
    votes = [v for r in replicas_by_index.values() if (v := r.on_receive_proposal(block)) is not None]
    qc = None
    if len(votes) >= committee.quorum_size():
        next_leader_idx = committee.leader_for_view(view + 1)
        if next_leader_idx in replicas_by_index:
            for v in votes:
                res = replicas_by_index[next_leader_idx].on_receive_vote(v)
                if res is not None:
                    qc = res
        else:
            idxs = sorted(v.voter_index for v in votes)
            agg = bls.Aggregate([bytes.fromhex(v.signature_hex) for v in votes])
            qc = QuorumCertificate(block.hash, view, idxs, agg.hex())
        if qc is not None:
            for r in replicas_by_index.values():
                r._apply_qc(qc)
    return block, qc, votes


def fund_validators(mine_counts):
    """Fresh local Blockchain(), real PoW-mined coinbase rewards to N fresh
    O-Coin wallets — mine_counts[i] blocks mined to validator i's address,
    so validators end up with genuinely DIFFERENT real balances (proving
    bond_of() isn't reading a placeholder). Returns (blockchain, addresses)."""
    chain = Blockchain()
    wallets = [Wallet() for _ in range(N)]
    addresses = [w.address for w in wallets]
    for i, count in enumerate(mine_counts):
        for _ in range(count):
            chain.mine_block(addresses[i])
    return chain, addresses


BLOCK_A = "a" * 64
BLOCK_B = "b" * 64


print("=== Scenario 1: bond_of() reads REAL, genuinely different on-chain stake ===")
chain, addresses = fund_validators([1, 2, 3, 1])
keys, committee = make_committee()
bonded = OnChainBondedCommittee(addresses)
bonds = bonded.all_bonds(chain)
print(f"  real bonds: {bonds}")
for i in range(N):
    # get_balance() itself can be a raw float (coinbase rewards follow a
    # decaying-emission CURVE, not whole coins) — stake_weight_of floors
    # it to a whole coin on purpose (see its own docstring: no float in a
    # consensus-relevant weight). bond_of must match that floor exactly,
    # not the raw balance.
    expected = int(chain.get_balance(addresses[i]))
    assert bonds[i] == expected, "bond_of must equal a fully independent get_balance() call, floored"
    assert bonds[i] == chain.stake_weight_of(addresses[i]), "bond_of must equal stake_weight_of exactly (same weighting PoS uses)"
assert len(set(bonds.values())) > 1, "validators must have genuinely DIFFERENT real stake, not a placeholder constant"
assert bonds[2] > bonds[1] > bonds[0] == bonds[3], "bonds must track how many blocks were actually mined to each address"
print("  OK — bonds are real, independently-verifiable, and vary by validator as expected")


print("\n=== Scenario 2: a proven equivocator's REAL balance is zeroed on-chain ===")
chain, addresses = fund_validators([2, 2, 2, 2])
keys, committee = make_committee()
bonded = OnChainBondedCommittee(addresses)
before = {i: chain.get_balance(addresses[i]) for i in range(N)}  # raw balance — what actually gets burned
before_bond = {i: chain.stake_weight_of(addresses[i]) for i in range(N)}  # floored — what the registry tracks as "bond"
assert before[2] > 0, "sanity: the culprit must actually hold real stake before being slashed"
registry = OnChainSlashingRegistry(committee, bonded, chain)
assert registry.bond == before_bond, "registry must initialize its bond view from real (floored) chain stake"

monitor = AccountabilityMonitor(committee)
monitor.observe(make_vote(keys[2], 2, BLOCK_A, 5))
ev = monitor.observe(make_vote(keys[2], 2, BLOCK_B, 5))
assert ev is not None and ev.verify(committee)

burned = registry.apply(ev)
assert burned == before[2], "must burn exactly the culprit's real pre-slash balance"
# Independent verification: don't just trust the registry's internal
# bookkeeping — ask the blockchain itself.
assert chain.get_balance(addresses[2]) == 0, "culprit's REAL on-chain balance must actually be zero now"
assert chain.stake_weight_of(addresses[2]) == 0
for i in (0, 1, 3):
    assert chain.get_balance(addresses[i]) == before[i], "honest validators' real balances must be untouched"
print(f"  OK — validator 2's real balance dropped {before[2]} -> 0 on-chain; honest validators' balances untouched")


print("\n=== Scenario 3: FORGED evidence burns nothing, verified against real balances ===")
chain, addresses = fund_validators([3, 3, 3, 3])
keys, committee = make_committee()
bonded = OnChainBondedCommittee(addresses)
before = {i: chain.get_balance(addresses[i]) for i in range(N)}

# Genuine vote_a, but vote_b's signature is forged (validator 1 signing,
# claimed to be validator 2) — structurally shaped like evidence but must
# fail cryptographic verification.
real_vote_a = make_vote(keys[2], 2, BLOCK_A, 9)
forged_sig = keys[1].sign(_vote_message(BLOCK_B, 9)).hex()
forged_vote_b = Vote(BLOCK_B, 9, 2, forged_sig)
forged_ev = EquivocationEvidence(2, 9, real_vote_a, forged_vote_b)
assert forged_ev.verify(committee) is False, "forged second signature must fail verification"

registry = OnChainSlashingRegistry(committee, bonded, chain)
burned = registry.apply(forged_ev)
assert burned == 0, "unverified evidence must burn nothing"
assert registry.slashed == set()
for i in range(N):
    assert chain.get_balance(addresses[i]) == before[i], "no real balance may move on forged evidence"
print("  OK — forged evidence rejected, every validator's real balance untouched")


print("\n=== Scenario 4: idempotent — re-submitting the same evidence burns nothing more ===")
chain, addresses = fund_validators([2, 2, 2, 2])
keys, committee = make_committee()
bonded = OnChainBondedCommittee(addresses)
registry = OnChainSlashingRegistry(committee, bonded, chain)
monitor = AccountabilityMonitor(committee)
monitor.observe(make_vote(keys[0], 0, BLOCK_A, 3))
ev = monitor.observe(make_vote(keys[0], 0, BLOCK_B, 3))
first = registry.apply(ev)
second = registry.apply(ev)
assert first > 0 and second == 0, "second application of the same evidence must burn 0 additional"
assert chain.get_balance(addresses[0]) == 0, "balance stays at 0, never goes negative"
print(f"  OK — first apply burned {first}, replay burned {second}, balance floor holds at 0")


print("\n=== Scenario 5: REAL cross-view conflicting-commit slash, grounded in real stake ===")
chain, addresses = fund_validators([5, 5, 4, 4])  # 0,1 = double-agents; 2,3 = honest single-partition
keys, committee = make_committee()
bonded = OnChainBondedCommittee(addresses)
before = {i: chain.get_balance(addresses[i]) for i in range(N)}

partA = {i: BftReplica(i, keys[i], committee) for i in (0, 1, 2)}
partB = {i: BftReplica(i, keys[i], committee) for i in (0, 1, 3)}
blocks_a, qcs_a = [], []
for v in range(1, 5):
    b, qc, _ = run_partition_view(committee, keys, partA, v, f"A-{v}")
    blocks_a.append(b); qcs_a.append(qc)
blocks_b, qcs_b = [], []
for v in range(1, 5):
    b, qc, _ = run_partition_view(committee, keys, partB, v, f"B-{v}")
    blocks_b.append(b); qcs_b.append(qc)
assert partA[2].committed[-1] != partB[3].committed[-1], "the two partitions must have genuinely committed conflicting blocks"

genesis = BftBlock.genesis()
witness_a = ThreeChainWitness(qcs_a[1], blocks_a[1], qcs_a[2], blocks_a[2], qcs_a[3], blocks_a[3])
witness_b = ThreeChainWitness(qcs_b[1], blocks_b[1], qcs_b[2], blocks_b[2], qcs_b[3], blocks_b[3])
chain_a = [genesis, blocks_a[0], blocks_a[1]]
chain_b = [genesis, blocks_b[0], blocks_b[1]]
evidence = ConflictingCommitEvidence(witness_a, chain_a, witness_b, chain_b)
assert evidence.verify(committee) and evidence.culprits() == [0, 1]

registry = OnChainSlashingRegistry(committee, bonded, chain)
burned = registry.apply(evidence)
assert burned == before[0] + before[1], "must burn exactly the two culprits' real combined stake"
assert chain.get_balance(addresses[0]) == 0 and chain.get_balance(addresses[1]) == 0, "both culprits' real balances zeroed on-chain"
assert chain.get_balance(addresses[2]) == before[2] and chain.get_balance(addresses[3]) == before[3], \
    "the two exclusively-honest, single-partition validators' real stake must be completely untouched"
print(f"  OK — cross-view culprits 0,1 real stake ({before[0]}+{before[1]}) burned on-chain; honest 2,3 untouched")


print("\n=== Scenario 6: slashing is surgical — unrelated real chain state is never touched ===")
chain, addresses = fund_validators([2, 2, 2, 2])
keys, committee = make_committee()
bonded = OnChainBondedCommittee(addresses)
genesis_premine_address = chain.GENESIS_PREMINE_ADDRESS
premine_before = chain.get_balance(genesis_premine_address)
block_count_before = len(chain.chain)

registry = OnChainSlashingRegistry(committee, bonded, chain)
monitor = AccountabilityMonitor(committee)
monitor.observe(make_vote(keys[3], 3, BLOCK_A, 1))
ev = monitor.observe(make_vote(keys[3], 3, BLOCK_B, 1))
registry.apply(ev)

assert chain.get_balance(genesis_premine_address) == premine_before, "an unrelated address's real balance must never move"
assert len(chain.chain) == block_count_before, "slashing must never mine, append, or otherwise mutate a real block"
print("  OK — genesis premine balance and chain length both completely unaffected by an unrelated slash")

print("\n=== ALL SCENARIOS PASSED ===")
