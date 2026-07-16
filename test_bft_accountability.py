"""Adversarial tests for bft_accountability.py — same "reproduce a real
attack, then prove the defense holds" standard as test_bft_consensus.py.

Scenario 3 covers same-view EQUIVOCATION: it FORCES an actual safety
violation (two conflicting blocks both getting valid Quorum Certificates
at the same view, which requires more than f Byzantine validators) and
shows the accountability layer identifies exactly the f+1 overlap
validators who provably equivocated.

Scenario 7 covers the CROSS-VIEW generalization: it drives two fully
independent, genuinely-real BftReplica simulations ("partitions") to two
separately, honestly-COMMITTED (real 3-chain) but mutually conflicting
histories — using 2 Byzantine "double-agent" validators who participate
honestly-looking in each partition separately (same identity, separate
local state per partition) plus one exclusively-honest validator per side
— and shows ConflictingCommitEvidence identifies exactly the 2 double
agents while the two genuinely-honest, single-partition validators (who
never equivocated, never even saw the other branch) stay untouchable.
That's the accountable-safety guarantee demonstrated for a cross-view
break, not just the same-view case, and via the ACTUAL protocol state
machine (BftReplica.propose/on_receive_proposal/on_receive_vote), not
hand-waved data structures.
"""
import bls_backend as bls

from bft_validator import BftValidatorKey
from bft_consensus import BftBlock, BftReplica, Vote, Committee, QuorumCertificate, _vote_message
from bft_accountability import (
    EquivocationEvidence, ThreeChainWitness, ConflictingCommitEvidence,
    AccountabilityMonitor, SlashingRegistry,
)

N = 4  # f = 1, quorum = 2f+1 = 3


def make_committee():
    keys = [BftValidatorKey() for _ in range(N)]
    committee = Committee([k.public_key_hex() for k in keys])
    return keys, committee


def make_vote(key, index, block_hash, view):
    sig = key.sign(_vote_message(block_hash, view))
    return Vote(block_hash, view, index, sig.hex())


BLOCK_A = "a" * 64
BLOCK_B = "b" * 64
BLOCK_C = "c" * 64


print("=== Scenario 1: an honest run produces NO evidence and NO slashing ===")
keys, committee = make_committee()
monitor = AccountabilityMonitor(committee)
registry = SlashingRegistry(committee, bond_per_validator=1000)
# Every validator votes at most once per view, across several views — normal.
for view in (1, 2, 3):
    block = {1: BLOCK_A, 2: BLOCK_B, 3: BLOCK_C}[view]
    for i, k in enumerate(keys):
        ev = monitor.observe(make_vote(k, i, block, view))
        assert ev is None, "honest single-vote-per-view must never trigger evidence"
assert monitor.all_evidence() == [], "no evidence expected in an honest run"
assert registry.total_slashed() == 0
print("  OK — honest committee: 0 evidence, 0 slashed, all bonds intact")


print("\n=== Scenario 2: a single equivocator is caught, verified, and slashed ===")
keys, committee = make_committee()
monitor = AccountabilityMonitor(committee)
registry = SlashingRegistry(committee, bond_per_validator=1000)
# Validator 2 double-signs: block A AND block B at the same view 5.
monitor.observe(make_vote(keys[2], 2, BLOCK_A, 5))
ev = monitor.observe(make_vote(keys[2], 2, BLOCK_B, 5))
assert ev is not None, "second conflicting vote must produce evidence"
assert ev.validator_index == 2 and ev.view == 5
assert ev.verify(committee), "emitted evidence must independently verify"
burned = registry.apply(ev)
assert burned == 1000, "the offender's full bond must be slashed"
assert registry.slashed == {2}, "only the equivocator is slashed"
assert all(registry.bond[i] == 1000 for i in (0, 1, 3)), "honest validators' bonds untouched"
print(f"  OK — validator 2 caught equivocating (A vs B @ view 5), evidence verifies, {burned} bond burned; honest bonds intact")


print("\n=== Scenario 3: FORCED SAFETY VIOLATION -> accountability names exactly the f+1 culprits ===")
# Two conflicting blocks BOTH reach a valid QC at the same view -> a real
# safety break, only possible with > f Byzantine validators. With n=4/f=1,
# quorum=3: block A signed by {byz0, byz1, honest2}, block B signed by
# {byz0, byz1, honest3}. The overlap {byz0, byz1} = f+1 = 2 validators each
# signed BOTH — that's the equivocation the theorem promises is catchable.
keys, committee = make_committee()
VIEW = 7
votes_A = [make_vote(keys[i], i, BLOCK_A, VIEW) for i in (0, 1, 2)]  # byz0, byz1, honest2
votes_B = [make_vote(keys[i], i, BLOCK_B, VIEW) for i in (0, 1, 3)]  # byz0, byz1, honest3

# Confirm this really IS a safety violation: both QCs genuinely verify.
def qc_from(votes, block_hash):
    import bls_backend as bls
    idxs = sorted(v.voter_index for v in votes)
    agg = bls.Aggregate([bytes.fromhex(v.signature_hex) for v in votes])
    return QuorumCertificate(block_hash, VIEW, idxs, agg.hex())
qc_A = qc_from(votes_A, BLOCK_A)
qc_B = qc_from(votes_B, BLOCK_B)
assert qc_A.verify(committee) and qc_B.verify(committee), "both conflicting QCs must be valid — else it's not a real safety break"
assert qc_A.block_hash != qc_B.block_hash and qc_A.view == qc_B.view
print(f"  set up a genuine safety break: two VALID QCs for different blocks at view {VIEW}")

# Any observer feeding the full vote stream through the monitor catches the culprits.
monitor = AccountabilityMonitor(committee)
registry = SlashingRegistry(committee, bond_per_validator=1000)
for v in votes_A + votes_B:  # order-independent; interleaved would work identically
    monitor.observe(v)
caught = set(monitor.evidence.keys())
assert caught == {0, 1}, f"accountability must name exactly the f+1 overlap validators, got {caught}"
assert len(caught) >= committee.f + 1, "accountable safety guarantees >= f+1 attributable culprits"
for ev in monitor.all_evidence():
    assert ev.verify(committee), "every emitted piece of evidence must independently verify"
    registry.apply(ev)
assert registry.slashed == {0, 1}, "exactly the two equivocators slashed"
# The honest validators voted for DIFFERENT blocks (2->A, 3->B) but each only
# once — voting differently is NOT an offense, and they must stay unslashed.
assert registry.bond[2] == 1000 and registry.bond[3] == 1000, "honest minority-voters must NOT be slashable"
print(f"  OK — safety broke, and the culprits are named: validators {caught} slashed; honest 2 & 3 (voted differently, once each) untouched")


print("\n=== Scenario 4: an honest validator CANNOT be framed ===")
keys, committee = make_committee()
# Attacker has honest validator 1's real vote for A, and wants to frame them.
real_vote = make_vote(keys[1], 1, BLOCK_A, 9)
# They fabricate a 'second' vote for B at the same view — but they don't hold
# validator 1's key, so they can only put a bogus signature on it.
forged_second = Vote(BLOCK_B, 9, 1, ("00" * 96))  # not a real signature by validator 1
framing = EquivocationEvidence(1, 9, real_vote, forged_second)
assert not framing.verify(committee), "evidence with a forged second signature must NOT verify"
# And the monitor rejects the forged vote outright (never even records it).
monitor = AccountabilityMonitor(committee)
monitor.observe(real_vote)
assert monitor.observe(forged_second) is None, "a forged vote must not produce evidence"
assert monitor.all_evidence() == [], "no honest validator can be framed"
print("  OK — forging the second signature fails verification; honest validator 1 cannot be framed")


print("\n=== Scenario 5: evidence self-consistency — non-offenses are rejected ===")
keys, committee = make_committee()
# (a) same block twice at same view = re-broadcast, NOT an offense
v1 = make_vote(keys[0], 0, BLOCK_A, 3)
v1_again = make_vote(keys[0], 0, BLOCK_A, 3)
assert not EquivocationEvidence(0, 3, v1, v1_again).verify(committee), "same-block re-vote is legal, not evidence"
# (b) different VIEWS is legal — voting once per view across views is normal
va = make_vote(keys[0], 0, BLOCK_A, 3)
vb = make_vote(keys[0], 0, BLOCK_B, 4)
assert not EquivocationEvidence(0, 3, va, vb).verify(committee), "votes in different views are not an equivocation"
# (c) evidence naming validator 0 but carrying validator 1's votes
w = make_vote(keys[1], 1, BLOCK_A, 3)
w2 = make_vote(keys[1], 1, BLOCK_B, 3)
assert not EquivocationEvidence(0, 3, w, w2).verify(committee), "validator_index must match the votes' voter_index"
print("  OK — same-block, cross-view, and mismatched-voter 'evidence' all correctly rejected")


print("\n=== Scenario 6: slashing is idempotent (no double-burn on resubmitted evidence) ===")
keys, committee = make_committee()
monitor = AccountabilityMonitor(committee)
registry = SlashingRegistry(committee, bond_per_validator=500)
monitor.observe(make_vote(keys[3], 3, BLOCK_A, 2))
ev = monitor.observe(make_vote(keys[3], 3, BLOCK_C, 2))
assert registry.apply(ev) == 500, "first slash burns the bond"
assert registry.apply(ev) == 0, "re-applying the same evidence burns nothing more"
assert registry.bond[3] == 0 and registry.slashed == {3}
print("  OK — a validator can't be double-burned by resubmitting the same proof")


def run_partition_view(committee, keys, replicas_by_index, view, payload):
    """Drives one view for a PARTITION — a subset of the full committee's
    replica objects. If the view's rightful leader has a real replica
    present in this partition, it proposes normally via propose(). If not
    (that validator has NO replica object in this partition at all — it's
    exclusive to the OTHER partition), a proposal is constructed BY HAND,
    correctly claiming that validator's REAL public key as proposer and
    extending this partition's own current high_qc — exactly what that
    validator would honestly propose if it were here, using only its
    PUBLIC key (no private key or vote needed from it, since it isn't a
    member of this partition). Either way every PRESENT replica votes via
    on_receive_proposal, real BLS signatures and all. Once quorum is
    reached, the resulting QC is applied to every present replica (real
    _apply_qc — equivalent to "every partition member reliably observed
    this valid QC," sidestepping only the exact propagation TIMING, not
    the cryptographic content, which the evidence never depends on
    anyway). Returns (block, qc_or_None, votes)."""
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


print("\n=== Scenario 7: CROSS-VIEW — two real, separately-COMMITTED conflicting chains ===")
keys, committee = make_committee()
# Partition A = {0,1,2}: double-agents 0,1 (their OWN, separate state for
# this partition) + validator 2, who is EXCLUSIVELY honest here — it never
# sees, votes on, or even knows partition B's proposals exist.
partA = {i: BftReplica(i, keys[i], committee) for i in (0, 1, 2)}
# Partition B = {0,1,3}: the SAME double-agents 0,1 (separate state objects,
# same real keys) + validator 3, exclusively honest in B.
partB = {i: BftReplica(i, keys[i], committee) for i in (0, 1, 3)}

blocks_a, qcs_a = [], []
for v in range(1, 5):
    b, qc, _ = run_partition_view(committee, keys, partA, v, f"A-cmd-{v}")
    blocks_a.append(b); qcs_a.append(qc)
blocks_b, qcs_b = [], []
for v in range(1, 5):
    b, qc, _ = run_partition_view(committee, keys, partB, v, f"B-cmd-{v}")
    blocks_b.append(b); qcs_b.append(qc)

print(f"  partition A really committed (via its own honest replica 2's state): {[h[:8] for h in partA[2].committed]}")
print(f"  partition B really committed (via its own honest replica 3's state): {[h[:8] for h in partB[3].committed]}")
assert len(partA[2].committed) >= 2 and len(partB[3].committed) >= 2, "both partitions must have genuinely committed a real block beyond genesis"
assert partA[2].committed[-1] != partB[3].committed[-1], "the two committed chains must actually conflict, not coincide"

# Build each side's witness from the SAME view-1..4 chain (block0=view2,
# block1=view3, block2=view4 — the 3-chain that got view2 committed).
genesis = BftBlock.genesis()
witness_a = ThreeChainWitness(qcs_a[1], blocks_a[1], qcs_a[2], blocks_a[2], qcs_a[3], blocks_a[3])
witness_b = ThreeChainWitness(qcs_b[1], blocks_b[1], qcs_b[2], blocks_b[2], qcs_b[3], blocks_b[3])
assert witness_a.verify(committee) and witness_b.verify(committee), "both witnesses must independently verify"
assert witness_a.block0.hash == partA[2].committed[-1], "witness must match what the HONEST replica actually, really committed"
assert witness_b.block0.hash == partB[3].committed[-1]

chain_a = [genesis, blocks_a[0], blocks_a[1]]
chain_b = [genesis, blocks_b[0], blocks_b[1]]
evidence = ConflictingCommitEvidence(witness_a, chain_a, witness_b, chain_b)
assert evidence.verify(committee) is True, "genuine conflicting-commit evidence must verify"
culprits = evidence.culprits()
print(f"  evidence.culprits() = {culprits}")
assert culprits == [0, 1], f"must name EXACTLY the 2 double-agent validators, got {culprits}"
assert len(culprits) >= committee.f + 1, "accountable safety guarantees >= f+1 attributable culprits"

monitor = AccountabilityMonitor(committee)
fresh = monitor.submit_conflicting_commits(evidence)
assert set(fresh) == {0, 1}
registry = SlashingRegistry(committee, bond_per_validator=1000)
burned = registry.apply(evidence)
assert burned == 2000 and registry.slashed == {0, 1}
assert registry.bond[2] == 1000 and registry.bond[3] == 1000, "the two genuinely-honest, single-partition validators must be untouchable"
print(f"  OK — {burned} slashed from validators {sorted(registry.slashed)}; honest 2 & 3 (each only ever saw ONE branch, never equivocated) untouched")


print("\n=== Scenario 8: a later block that legitimately EXTENDS an earlier commit is NOT a conflict ===")
keys2, committee2 = make_committee()
solo = {i: BftReplica(i, keys2[i], committee2) for i in range(N)}
blocks_s, qcs_s = [], []
for v in range(1, 8):
    b, qc, _ = run_partition_view(committee2, keys2, solo, v, f"solo-{v}")
    blocks_s.append(b); qcs_s.append(qc)
assert len(solo[0].committed) >= 4, "a single honest run should commit several blocks in a row"
# Two REAL witnesses from the SAME honest chain — block0=view2 (blocks_s[1])
# and block0=view5 (blocks_s[4], which genuinely extends view2's block).
witness_early = ThreeChainWitness(qcs_s[1], blocks_s[1], qcs_s[2], blocks_s[2], qcs_s[3], blocks_s[3])
witness_late = ThreeChainWitness(qcs_s[4], blocks_s[4], qcs_s[5], blocks_s[5], qcs_s[6], blocks_s[6])
assert witness_early.verify(committee2) and witness_late.verify(committee2)
genesis2 = BftBlock.genesis()
chain_early = [genesis2, blocks_s[0], blocks_s[1]]
chain_late = [genesis2, blocks_s[0], blocks_s[1], blocks_s[2], blocks_s[3], blocks_s[4]]
non_conflict = ConflictingCommitEvidence(witness_early, chain_early, witness_late, chain_late)
assert non_conflict.verify(committee2) is False, "a later block that extends the earlier one is normal chain progress, NOT a punishable conflict"
print("  OK — later-extends-earlier correctly rejected as evidence (that's just the chain growing)")


print("\n=== Scenario 9: a witness with a forged/mismatched QC fails verification ===")
keys3, committee3 = make_committee()
tamper = {i: BftReplica(i, keys3[i], committee3) for i in range(N)}
blocks_t, qcs_t = [], []
for v in range(1, 5):
    b, qc, _ = run_partition_view(committee3, keys3, tamper, v, f"t-{v}")
    blocks_t.append(b); qcs_t.append(qc)
# Swap in a QC that does NOT actually certify block1 (wrong view) — a
# fabricated witness must not verify.
bad_qc1 = QuorumCertificate(qcs_t[2].block_hash, 999, qcs_t[2].signer_indices, qcs_t[2].agg_signature_hex)
forged_witness = ThreeChainWitness(qcs_t[1], blocks_t[1], bad_qc1, blocks_t[2], qcs_t[3], blocks_t[3])
assert forged_witness.verify(committee3) is False, "a witness whose QC view doesn't match its block must fail"
print("  OK — a witness with a mismatched/forged QC is correctly rejected")


print("\n=== ALL ACCOUNTABILITY SCENARIOS PASSED ===")
