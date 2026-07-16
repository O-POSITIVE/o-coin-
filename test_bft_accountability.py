"""Adversarial tests for bft_accountability.py — same "reproduce a real
attack, then prove the defense holds" standard as test_bft_consensus.py.

The centerpiece is Scenario 3: it FORCES an actual safety violation (two
conflicting blocks both getting valid Quorum Certificates at the same view,
which requires more than f Byzantine validators) and shows the
accountability layer identifies exactly the f+1 overlap validators who
provably equivocated — while the honest validators who merely voted for
different blocks are untouchable. That's the accountable-safety property
demonstrated empirically, not just asserted.
"""
from bft_validator import BftValidatorKey
from bft_consensus import Vote, Committee, QuorumCertificate, _vote_message
from bft_accountability import EquivocationEvidence, AccountabilityMonitor, SlashingRegistry

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
    from py_ecc.bls import G2ProofOfPossession as bls
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


print("\n=== ALL ACCOUNTABILITY SCENARIOS PASSED ===")
