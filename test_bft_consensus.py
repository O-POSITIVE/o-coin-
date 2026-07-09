"""Real multi-replica simulation of bft_consensus.py — no networking,
just several BftReplica instances passing messages to each other
in-process, exactly the "prove the protocol logic before adding a
network layer" step described in that module's docstring. Scenarios,
not just happy-path: an honest run (confirming blocks actually get
proposed/voted/QC'd/COMMITTED, consistently across every replica), a
forced equivocation attempt (confirming the safety rule actually stops a
Byzantine leader from getting two conflicting blocks both committed), a
skipped/dead leader (confirming the committee recovers and keeps
committing afterward), a NewView handoff (confirming the new leader
after a view-change proposes from the best QC anyone in the committee
holds, not just its own), and three forgery attempts against vote/
NewView collection (confirming BLS aggregation's all-or-nothing
verification can't be poisoned by a single bad signature, and that
NewView messages can't be replayed or sender-spoofed to fake quorum).
Every scenario here was used to find a real bug during development, not
written after the fact to match already-correct behavior.
"""
from bft_consensus import BftBlock, BftReplica, Committee, QuorumCertificate, GENESIS_BLOCK_HASH, NewViewMsg, Vote, _vote_message
from bft_validator import BftValidatorKey

N = 4  # f=1


def make_committee_and_replicas():
    keys = [BftValidatorKey() for _ in range(N)]
    committee = Committee([k.public_key_hex() for k in keys])
    replicas = [BftReplica(i, keys[i], committee) for i in range(N)]
    return committee, replicas


def run_honest_view(committee, replicas, view, payload):
    """Drives one full view: leader proposes, everyone votes, votes route
    to the NEXT view's leader who aggregates them into a QC (which, via
    _apply_qc, updates that leader's own high_qc/locked/commit state —
    exactly mirroring on_receive_proposal's handling for every other
    replica, just triggered by vote-collection instead)."""
    for r in replicas:
        r.advance_to_view(view)
    leader = replicas[committee.leader_for_view(view)]
    block = leader.propose(payload)
    votes = [v for r in replicas if (v := r.on_receive_proposal(block)) is not None]
    next_leader = replicas[committee.leader_for_view(view + 1)]
    for v in votes:
        next_leader.on_receive_vote(v)
    return block, votes


def committed_lists_consistent(lists):
    """The real safety property to check is NOT 'every replica has an
    identical committed list at this exact instant' — in any pipelined
    protocol, whoever just formed the latest QC (via on_receive_vote) is
    always one step ahead of replicas that haven't yet seen it embedded
    in a future proposal, and that gap never fully closes at any single
    snapshot (there's always a newest QC not yet propagated). That's
    normal, expected staggering, the same as comparing two real network
    nodes' chain heights at slightly different sync instants — not a
    disagreement. The actual safety property: every replica's committed
    list must be a PREFIX of every other's (or vice versa) — i.e. no two
    replicas ever committed CONFLICTING blocks at the same position."""
    longest = max(lists, key=len)
    return all(longest[:len(lst)] == lst for lst in lists)


print("=== Scenario 1: honest run, confirm real commits ===")
committee, replicas = make_committee_and_replicas()
blocks = []
for view in range(1, 9):
    block, votes = run_honest_view(committee, replicas, view, payload=f"command-{view}")
    blocks.append(block)
    print(f"  view {view}: leader={committee.leader_for_view(view)}, votes={len(votes)}/{committee.n} (quorum={committee.quorum_size()})")

committed_sets = [tuple(r.committed) for r in replicas]
print(f"\nAll {N} replicas' committed histories are mutually consistent (no conflicting forks committed): {committed_lists_consistent(committed_sets)}")
assert committed_lists_consistent(committed_sets)
longest = max(committed_sets, key=len)
print(f"Committed chain length (incl. genesis): {len(longest)}")
assert len(longest) >= 5, "expected at least genesis + several real commits after 8 views"
print(f"Genesis still first: {longest[0] == GENESIS_BLOCK_HASH}")
assert longest[0] == GENESIS_BLOCK_HASH
# Commit order must match proposal order (block N committed strictly
# after block N-1, never out of order) — check via each committed
# block's own recorded view number, ascending.
views_in_commit_order = [replicas[0].blocks[h].view for h in longest[1:] if h in replicas[0].blocks]
print(f"Commit order matches proposal order (ascending views): {views_in_commit_order == sorted(views_in_commit_order)}")
assert views_in_commit_order == sorted(views_in_commit_order)


print("\n=== Scenario 2: forced equivocation — a Byzantine leader tries to fork ===")
committee, replicas = make_committee_and_replicas()
for view in range(1, 3):
    run_honest_view(committee, replicas, view, payload=f"command-{view}")

fork_view = 3
leader_idx = committee.leader_for_view(fork_view)
leader = replicas[leader_idx]
for r in replicas:
    r.advance_to_view(fork_view)
block_a = leader.propose(payload="honest-command")
block_b = BftBlock(fork_view, leader.high_qc.block_hash, "EVIL-conflicting-command", leader.my_key.public_key_hex(), justify=leader.high_qc.to_dict())
print(f"  leader (replica {leader_idx}) equivocates: proposes BOTH block_a={block_a.hash[:10]}... and block_b={block_b.hash[:10]}... at view {fork_view}")

# Split the honest replicas 2/2 — send block_a to replicas 0,1 and block_b to replicas 2,3 (leader itself votes for whichever it "really" wants, here block_a)
half = N // 2
votes_a = [v for r in replicas[:half] if (v := r.on_receive_proposal(block_a)) is not None]
votes_b = [v for r in replicas[half:] if (v := r.on_receive_proposal(block_b)) is not None]
print(f"  votes for block_a: {len(votes_a)}, votes for block_b: {len(votes_b)} (quorum needed: {committee.quorum_size()})")
neither_reached_quorum = len(votes_a) < committee.quorum_size() and len(votes_b) < committee.quorum_size()
print(f"  neither side alone reaches quorum (2f+1={committee.quorum_size()} out of n={committee.n}): {neither_reached_quorum}")
assert neither_reached_quorum, "a 2-way split among 4 replicas should never let either side alone reach a 3-vote quorum"

# Now try to feed ALL votes (both sides) to the collecting leader anyway,
# simulating an attacker who somehow gathered votes from both camps —
# the real safety guarantee isn't "can't gather votes", it's "an honest
# replica never signs twice for one view", which we test directly here:
double_voter = None
for r in replicas:
    v_a = r.on_receive_proposal(block_a)
    v_b = r.on_receive_proposal(block_b)
    if v_a is not None and v_b is not None:
        double_voter = r
print(f"  any honest replica signed votes for BOTH conflicting blocks at the same view: {double_voter is not None}")
assert double_voter is None, "an honest replica must never vote for two different blocks in the same view"


print("\n=== Scenario 3: a leader goes silent — committee must recover ===")
committee, replicas = make_committee_and_replicas()
for view in range(1, 5):
    run_honest_view(committee, replicas, view, payload=f"pre-stall-{view}")
before_stall_committed = len(replicas[0].committed)

# View 5's leader "goes silent" — nobody proposes, everyone times out and
# advances past it instead of voting for anything.
for r in replicas:
    r.advance_to_view(6)
print(f"  view 5's leader ({committee.leader_for_view(5)}) never proposed — all replicas advanced straight past it to view 6")

for view in range(6, 10):
    run_honest_view(committee, replicas, view, payload=f"post-stall-{view}")
run_honest_view(committee, replicas, 10, payload="settle")  # see Scenario 1's comment on why one extra view is needed before comparing
after_stall_committed = len(replicas[0].committed)
print(f"  committed blocks before stall: {before_stall_committed}, after recovery + 4 more views: {after_stall_committed}")
print(f"  committee kept making real progress after a skipped leader: {after_stall_committed > before_stall_committed}")
assert after_stall_committed > before_stall_committed
final_sets = [tuple(r.committed) for r in replicas]
print(f"  all replicas' histories still mutually consistent after recovering from the stall: {committed_lists_consistent(final_sets)}")
assert committed_lists_consistent(final_sets)


print("\n=== Scenario 4: NewView handoff — new leader must propose from the BEST known QC, not just its own ===")
committee, replicas = make_committee_and_replicas()
for view in range(1, 4):
    run_honest_view(committee, replicas, view, payload=f"cmd-{view}")
# Only replica 0 (leader_for_view(4)) ever collected view 3's votes, so
# only IT has high_qc.view==3 — everyone else is stuck at view==2. This
# reproduces the exact real gap found above: without a NewView handoff,
# view 5's leader (replica 1, high_qc.view==2) would propose on top of
# stale history, wasting the real work already done on block 3.
stale_views = [r.high_qc.view for r in replicas]
print(f"  high_qc views before view-change: {stale_views} (replica 0 alone knows about view 3)")
assert stale_views[0] == 3 and all(v == 2 for v in stale_views[1:])

for r in replicas:
    r.advance_to_view(5)
leader5 = replicas[committee.leader_for_view(5)]
print(f"  view 5 leader is replica {committee.leader_for_view(5)}, whose OWN high_qc.view is still {leader5.high_qc.view}")

new_views = [r.make_new_view() for r in replicas]
for nv in new_views:
    leader5.on_receive_new_view(nv)
print(f"  after collecting NewView messages from all replicas, leader5's high_qc.view is now: {leader5.high_qc.view}")
assert leader5.high_qc.view == 3, "NewView handoff should have picked up replica 0's better QC"

block5 = leader5.propose("cmd-5-after-handoff")
parent_view = replicas[0].blocks[block5.parent_hash].view if block5.parent_hash in replicas[0].blocks else None
print(f"  block5's parent is now view {parent_view} (should be 3, not the stale 2 from before the fix)")
assert parent_view == 3


print("\n=== Scenario 5: a single bad vote must not poison the whole aggregate QC ===")
committee, replicas = make_committee_and_replicas()
leader = replicas[0]
block_hash, view = "a" * 64, 1
honest_votes = [
    Vote(block_hash, view, 0, replicas[0].my_key.sign(_vote_message(block_hash, view)).hex()),
    Vote(block_hash, view, 1, replicas[1].my_key.sign(_vote_message(block_hash, view)).hex()),
    Vote(block_hash, view, 3, replicas[3].my_key.sign(_vote_message(block_hash, view)).hex()),
]
bad_vote = Vote(block_hash, view, 2, replicas[2].my_key.sign(b"not the real vote message").hex())
formed = [leader.on_receive_vote(v) for v in [honest_votes[0], honest_votes[1], bad_vote, honest_votes[2]]]
qc = next((q for q in formed if q), None)
print(f"  a bogus vote from replica 2 mixed in with 3 honest votes — QC formed: {qc is not None}")
assert qc is not None, "the 3 honest votes alone should still reach quorum (2f+1=3)"
print(f"  QC verifies: {qc.verify(committee)}, signers: {qc.signer_indices} (must exclude replica 2)")
assert qc.verify(committee)
assert 2 not in qc.signer_indices


print("\n=== Scenario 6: NewView collection must resist replay and sender-spoofing, not just forged content ===")
committee, replicas = make_committee_and_replicas()
for r in replicas:
    r.advance_to_view(5)
leader = replicas[0]
real_msg = replicas[1].make_new_view()
leader.on_receive_new_view(real_msg)
leader.on_receive_new_view(real_msg)
replayed_result = leader.on_receive_new_view(real_msg)
print(f"  3 copies of ONE real sender's message reaching quorum (must be False): {replayed_result}")
assert replayed_result is False

leader2 = replicas[2]
for r in replicas:
    r.advance_to_view(6)
stolen = replicas[1].make_new_view()
spoofed = NewViewMsg(stolen.view, stolen.high_qc, 3, stolen.signature_hex)  # relabel sender 1's real signature as sender 3's
spoofed_result = leader2.on_receive_new_view(spoofed)
print(f"  a real message relabeled under a different sender_index being accepted at all (must be False): {spoofed_result}")
assert spoofed_result is False

print("\n=== ALL SCENARIOS PASSED ===")
