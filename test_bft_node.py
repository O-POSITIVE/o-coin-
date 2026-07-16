"""Real multi-node HTTP test for bft_node.py — the network analog of the
in-process safety tests in test_bft_consensus.py, and the BFT counterpart
of the chain's own multi-node HTTP test. Spins up a genuine committee of
BftNode processes-in-threads on localhost, each with its own real BLS key
and its own Flask server, lets them talk ONLY over real HTTP, and asserts
they reach agreement — same block chain committed by everyone.

No mocking of the transport: every proposal, vote, and new-view message
actually crosses an HTTP socket between independent servers.
"""
import logging
import socket
import time
import urllib.request
import json

# Werkzeug logs every request line; silence it so the scenario output reads cleanly.
logging.getLogger("werkzeug").setLevel(logging.ERROR)

from bft_validator import BftValidatorKey
from bft_consensus import Committee
from bft_node import BftNode

N = 4  # f = 1, quorum = 3


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _get_status(url):
    with urllib.request.urlopen(url + "/bft/status", timeout=2.0) as resp:
        return json.loads(resp.read().decode())


def build_cluster(n=N, view_timeout=2.0):
    keys = [BftValidatorKey() for _ in range(n)]
    committee = Committee([k.public_key_hex() for k in keys])
    ports = [_free_port() for _ in range(n)]
    peers = {i: f"http://127.0.0.1:{ports[i]}" for i in range(n)}
    nodes = [BftNode(i, keys[i], committee, peers, view_timeout_seconds=view_timeout, tick_seconds=0.2)
             for i in range(n)]
    for i, node in enumerate(nodes):
        node.start("127.0.0.1", ports[i])
    # Wait until every server is actually accepting connections.
    deadline = time.time() + 10
    for i in range(n):
        while time.time() < deadline:
            try:
                _get_status(peers[i]); break
            except Exception:
                time.sleep(0.05)
    return keys, committee, peers, nodes


def wait_for_commits(peers, present_indices, min_commits, timeout=25):
    """Poll every present node's /bft/status until each has committed at
    least min_commits blocks (beyond genesis), or timeout. Returns the last
    status dict per node."""
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        last = {i: _get_status(peers[i]) for i in present_indices}
        if all(s["committed_count"] >= min_commits + 1 for s in last.values()):  # +1 for genesis
            return last
        time.sleep(0.25)
    return last


def assert_consistent(statuses):
    """No two honest nodes may commit conflicting histories: on the shorter
    of any two committed lists, they must agree position-for-position. This
    is the safety property — a real fork would show up as a mismatch here."""
    items = list(statuses.values())
    for a in items:
        for b in items:
            shared = min(len(a["committed"]), len(b["committed"]))
            assert a["committed"][:shared] == b["committed"][:shared], \
                f"FORK: node {a['index']} and node {b['index']} committed conflicting chains"


print("=== Scenario 1: full committee, all honest, reaches agreement over real HTTP ===")
keys, committee, peers, nodes = build_cluster()
try:
    # Leader of view 1 is index 1 (1 % 4). Have every node try to kick off;
    # only that leader actually proposes.
    for node in nodes:
        node.kickoff()
    statuses = wait_for_commits(peers, list(range(N)), min_commits=3, timeout=25)
    for i in range(N):
        print(f"  node {i}: view={statuses[i]['current_view']} committed={statuses[i]['committed_count']-1} beyond genesis")
    assert all(statuses[i]["committed_count"] >= 4 for i in range(N)), \
        "every honest node must commit a real chain of blocks over HTTP"
    assert_consistent(statuses)
    # All four agreed on the same committed prefix — check they're literally identical up to the shortest.
    shortest = min(statuses[i]["committed_count"] for i in range(N))
    ref = statuses[0]["committed"][:shortest]
    for i in range(1, N):
        assert statuses[i]["committed"][:shortest] == ref, "all honest nodes must commit the identical chain"
    print(f"  OK — all {N} nodes committed the identical chain of {shortest-1} blocks, agreed over real HTTP")
finally:
    for node in nodes:
        node.stop()
    time.sleep(0.5)


print("\n=== Scenario 2: pacemaker SELF-START — committee boots with no kickoff ===")
# Nobody calls kickoff(). The leader of view 1 never proposes, so the ONLY
# way anything happens is the pacemaker: every node's view-1 deadline
# expires, they broadcast NewViews, converge on a later view whose leader
# then proposes, and the chain commits. This exercises the entire
# timeout -> NewView-broadcast -> view-sync -> elect-leader -> propose path
# (cheap at n=4, where once a live leader is elected all 4 nodes drive a
# normal 3-chain). A committee that could only ever make progress from an
# explicit external kickoff would fail this.
keys, committee, peers, nodes = build_cluster(view_timeout=2.0)
try:
    statuses = wait_for_commits(peers, list(range(N)), min_commits=3, timeout=40)
    for i in range(N):
        print(f"  node {i}: view={statuses[i]['current_view']} committed={statuses[i]['committed_count']-1} beyond genesis")
    assert all(statuses[i]["committed_count"] >= 4 for i in range(N)), \
        "the committee must self-start purely via the pacemaker and commit a real chain"
    assert_consistent(statuses)
    print("  OK — committee bootstrapped itself with zero kickoff, purely via the timeout/new-view pacemaker, and agreed")
finally:
    for node in nodes:
        node.stop()
    time.sleep(0.5)


print("\n=== Scenario 3: liveness around a permanently crashed node (n=7, f=2) ===")
# COMMITTEE SIZE IS DELIBERATE. With n=4/f=1 and a fixed round-robin
# schedule, a single PERMANENT crash poisons every possible 3-consecutive-
# view commit window: the dead node lands as either the proposer OR the
# vote-collector (the next view's leader, since votes go only there) in
# every window of three, so no block can ever complete its 3-chain. That's
# an inherent property of this simplified single-next-leader vote
# collection, not a transport bug — worked out from the schedule, and worth
# stating honestly rather than hiding. At n=7/f=2 a single crash still
# leaves 3-consecutive-honest-leader windows (e.g. views led by 2,3,4 with
# collectors 3,4,5, all alive), so the committee genuinely COMMITS around
# the dead node. Timeouts are sized well above one view's serialized BLS
# cost (py_ecc's pure-Python BLS verify is ~180ms, and 7 nodes share one
# process/GIL here) so the pacemaker converges instead of thrashing.
N7 = 7
keys, committee, peers, nodes = build_cluster(n=N7, view_timeout=4.0)
present = [i for i in range(N7) if i != 1]
try:
    nodes[1].stop()  # node 1 is also the view-1 leader, so view 1 must time out and rotate
    statuses = wait_for_commits(peers, present, min_commits=2, timeout=120)
    for i in present:
        print(f"  node {i}: view={statuses[i]['current_view']} committed={statuses[i]['committed_count']-1} beyond genesis")
    assert all(statuses[i]["committed_count"] >= 3 for i in present), \
        "the 6 surviving nodes must resynchronize around the dead leader and commit real blocks"
    assert_consistent(statuses)
    print("  OK — committee routed around the crashed leader via the pacemaker and kept committing consistently")
finally:
    for i in present:
        nodes[i].stop()
    time.sleep(0.5)

print("\n=== ALL BFT NODE (HTTP) SCENARIOS PASSED ===")
