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


def build_cluster(n=N, view_timeout=2.0, deferred=()):
    """Build n nodes. Every node's intended (host, port) is stashed on
    node.host_port; nodes whose index is in `deferred` are created but NOT
    started (the test starts them later via node.start(*node.host_port), to
    simulate a late-joining / restarted validator)."""
    keys = [BftValidatorKey() for _ in range(n)]
    committee = Committee([k.public_key_hex() for k in keys])
    ports = [_free_port() for _ in range(n)]
    peers = {i: f"http://127.0.0.1:{ports[i]}" for i in range(n)}
    nodes = [BftNode(i, keys[i], committee, peers, view_timeout_seconds=view_timeout, tick_seconds=0.2)
             for i in range(n)]
    for i, node in enumerate(nodes):
        node.host_port = ("127.0.0.1", ports[i])
        if i not in deferred:
            node.start("127.0.0.1", ports[i])
    # Wait until every STARTED server is actually accepting connections.
    deadline = time.time() + 10
    for i in range(n):
        if i in deferred:
            continue
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
    statuses = wait_for_commits(peers, list(range(N)), min_commits=2, timeout=60)
    for i in range(N):
        print(f"  node {i}: view={statuses[i]['current_view']} committed={statuses[i]['committed_count']-1} beyond genesis")
    assert all(statuses[i]["committed_count"] >= 3 for i in range(N)), \
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
    statuses = wait_for_commits(peers, list(range(N)), min_commits=2, timeout=60)
    for i in range(N):
        print(f"  node {i}: view={statuses[i]['current_view']} committed={statuses[i]['committed_count']-1} beyond genesis")
    assert all(statuses[i]["committed_count"] >= 3 for i in range(N)), \
        "the committee must self-start purely via the pacemaker and commit a real chain"
    assert_consistent(statuses)
    print("  OK — committee bootstrapped itself with zero kickoff, purely via the timeout/new-view pacemaker, and agreed")
finally:
    for node in nodes:
        node.stop()
    time.sleep(0.5)


print("\n=== Scenario 3: liveness around a permanently crashed node (n=4, f=1) ===")
# This is the case that COULDN'T commit under the old single-next-leader
# vote routing: with n=4/f=1 and a fixed round-robin, a permanently dead
# node lands as the vote-tallier (the next view's leader) often enough to
# poison every 3-chain commit window, even though a full honest quorum keeps
# voting. Broadcasting votes to the WHOLE committee (bft_node's vote
# dissemination) removes that single-tallier dependency: any of the 3 live
# nodes assembles each QC the moment it holds 2f+1 votes, so the dead node
# can no longer block finality. The 3 survivors here ARE exactly a quorum
# (2f+1 = 3), so this is the tightest possible crash case — and it must now
# commit consistently. Timeouts are sized above one view's serialized BLS
# cost (py_ecc's pure-Python verify is ~180ms and all nodes share one
# process/GIL) so the pacemaker converges instead of thrashing.
keys, committee, peers, nodes = build_cluster(view_timeout=3.0)
present = [0, 2, 3]  # node 1 (also the view-1 leader) will be crashed
try:
    nodes[1].stop()  # node 1 is the view-1 leader too, so view 1 must time out and rotate
    statuses = wait_for_commits(peers, present, min_commits=2, timeout=90)
    for i in present:
        print(f"  node {i}: view={statuses[i]['current_view']} committed={statuses[i]['committed_count']-1} beyond genesis")
    assert all(statuses[i]["committed_count"] >= 3 for i in present), \
        "the 3 surviving nodes (== quorum) must commit around the dead leader now that votes are broadcast"
    assert_consistent(statuses)
    print("  OK — tightest crash case (3-of-4, dead node = view-1 leader) commits consistently thanks to vote broadcast")
finally:
    for i in present:
        nodes[i].stop()
    time.sleep(0.5)

print("\n=== Scenario 4: block sync — a late-joining node catches up and rejoins ===")
# Node 3 is DEFERRED (its server never starts at first). Nodes 0,1,2 are
# exactly a quorum (2f+1 = 3), so they commit a real chain WITHOUT node 3,
# which stays frozen at genesis. Then node 3 is started cold: the first live
# proposal it receives references a parent deep in a chain it has never seen.
# Without block sync it would refuse to vote forever (missing-parent guard)
# and stay stuck. With it, node 3 fetches the missing ancestor chain from a
# peer, imports it (try_import_block validates each block's QC before
# trusting it), catches its committed state up to the others, and then votes
# on subsequent proposals — a genuine rejoin, proven over real HTTP.
keys, committee, peers, nodes = build_cluster(view_timeout=2.0, deferred={3})
try:
    # Let the 3-node quorum commit a few blocks while node 3 is absent.
    quorum = [0, 1, 2]
    early = wait_for_commits(peers, quorum, min_commits=3, timeout=60)
    for i in quorum:
        print(f"  (pre-join) node {i}: committed={early[i]['committed_count']-1} beyond genesis")
    assert all(early[i]["committed_count"] >= 4 for i in quorum), "the quorum must commit real blocks while node 3 is away"

    # Now bring node 3 online cold (fresh at genesis) and let it catch up.
    nodes[3].start(*nodes[3].host_port)
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            s3 = _get_status(peers[3])
            if s3["committed_count"] >= 4:
                break
        except Exception:
            pass
        time.sleep(0.25)

    final = {i: _get_status(peers[i]) for i in range(N)}
    for i in range(N):
        print(f"  node {i}: view={final[i]['current_view']} committed={final[i]['committed_count']-1} beyond genesis")
    assert final[3]["committed_count"] >= 4, \
        "the late-joining node must catch up to a real committed chain via block sync"
    # And what it caught up to must MATCH the others — sync can't invent a fork.
    assert_consistent(final)
    shortest = min(final[i]["committed_count"] for i in range(N))
    ref = final[0]["committed"][:shortest]
    assert final[3]["committed"][:shortest] == ref, "the synced node's chain must be identical to the committee's"
    print(f"  OK — node 3 joined cold, synced {final[3]['committed_count']-1} committed blocks, and matches the committee exactly")
finally:
    for node in nodes:
        node.stop()
    time.sleep(0.5)


print("\n=== ALL BFT NODE (HTTP) SCENARIOS PASSED ===")
