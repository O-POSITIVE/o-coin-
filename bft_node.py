"""HTTP wiring for the BFT layer — lets the pure BftReplica state machine
(bft_consensus.py) actually run as separate networked processes across
machines, instead of only being driven in-process by a test harness.

WHAT THIS ADDS, AND WHAT IT DELIBERATELY DOESN'T:
  bft_consensus.BftReplica is intentionally pure logic: on_receive_proposal
  returns a Vote, on_receive_vote returns a QC, make_new_view/
  on_receive_new_view handle the view-change handshake, maybe_advance_view
  handles the timeout. This file is ONLY the transport + scheduling glue
  around those methods:
    - a Flask server exposing /bft/proposal, /bft/vote, /bft/new_view for
      peers to deliver messages to this replica, plus /bft/status for
      introspection,
    - best-effort HTTP delivery of this replica's OUTGOING messages to the
      right peer(s) (the next view's leader for a vote, everyone for a
      proposal),
    - a periodic timeout tick driving maybe_advance_view for liveness.
  It adds NO new consensus rule and does NOT modify bft_consensus.py — every
  safety/liveness decision still happens inside the untouched replica.

CONCURRENCY MODEL — single consumer, no locks:
  Every message (from an HTTP handler OR generated locally, e.g. the
  proposer casting its own vote) is put on ONE queue.Queue and processed by
  ONE worker thread. The BftReplica is therefore only ever touched by that
  single thread — no lock is needed and there's no re-entrancy (a locally
  generated follow-up message is ENQUEUED, never called inline down the
  stack). HTTP handlers just enqueue and return immediately, so a slow or
  dead peer never blocks message processing. Outgoing HTTP sends run on a
  separate small thread pool for the same reason — a peer being down is the
  expected BFT case (up to f of them can be), never something that may stall
  this replica.

ISOLATION (same as bft_consensus.py / bft_accountability.py /
bft_onchain_stake.py): imports ONLY from bft_consensus / bft_validator.
Nothing here imports blockchain.py or node.py, and neither of those imports
this. Running this touches no live PoW/PoS chain state whatsoever. Whether
BFT consensus should ever drive the real chain is a separate, deliberate
integration decision that this file does not make or assume.

WHAT'S PROVEN vs. NOT: test_bft_node.py spins up a real committee of these
nodes on localhost, over real HTTP, and asserts they all commit the SAME
chain — the network analog of the in-process safety tests, and of the
chain's own multi-node HTTP test. It also proves BLOCK SYNC: a node started
cold, long after the others have committed, fetches the missing history from
a peer, catches up, and rejoins (Scenario 4) — closing the missing-ancestor
gap on_receive_proposal used to document as unbuilt. The remaining known gap
(inherited from bft_consensus.py's own TODOs, NOT introduced here) is live
committee reconfiguration — changing the validator set mid-run; this layer
assumes a fixed committee for the duration of a run and does not pretend to
solve that.
"""
import argparse
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from flask import Flask, jsonify, request

from bft_validator import BftValidatorKey
from bft_consensus import (
    BftReplica, BftBlock, Vote, NewViewMsg, Committee, QuorumCertificate, GENESIS_BLOCK_HASH,
)


class BftNode:
    """One networked validator: wraps a BftReplica with a Flask server, a
    single-consumer event loop, best-effort peer delivery, and a liveness
    timer. `peers` maps EVERY committee index (including this node's own) to
    that validator's base HTTP URL, e.g. {0: "http://127.0.0.1:7000", ...};
    this node's own entry is skipped when broadcasting."""

    def __init__(self, my_index, my_key: BftValidatorKey, committee: Committee,
                 peers: dict, view_timeout_seconds=2.0, tick_seconds=0.25):
        self.my_index = my_index
        self.committee = committee
        self.peers = dict(peers)
        self.replica = BftReplica(my_index, my_key, committee, view_timeout_seconds=view_timeout_seconds)
        self.tick_seconds = tick_seconds

        self.inbox = queue.Queue()
        self.last_progress = time.time()
        self._payload_seq = 0
        # ── transport-layer pacemaker state ──
        # BftReplica.maybe_advance_view uses a single FIXED timeout, which
        # drifts honest replicas apart under a crash (each one advances on
        # its own clock, so their NewViews never line up on one view). This
        # layer runs its own pacemaker on top of the untouched replica —
        # exponential backoff on consecutive failed views (so the committee
        # gets progressively longer to resynchronize) plus catch-up to any
        # higher view it hears about — using only the replica's PUBLIC
        # advance_to_view/make_new_view, adding no new consensus rule. This
        # is the "Pacemaker" component the HotStuff paper separates from the
        # safety core; bft_consensus.py deliberately left it as a stub.
        self._base_timeout = float(view_timeout_seconds)
        self._max_backoff_mult = 8
        self._consec_timeouts = 0
        self._view_deadline = time.time() + self._base_timeout
        self._sync_in_flight = False  # at most one block-sync fetch outstanding at a time
        self._running = False
        self._senders = ThreadPoolExecutor(max_workers=max(4, len(peers)))
        self._worker = None
        self._timer = None
        self._server = None
        self._server_thread = None

        self.app = self._build_app()

    # ── outgoing helpers ─────────────────────────────────────────────
    def _post(self, target_index, path, body):
        """Best-effort POST to one peer. A failure (peer down, timeout) is
        swallowed on purpose — tolerating up to f unreachable validators is
        the entire point of BFT, not an error to surface here."""
        url = self.peers.get(target_index)
        if url is None:
            return
        try:
            requests.post(url + path, json=body, timeout=2.0)
        except requests.RequestException:
            pass

    def _deliver(self, target_index, path, body):
        """Route a message to a committee member. If that member is THIS
        node, enqueue it locally (never a network round-trip to ourselves,
        and never an inline call — keeps the single-consumer invariant);
        otherwise send it over HTTP off the worker thread."""
        if not self._running:
            return  # stopped node: don't schedule onto an already-shutdown sender pool
        if target_index == self.my_index:
            kind = {"/bft/proposal": "proposal", "/bft/vote": "vote", "/bft/new_view": "new_view"}[path]
            self.inbox.put({"kind": kind, "body": body})
        else:
            self._senders.submit(self._post, target_index, path, body)

    def _broadcast_proposal(self, block: BftBlock):
        body = block.to_dict()
        for idx in self.peers:
            self._deliver(idx, "/bft/proposal", body)

    def _emit_new_view(self):
        """Broadcast this replica's NewView (its current view + best QC) to
        the WHOLE committee, not just the incoming leader. The leader needs
        2f+1 of them to propose; every other node uses them purely for view
        synchronization (catch up if it's behind) — that all-to-all gossip
        of the view-change is exactly what keeps honest nodes converging on
        one view instead of drifting apart. on_receive_new_view on a
        non-leader just accumulates/updates high_qc and never proposes (see
        the is_leader guard in _handle_new_view), so this is safe to send to
        everyone."""
        nv = self.replica.make_new_view()
        body = {"view": nv.view, "high_qc": nv.high_qc,
                "sender_index": nv.sender_index, "signature_hex": nv.signature_hex}
        for idx in self.peers:
            self._deliver(idx, "/bft/new_view", body)

    def _sync_to_view(self, view):
        """Catch up to a higher view observed in a peer's message. Hearing
        others at a later view means the network is live and moving, so
        reset the backoff and give the new view a fresh full window, then
        re-broadcast our own NewView there so nodes still further behind
        converge too. Returns True if we actually advanced. Bounded: we only
        advance (and thus only re-emit) when the view STRICTLY increases, so
        each node emits at most one NewView per view value."""
        if view <= self.replica.current_view:
            return False
        self.replica.advance_to_view(view)
        self._consec_timeouts = 0
        self._view_deadline = time.time() + self._base_timeout
        return True

    def _next_payload(self):
        self._payload_seq += 1
        return {"proposer": self.my_index, "view": self.replica.current_view, "seq": self._payload_seq}

    def _touch(self):
        """Record real progress (a vote cast, a QC formed, a view committed):
        push out the view deadline a fresh full window and reset the backoff,
        since the network is demonstrably healthy right now."""
        self.last_progress = time.time()
        self._consec_timeouts = 0
        self._view_deadline = time.time() + self._base_timeout

    # ── the single consumer ──────────────────────────────────────────
    def _handle_proposal(self, body):
        block = BftBlock.from_dict(body)
        justify = QuorumCertificate.from_dict(block.justify)
        # View synchronization lives in this transport layer, not in the
        # replica: a proposal for a later view carries a valid QC proving
        # the prior view finished, so it's safe to catch this replica's
        # view up before handing the block to the (untouched) safety rule,
        # which only ever votes for a proposal at its OWN current view.
        if justify is not None and block.view > self.replica.current_view:
            # A valid-looking proposal at a later view is itself progress and
            # the view-sync signal — advance to it (the safety rule inside
            # on_receive_proposal still independently decides whether to
            # actually vote). No NewView emission here: the proposal already
            # carries everyone forward.
            self._sync_to_view(block.view)
        # BLOCK SYNC: if we're missing this proposal's parent, we've fallen
        # behind (or just joined). on_receive_proposal would refuse to vote
        # and we'd be stuck forever. Instead fetch the missing ancestor chain
        # from a peer, import it, and re-deliver this same proposal to
        # ourselves so we can then vote on it normally.
        if block.parent_hash not in self.replica.blocks:
            # Pass our current frontier (high_qc's block) as `have` so the
            # peer only sends what we're actually missing instead of re-
            # walking the whole chain to genesis every time. Captured here on
            # the consumer thread so it's a consistent snapshot.
            self._request_sync(block.parent_hash, body, self.replica.high_qc.block_hash)
            return
        vote = self.replica.on_receive_proposal(block)
        if vote is not None:
            self._touch()
            # Vote dissemination — BROADCAST to the whole committee, not just
            # the next view's leader. The textbook "linear HotStuff"
            # optimization sends each vote only to the leader of view V+1, who
            # is the sole node that tallies them into QC(V). That's cheaper
            # (O(n) messages) but has a real liveness cost: if that one
            # designated tallier is the crashed/Byzantine node, QC(V) never
            # forms even though a full honest quorum voted — and under a fixed
            # round-robin schedule the dead node lands as that tallier often
            # enough to stall commits entirely (the n=4/f=1 limitation we
            # hit). Broadcasting votes (O(n^2) messages) means ANY live
            # replica can assemble the QC the instant it holds 2f+1 votes, so
            # no single node's death can block finality. on_receive_vote is
            # already written to form a QC from whatever votes it collects,
            # so this needs zero change to the consensus core — only where the
            # vote is addressed. This is the standard robustness/bandwidth
            # trade PBFT-family protocols make.
            body_out = vote.to_dict()
            for idx in self.peers:
                self._deliver(idx, "/bft/vote", body_out)

    def _handle_vote(self, body):
        vote = Vote.from_dict(body)
        qc = self.replica.on_receive_vote(vote)
        if qc is not None:
            self._touch()
            self.replica.advance_to_view(qc.view + 1)
            if self.replica.is_leader():
                self._broadcast_proposal(self.replica.propose(self._next_payload()))

    def _handle_new_view(self, body):
        msg = NewViewMsg(body["view"], body["high_qc"], body["sender_index"], body["signature_hex"])
        # View-sync FIRST: if this peer is ahead of us, catch up and
        # re-broadcast our NewView at the new view so the committee converges.
        if self._sync_to_view(msg.view):
            self._emit_new_view()
        if self.replica.on_receive_new_view(msg):
            self._touch()
            if self.replica.is_leader():  # only the incoming leader proposes; others just synced high_qc
                self._broadcast_proposal(self.replica.propose(self._next_payload()))

    def _handle_timeout(self):
        """Transport-layer pacemaker tick. If the current view's deadline has
        passed with no progress, advance one view, apply exponential backoff
        to the next deadline (giving the committee progressively longer to
        resynchronize), and broadcast a NewView so the next leader can
        collect a quorum and everyone converges on the new view."""
        now = time.time()
        if now < self._view_deadline:
            return
        self._consec_timeouts += 1
        self.replica.advance_to_view(self.replica.current_view + 1)
        mult = min(2 ** self._consec_timeouts, self._max_backoff_mult)
        self._view_deadline = now + self._base_timeout * mult
        self._emit_new_view()

    # ── block sync (catch-up for a lagging / restarted replica) ──────
    def _request_sync(self, missing_hash, retry_proposal_body, have_hash):
        """Kick off a background fetch of the ancestor chain ending at
        missing_hash (down to but excluding have_hash, our current frontier).
        Runs the network I/O on the sender pool (never blocks the consumer),
        then feeds the fetched blocks and a re-delivery of the stalled
        proposal back through the inbox so they're applied on the single
        consumer thread. At most one fetch runs at a time; extra proposals
        that arrive mid-sync are simply dropped — more will come, and
        HotStuff already tolerates message loss."""
        if self._sync_in_flight:
            return
        self._sync_in_flight = True
        self._senders.submit(self._do_sync, missing_hash, retry_proposal_body, have_hash)

    def _do_sync(self, tip_hash, retry_proposal_body, have_hash):
        blocks = None
        for idx, url in self.peers.items():
            if idx == self.my_index:
                continue
            try:
                resp = requests.get(url + f"/bft/sync/{tip_hash}", params={"have": have_hash}, timeout=3.0)
                data = resp.json()
            except (requests.RequestException, ValueError):
                continue
            if data.get("blocks"):
                blocks = data["blocks"]
                break
        # Enqueue results for the consumer thread: import the ancestors
        # (oldest-first), then clear the in-flight flag and re-deliver the
        # proposal that stalled so it can now be voted on.
        if blocks:
            for b in blocks:
                self.inbox.put({"kind": "import_block", "body": b})
        self.inbox.put({"kind": "sync_done", "body": retry_proposal_body})

    def _handle_import_block(self, body):
        # try_import_block validates the block (justify QC + rightful
        # proposer) before trusting it, so a peer serving forged/garbage
        # blocks can't corrupt our state — it just returns False.
        self.replica.try_import_block(BftBlock.from_dict(body))

    def _handle_sync_done(self, retry_proposal_body):
        self._sync_in_flight = False
        if retry_proposal_body is not None:
            self.inbox.put({"kind": "proposal", "body": retry_proposal_body})

    def _consume(self):
        dispatch = {
            "proposal": self._handle_proposal,
            "vote": self._handle_vote,
            "new_view": self._handle_new_view,
            "import_block": self._handle_import_block,
            "sync_done": self._handle_sync_done,
        }
        while self._running:
            try:
                msg = self.inbox.get(timeout=0.5)
            except queue.Empty:
                continue
            if msg.get("kind") == "timeout":
                self._handle_timeout()
                continue
            try:
                dispatch[msg["kind"]](msg["body"])
            except Exception as exc:  # one malformed message must never kill the loop
                print(f"[bft-node {self.my_index}] error handling {msg.get('kind')}: {exc}")

    def _tick(self):
        while self._running:
            time.sleep(self.tick_seconds)
            self.inbox.put({"kind": "timeout"})

    # ── HTTP surface ─────────────────────────────────────────────────
    def _build_app(self):
        app = Flask(f"bft_node_{self.my_index}")

        @app.post("/bft/proposal")
        def _proposal():
            self.inbox.put({"kind": "proposal", "body": request.get_json(force=True)})
            return jsonify(ok=True)

        @app.post("/bft/vote")
        def _vote():
            self.inbox.put({"kind": "vote", "body": request.get_json(force=True)})
            return jsonify(ok=True)

        @app.post("/bft/new_view")
        def _new_view():
            self.inbox.put({"kind": "new_view", "body": request.get_json(force=True)})
            return jsonify(ok=True)

        @app.get("/bft/sync/<tip_hash>")
        def _sync(tip_hash):
            # Serve the chain of stored blocks from tip_hash back to (but not
            # including) the requester's `have` frontier — everything it's
            # actually missing, oldest-first, ready to import in order. The
            # walk also stops at genesis, so an unknown/off-branch `have`
            # degrades safely to "everything back to genesis" rather than
            # looping. Read-only parent_hash lookups (no dict iteration), safe
            # against the consumer thread's concurrent inserts. Empty list if
            # we don't have tip_hash either (requester tries another peer).
            have = request.args.get("have", GENESIS_BLOCK_HASH)
            blocks = self.replica.blocks
            chain = []
            h = tip_hash
            steps = 0
            while h in blocks and h != GENESIS_BLOCK_HASH and h != have and steps < 1_000_000:
                chain.append(blocks[h].to_dict())
                h = blocks[h].parent_hash
                steps += 1
            chain.reverse()  # oldest-first, ready to import in order
            return jsonify(blocks=chain)

        @app.get("/bft/status")
        def _status():
            r = self.replica
            return jsonify(
                index=self.my_index,
                current_view=r.current_view,
                high_qc_view=r.high_qc.view,
                locked_qc_view=r.locked_qc.view,
                committed=r.committed,
                committed_count=len(r.committed),
            )

        return app

    # ── lifecycle ────────────────────────────────────────────────────
    def start(self, host, port):
        """Starts the HTTP server + consumer + timer threads. Uses
        werkzeug's make_server (not app.run) so the server is a real object
        this process can cleanly shut down — important for tests that spin
        several nodes up and down in one interpreter."""
        from werkzeug.serving import make_server
        self._running = True
        self._view_deadline = time.time() + self._base_timeout
        self._server = make_server(host, port, self.app, threaded=True)
        self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._server_thread.start()
        self._worker = threading.Thread(target=self._consume, daemon=True)
        self._worker.start()
        self._timer = threading.Thread(target=self._tick, daemon=True)
        self._timer.start()

    def kickoff(self):
        """Bootstrap the very first proposal. Every node may call this; only
        the leader of the current view (view 1 -> leader 1) actually
        proposes. A no-op for everyone else."""
        if self.replica.is_leader():
            self._broadcast_proposal(self.replica.propose(self._next_payload()))

    def stop(self):
        self._running = False
        if self._server is not None:
            self._server.shutdown()
        self._senders.shutdown(wait=False)


def main():
    ap = argparse.ArgumentParser(description="Run one BFT validator node (isolated from the live O-Coin chain).")
    ap.add_argument("--index", type=int, required=True, help="this node's committee index")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--key-hex", required=True, help="this validator's BLS private key (hex)")
    ap.add_argument("--pubkeys", required=True, help="comma-separated committee pubkeys (hex), index order")
    ap.add_argument("--peers", required=True,
                    help="comma-separated base URLs, index order, e.g. http://127.0.0.1:7000,http://127.0.0.1:7001,...")
    ap.add_argument("--view-timeout", type=float, default=2.0)
    ap.add_argument("--kickoff", action="store_true", help="propose immediately if this node leads view 1")
    args = ap.parse_args()

    committee = Committee(args.pubkeys.split(","))
    peers = {i: url for i, url in enumerate(args.peers.split(","))}
    key = BftValidatorKey(private_key_int=int(args.key_hex, 16))
    node = BftNode(args.index, key, committee, peers, view_timeout_seconds=args.view_timeout)
    node.start(args.host, args.port)
    print(f"[bft-node {args.index}] listening on {args.host}:{args.port}, committee n={committee.n} f={committee.f}")
    if args.kickoff:
        time.sleep(1.0)  # give peers a moment to bind their ports first
        node.kickoff()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        node.stop()


if __name__ == "__main__":
    main()
