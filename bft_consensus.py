"""Chained HotStuff-style BFT consensus — a real, from-scratch
implementation of the actual protocol Hyperliquid's HyperBFT descends
from (HotStuff: Yin et al., "HotStuff: BFT Consensus in the Lens of
Blockchain"), not a simplified stand-in. Deliberately isolated from
blockchain.py/node.py: nothing here imports, or is imported by, the live
PoW/PoS chain — kept as a standalone, theorycraft-and-review-first
exploration until a real integration decision gets made.

Consensus family, for comparison against blockchain.py: this is BFT/
quorum-voting consensus, not Nakamoto consensus. Open-membership mining/
staking is replaced by a KNOWN, FIXED validator committee that votes
explicitly in rounds ("views"). Finality here is DETERMINISTIC — once a
block is committed (see BftReplica._try_advance_lock_and_commit's
3-chain check), it's final immediately, not "probably safe after N
confirmations" the way a PoW/PoS block is. That's the actual point of
building this: a genuinely different consensus family, not a variant of
the existing one.

Core mechanics, all present here, none hand-waved:
  - A ROTATING LEADER proposes one block per view, round-robin across the
    committee (Committee.leader_for_view).
  - Each block's `justify` field carries the Quorum Certificate (QC) for
    its PARENT — the "chained"/pipelined part of chained HotStuff. A QC
    is real cryptographic proof that >=2f+1 (of n=3f+1) validators signed
    the same (block_hash, view) — see bft_validator.py for why BLS makes
    this cheap (one constant-size aggregate signature) regardless of
    committee size.
  - SAFETY rule (BftReplica._safe_to_vote): a validator only votes for a
    proposal that extends its locked QC, UNLESS the proposal's own
    justify QC is from a later view than what's locked (the liveness
    escape hatch that lets the network recover after a view-change
    instead of a replica staying stuck forever on a stale lock). This is
    what makes two conflicting histories both finalizing impossible, as
    long as fewer than f of the n=3f+1 validators are Byzantine.
  - LIVENESS: a replica that sees no progress within view_timeout_seconds
    advances to the next view (and thus the next leader) on its own
    (maybe_advance_view) rather than stalling forever behind one
    unresponsive or malicious leader.
  - COMMIT rule, the real "three-chain": block B0 becomes committed the
    moment a replica observes B0 <- B1(justify=QC(B0)) <-
    B2(justify=QC(B1)) <- (a new proposal justified by QC(B2)), all at
    consecutive views. Seeing that fourth QC is what finalizes B0. This
    is what lets ordinary block proposals themselves double as the
    vote-carriers for the previous few blocks' phases, instead of
    needing separate all-to-all voting rounds per phase the way older
    BFT protocols (PBFT) require.

Honesty note: the three-chain commit rule above is reconstructed from the
HotStuff paper's description, not copied from a reference implementation
— correctness here rests on the real adversarial tests in
test_bft_consensus.py (a forced fork attempt, verifying the safety rule
actually blocks it) rather than on trusting memory of the paper alone.
"""
import hashlib
import json
import time

from py_ecc.bls import G2ProofOfPossession as bls

from bft_validator import BftValidatorKey


def _hash_dict(d: dict) -> str:
    return hashlib.sha256(json.dumps(d, sort_keys=True, default=str).encode()).hexdigest()


def _vote_message(block_hash: str, view: int) -> bytes:
    return f"{view}:{block_hash}".encode()


class BftBlock:
    GENESIS_HASH = "0" * 64

    def __init__(self, view, parent_hash, payload, proposer_pubkey_hex, justify=None):
        self.view = view
        self.parent_hash = parent_hash
        self.payload = payload  # deliberately generic (any JSON-serializable value) — see module docstring
        self.proposer_pubkey_hex = proposer_pubkey_hex
        self.justify = justify  # a QC's to_dict(), certifying parent_hash — None only for genesis
        self.hash = self.compute_hash()

    def compute_hash(self):
        return _hash_dict({
            "view": self.view, "parent_hash": self.parent_hash, "payload": self.payload,
            "proposer": self.proposer_pubkey_hex, "justify": self.justify,
        })

    def to_dict(self):
        return {
            "view": self.view, "parent_hash": self.parent_hash, "payload": self.payload,
            "proposer_pubkey_hex": self.proposer_pubkey_hex, "justify": self.justify, "hash": self.hash,
        }

    @staticmethod
    def from_dict(d):
        return BftBlock(d["view"], d["parent_hash"], d["payload"], d["proposer_pubkey_hex"], d["justify"])

    @staticmethod
    def genesis():
        # Every replica constructs this identically and trusts it
        # unconditionally, exactly once — same bootstrap reasoning
        # Blockchain()'s genesis block uses in blockchain.py. Note:
        # GENESIS_HASH ("0"*64) is the sentinel used as genesis's own
        # PARENT hash (meaning "no parent") — it is NOT the same value as
        # this block's own computed .hash (a real sha256 digest). See
        # GENESIS_BLOCK_HASH below for the latter.
        return BftBlock(0, BftBlock.GENESIS_HASH, None, None, justify=None)


# The genesis BLOCK's own computed hash (a real sha256 digest) — every
# replica derives the same one deterministically. This is what the
# bootstrap genesis QC's block_hash actually is (see BftReplica.__init__),
# and what on_receive_proposal checks against to know when it's safe to
# skip real signature verification — NOT BftBlock.GENESIS_HASH, which is
# a different value (the sentinel used as genesis's own *parent* hash).
GENESIS_BLOCK_HASH = BftBlock.genesis().hash


class QuorumCertificate:
    """Proof that >=2f+1 validators voted for the SAME (block_hash, view)
    pair. signer_indices records WHICH validators (by index into the
    committee's pubkey list) contributed — FastAggregateVerify has to be
    told exactly which public keys to sum; that can't be recovered from
    the aggregate signature alone."""

    def __init__(self, block_hash, view, signer_indices, agg_signature_hex):
        self.block_hash = block_hash
        self.view = view
        self.signer_indices = sorted(signer_indices)
        self.agg_signature_hex = agg_signature_hex

    def to_dict(self):
        return {
            "block_hash": self.block_hash, "view": self.view,
            "signer_indices": self.signer_indices, "agg_signature_hex": self.agg_signature_hex,
        }

    @staticmethod
    def from_dict(d):
        if d is None:
            return None
        return QuorumCertificate(d["block_hash"], d["view"], d["signer_indices"], d["agg_signature_hex"])

    def verify(self, committee: "Committee"):
        """Real verification — recomputes the exact message every
        claimed signer must have signed, and checks the aggregate
        against exactly those public keys. Nothing here is trusted just
        because it was already in a dict; a forged or under-quorum QC
        fails this."""
        if len(self.signer_indices) < committee.quorum_size():
            return False
        if len(set(self.signer_indices)) != len(self.signer_indices):
            return False  # no double-counting the same validator toward quorum
        try:
            pks = [bytes.fromhex(committee.pubkeys[i]) for i in self.signer_indices]
            sig = bytes.fromhex(self.agg_signature_hex)
        except (IndexError, ValueError, TypeError):
            return False
        message = _vote_message(self.block_hash, self.view)
        try:
            return bls.FastAggregateVerify(pks, message, sig)
        except Exception:
            return False


class Vote:
    def __init__(self, block_hash, view, voter_index, signature_hex):
        self.block_hash = block_hash
        self.view = view
        self.voter_index = voter_index
        self.signature_hex = signature_hex

    def to_dict(self):
        return {"block_hash": self.block_hash, "view": self.view,
                "voter_index": self.voter_index, "signature_hex": self.signature_hex}

    @staticmethod
    def from_dict(d):
        return Vote(d["block_hash"], d["view"], d["voter_index"], d["signature_hex"])


class Committee:
    """The known, fixed validator set for a given run — index-ordered,
    since QCs reference validators by index (constant-size regardless of
    committee size, same reasoning as the aggregate signature itself).
    Deliberately reconfigurable BY REPLACEMENT, not hardcoded to any
    specific size: going from 4 (f=1) validators today to 7 (f=2) or more
    later is a matter of constructing a new Committee with a longer
    pubkeys list, not a code change. The actual GOVERNANCE process for
    doing that safely and live (an in-protocol reconfiguration command,
    agreed on via consensus itself) is real, unbuilt future work — out of
    scope for this isolated v1, which assumes the committee is fixed for
    the duration of a run."""

    def __init__(self, pubkeys_hex):
        self.pubkeys = list(pubkeys_hex)
        self.n = len(self.pubkeys)
        if self.n < 4:
            raise ValueError("BFT needs at least n=4 validators (f=1) to tolerate any Byzantine fault at all")
        self.f = (self.n - 1) // 3  # standard bound: n = 3f+1

    def quorum_size(self):
        return 2 * self.f + 1

    def leader_for_view(self, view):
        return view % self.n

    def index_of(self, pubkey_hex):
        try:
            return self.pubkeys.index(pubkey_hex)
        except ValueError:
            return None


class BftReplica:
    """One validator's local state machine. Pure logic — no networking,
    no threads. Driving several of these directly from Python (see
    test_bft_consensus.py) is deliberate: prove the protocol logic
    itself is correct before any network/HTTP layer (bft_node.py — not
    yet built) gets added on top of it."""

    def __init__(self, my_index, my_key: BftValidatorKey, committee: Committee, view_timeout_seconds=10):
        self.my_index = my_index
        self.my_key = my_key
        self.committee = committee
        self.view_timeout_seconds = view_timeout_seconds

        genesis = BftBlock.genesis()
        self.blocks = {genesis.hash: genesis}  # hash -> BftBlock, every valid block ever seen
        genesis_qc = QuorumCertificate(genesis.hash, 0, [], None)  # bootstrap-trusted, not a real signature
        self.high_qc = genesis_qc
        self.locked_qc = genesis_qc
        self.current_view = 1
        self.committed = [genesis.hash]  # ordered list of committed block hashes
        self.pending_votes = {}  # (block_hash, view) -> {voter_index: signature_hex} — only populated while collecting as next leader
        self.pending_new_views = {}  # view -> {sender_index: NewViewMsg} — only populated while collecting as the incoming leader after a view-change
        # view -> block_hash this replica already voted for. THE single
        # most safety-critical piece of state a HotStuff replica keeps —
        # BFT safety's whole overlap argument (any two quorums of 2f+1
        # out of n=3f+1 share at least one honest validator) only holds
        # if an honest validator never signs a second, conflicting vote
        # for a view it already voted in. Without this, a Byzantine
        # leader could equivocate (send different proposals for the same
        # view to different replicas) and get two conflicting blocks
        # each honestly voted into existence, defeating the entire point
        # of the protocol.
        self.voted_views = {}

    # ── Proposing ────────────────────────────────────────────────────
    def is_leader(self, view=None):
        view = self.current_view if view is None else view
        return self.committee.leader_for_view(view) == self.my_index

    def propose(self, payload):
        """Only meaningful when is_leader(self.current_view). Extends the
        highest-QC'd block this replica knows about, justified by that
        QC — the pipelining step that lets a normal proposal also serve
        as the previous blocks' next vote phase."""
        parent_hash = self.high_qc.block_hash
        block = BftBlock(self.current_view, parent_hash, payload, self.my_key.public_key_hex(), justify=self.high_qc.to_dict())
        return block

    # ── Voting (safety) ──────────────────────────────────────────────
    def _extends(self, block_hash, ancestor_hash):
        """Walks the block tree backward via parent_hash — True if
        ancestor_hash is block_hash itself or a real ancestor of it, per
        what this replica has actually seen. A bounded walk (not an
        index), a fine v1 simplification — a real deployment would keep
        a height index instead of walking on every safety check."""
        h = block_hash
        steps = 0
        while h in self.blocks and steps < 100_000:
            if h == ancestor_hash:
                return True
            h = self.blocks[h].parent_hash
            steps += 1
        return h == ancestor_hash

    def _safe_to_vote(self, block: BftBlock, justify_qc: QuorumCertificate):
        # block itself isn't stored in self.blocks yet at this point (it
        # only gets added once this whole check passes) — so the ancestry
        # walk has to start from its PARENT, with block.hash==ancestor
        # handled as its own immediate (trivial) case.
        extends_locked = block.hash == self.locked_qc.block_hash or self._extends(block.parent_hash, self.locked_qc.block_hash)
        qc_is_newer = justify_qc.view > self.locked_qc.view
        return extends_locked or qc_is_newer

    def on_receive_proposal(self, block: BftBlock):
        """Returns a Vote to send to the next leader if this proposal is
        accepted, else None — an invalid/unsafe proposal simply never
        gets this replica's vote; there's no separate reject message in
        HotStuff, only voting or withholding a vote."""
        if block.view != self.current_view:
            return None  # only ever vote for the currently-live view
        already_voted_for = self.voted_views.get(block.view)
        if already_voted_for is not None and already_voted_for != block.hash:
            return None  # equivocation guard — see voted_views' docstring in __init__
        proposer_idx = self.committee.index_of(block.proposer_pubkey_hex)
        if proposer_idx is None or self.committee.leader_for_view(block.view) != proposer_idx:
            return None  # not this view's rightful leader
        if block.parent_hash not in self.blocks:
            # Never vote for a proposal whose parent this replica doesn't
            # already have stored locally — a replica that previously
            # rejected some earlier block (e.g. it didn't extend what was
            # locked at the time) never added it to self.blocks. Voting
            # for a LATER block built on that missing parent anyway (the
            # liveness escape hatch below allows exactly this, on a newer
            # QC) would leave this replica's own block tree with a real
            # gap in it — able to vote for a descendant while permanently
            # missing an ancestor, breaking every future ancestry walk
            # (_extends, the 3-chain commit check) for this replica.
            # Caught via real multi-replica testing, not theoretical: a
            # skipped-leader scenario reproduced this exact gap. The
            # correct real fix is a block-sync/catch-up step (fetch
            # missing ancestors from peers before voting) — real, needed,
            # unbuilt future work; refusing to vote here is the safe
            # fallback until that exists, not a permanent design choice.
            return None

        justify_qc = QuorumCertificate.from_dict(block.justify)
        if justify_qc is None or justify_qc.block_hash != block.parent_hash:
            return None  # justify must certify the block's own claimed parent
        if justify_qc.block_hash != GENESIS_BLOCK_HASH and not justify_qc.verify(self.committee):
            return None
        if not self._safe_to_vote(block, justify_qc):
            return None

        self.blocks[block.hash] = block
        self._apply_qc(justify_qc)

        signature = self.my_key.sign(_vote_message(block.hash, block.view))
        self.voted_views[block.view] = block.hash
        return Vote(block.hash, block.view, self.my_index, signature.hex())

    def _apply_qc(self, qc: QuorumCertificate):
        """Shared handling for 'this replica has now seen strong (2f+1)
        evidence for a block' — true whether that evidence arrived
        embedded in someone else's proposal (on_receive_proposal) or was
        just assembled locally out of collected votes (on_receive_vote).
        Either way it updates high_qc and re-checks the commit rule."""
        if qc.view > self.high_qc.view:
            self.high_qc = qc
        self._try_advance_lock_and_commit(qc)

    def _try_advance_lock_and_commit(self, justify_qc: QuorumCertificate):
        """The three-chain commit rule. justify_qc certifies this
        proposal's PARENT, call it B2. B2's own justify certifies B1.
        B1's own justify certifies B0. If B0<-B1<-B2 are at consecutive
        views (no gap from a skipped/failed view), B0 — and everything
        back to the last previously-committed block — is now final."""
        b2 = self.blocks.get(justify_qc.block_hash)
        if justify_qc.view > self.locked_qc.view:
            self.locked_qc = justify_qc  # "pre-commit": b2 is now locked
        if b2 is None or b2.justify is None:
            return
        qc1 = QuorumCertificate.from_dict(b2.justify)
        b1 = self.blocks.get(qc1.block_hash)
        if b1 is None or b1.justify is None:
            return
        qc0 = QuorumCertificate.from_dict(b1.justify)
        b0 = self.blocks.get(qc0.block_hash)
        if b0 is None:
            return
        consecutive = (b1.view == b0.view + 1) and (b2.view == b1.view + 1) and (justify_qc.view == b2.view)
        if consecutive and b0.hash not in self.committed:
            self._commit_chain_up_to(b0.hash)

    def _commit_chain_up_to(self, block_hash):
        """Walks back from block_hash to the last already-committed
        ancestor, marking everything in between committed in order — a
        real chained commit finalizes a whole run of blocks the first
        time a 3-chain confirms them, not just the newest one."""
        chain = []
        h = block_hash
        while h not in self.committed and h in self.blocks:
            chain.append(h)
            h = self.blocks[h].parent_hash
        for h in reversed(chain):
            self.committed.append(h)

    # ── Vote collection (only matters while collecting as next leader) ──
    def on_receive_vote(self, vote: Vote):
        """Returns a freshly-formed QuorumCertificate the moment enough
        votes have accumulated for (vote.block_hash, vote.view), else
        None. A vote for anything this replica isn't currently
        collecting for is simply not relevant, not an error.

        Every individual vote is verified against its OWN claimed
        voter's public key before ever being counted — this matters far
        more here than it might look. BLS aggregate verification is
        all-or-nothing: FastAggregateVerify fails if even ONE signature
        among the aggregated set is wrong, for any reason. Skipping
        per-vote verification would mean a single Byzantine replica could
        submit one bogus 'vote' and silently poison the entire resulting
        QC — the leader would believe it formed a valid quorum, propose
        from it, and have every honest replica reject the proposal
        (QuorumCertificate.verify fails), wasting the round. Repeated
        every time that replica's vote gets included, this is a real,
        repeatable liveness-breaking attack, not a theoretical one —
        confirmed by directly constructing exactly this scenario before
        this fix existed."""
        key = (vote.block_hash, vote.view)
        try:
            pk = bytes.fromhex(self.committee.pubkeys[vote.voter_index])
            sig = bytes.fromhex(vote.signature_hex)
        except (IndexError, ValueError):
            return None
        if not bls.Verify(pk, _vote_message(vote.block_hash, vote.view), sig):
            return None  # bad/forged vote — never counted, never gets near the aggregate

        bucket = self.pending_votes.setdefault(key, {})
        bucket[vote.voter_index] = vote.signature_hex
        if len(bucket) < self.committee.quorum_size():
            return None
        signer_indices = sorted(bucket.keys())
        sigs = [bytes.fromhex(bucket[i]) for i in signer_indices]
        agg = bls.Aggregate(sigs)
        qc = QuorumCertificate(vote.block_hash, vote.view, signer_indices, agg.hex())
        del self.pending_votes[key]
        self._apply_qc(qc)
        return qc

    # ── Liveness ─────────────────────────────────────────────────────
    def maybe_advance_view(self, last_progress_time):
        """Call periodically against a caller-tracked last-progress
        timestamp (a real deployment would tie this to a timer/thread —
        see bft_node.py, not yet built). Returns True (and advances the
        view, rotating to the next leader) if too long has passed with
        no progress, so one unresponsive or malicious leader can't stall
        the network forever."""
        if time.time() - last_progress_time > self.view_timeout_seconds:
            self.current_view += 1
            return True
        return False

    def advance_to_view(self, view):
        """Explicit view advance — used by the test/simulation harness
        to move every replica forward together once a round completes,
        independent of maybe_advance_view's wall-clock timeout path."""
        if view > self.current_view:
            self.current_view = view

    def make_new_view(self):
        """Send this to the leader of self.current_view whenever a
        timeout fires (maybe_advance_view returning True) — carries this
        replica's own high_qc so the incoming leader can propose from the
        best QC *anyone* in the committee actually has, not just whatever
        it personally collected. Without this, a leader that missed out
        on collecting some other replica's already-formed QC (e.g. it
        wasn't the one who happened to gather that round's votes) would
        silently propose on top of stale history — real committee work
        wasted, not a safety violation (the safety rule still protects
        correctness) but a real, avoidable liveness/efficiency cost.
        Found via direct testing, not just theory: a forced-stall
        scenario showed a new leader building on a 1-view-stale parent
        while another replica already held a strictly better QC that
        never reached it.

        Signed over (view, high_qc's block_hash+view) and carries
        my_index — both are load-bearing, not decoration. Without a
        signature binding a specific sender to a specific claim, a
        replayed or relabeled copy of one real message could be counted
        as if it came from a different (or the same, repeatedly) sender;
        on_receive_new_view needs real per-sender identity to correctly
        require 2f+1 DISTINCT senders, the same way on_receive_vote
        already does via voter_index."""
        signature = self.my_key.sign(_new_view_message(self.current_view, self.high_qc.block_hash, self.high_qc.view))
        return NewViewMsg(self.current_view, self.high_qc.to_dict(), self.my_index, signature.hex())

    def on_receive_new_view(self, msg: "NewViewMsg"):
        """Collects NewView messages (only meaningful while this replica
        is about to lead msg.view). Once quorum_size() DISTINCT senders
        have responded, adopts the HIGHEST *verified* QC among their
        claims (via _apply_qc, same as vote-collection) — that's what
        makes it safe and efficient for propose() to just read
        self.high_qc afterward: by the time propose() runs, it already
        reflects the best-known state across whoever actually responded,
        not just this one replica's own view of the world.

        Two independent checks here, both confirmed necessary via direct
        testing, not assumed: (1) the message's own signature is verified
        against its claimed sender_index BEFORE counting it — otherwise
        one real message replayed under a relabeled/duplicated sender
        claim could fake quorum from a single distinct sender (confirmed:
        three copies of one real replica's message satisfied quorum_size
        before this fix). (2) each embedded high_qc is independently
        verified before being trusted — otherwise a Byzantine replica
        could fabricate a NewView carrying an arbitrary nonexistent QC
        (confirmed: a forged view=9999 QC got adopted outright before
        this check existed). Both attacks are real and distinct; fixing
        only one leaves the other open."""
        try:
            pk = bytes.fromhex(self.committee.pubkeys[msg.sender_index])
            sig = bytes.fromhex(msg.signature_hex)
        except (IndexError, ValueError):
            return False
        expected_message = _new_view_message(msg.view, msg.high_qc["block_hash"], msg.high_qc["view"])
        if not bls.Verify(pk, expected_message, sig):
            return False  # forged sender claim, or tampered content — never counted

        bucket = self.pending_new_views.setdefault(msg.view, {})
        bucket[msg.sender_index] = msg
        if len(bucket) < self.committee.quorum_size():
            return False
        del self.pending_new_views[msg.view]
        valid_qcs = []
        for m in bucket.values():
            qc = QuorumCertificate.from_dict(m.high_qc)
            if qc.block_hash == GENESIS_BLOCK_HASH or qc.verify(self.committee):
                valid_qcs.append(qc)
        if not valid_qcs:
            return False
        best = max(valid_qcs, key=lambda qc: qc.view)
        self._apply_qc(best)
        return True


def _new_view_message(view, high_qc_block_hash, high_qc_view) -> bytes:
    return f"newview:{view}:{high_qc_block_hash}:{high_qc_view}".encode()


class NewViewMsg:
    def __init__(self, view, high_qc_dict, sender_index, signature_hex):
        self.view = view
        self.high_qc = high_qc_dict
        self.sender_index = sender_index
        self.signature_hex = signature_hex
