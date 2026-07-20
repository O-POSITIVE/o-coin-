"""The O-Coin node — an always-on HTTP server that IS the blockchain, in
the sense that matters: it holds a copy of the chain, accepts new
transactions into its mempool, hands out mining templates, accepts
completed blocks from miners, and syncs with other nodes.

Run one of these per participant, same as any real chain — right now
"participant" realistically means you, maybe on more than one machine,
but the node/miner split (this file talks to miner.py over HTTP, never
in-process) means someone else running their own node and pointing a
miner at it works exactly the same way, with zero code changes needed on
either side. That's not a hypothetical nicety — it's the actual
mechanism that made Dogecoin (and every real PoW chain) work as more than
just its creator's own machine.

Two upgrades in this file specifically, on top of blockchain.py's own
(see that file's docstring for fees/retargeting/fee-priority/validation):
  - SCALABLE storage: each block is one SQLite row, appended once and
    never rewritten — saving stays fast (O(1) per block) no matter how
    long the chain gets, instead of re-serializing the entire chain to
    one JSON file on every single block (which gets slower forever as
    the chain grows).
  - FAST propagation: when this node mines or accepts a new block, it
    immediately pushes it to every registered peer's /blocks/receive
    (fire-and-forget, doesn't block the response) instead of waiting for
    someone to eventually call /nodes/resolve. Peers that are already
    caught up accept it in one hop; a peer that's behind or has a
    conflicting block falls back to the full longest-chain resolution
    automatically.

Run it:
    pip install -r requirements.txt
    python node.py                  # defaults to port 5100
    python node.py --port 5101      # run a second node locally, to test sync
"""
import argparse
import json
import os
import re
import threading
import time

# Same fix trading-platform's server.py carries: this development machine's
# network security software intercepts TLS with a certificate that's in the
# OS trust store but not Python's bundled CA list, so any HTTPS call from a
# locally-run node (e.g. syncing from a hosted peer via OCOIN_PEERS) fails
# certificate verification without this. Harmless no-op on Render/Linux.
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

import psycopg2
import psycopg2.extras
import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from blockchain import Block, Blockchain
from transaction import Transaction

# Loads DATABASE_URL/OCOIN_NODE_SHARED_SECRET from a local .env file when
# running `python node.py` directly (e.g. Start Mining.bat) — same
# convention trading-platform's server.py uses. On Render, real env vars are
# already set directly and this is a harmless no-op (no .env file deployed).
load_dotenv()

app = Flask(__name__)
# Per-IP rate limiting (decentralization phase D2) on the now-public gossip /
# write routes only — reads and mining stay unthrottled (no default limit).
# Behind Render's proxy the real client IP is the LEFTMOST entry of
# X-Forwarded-For. request.remote_addr (and ProxyFix's rightmost pick) is a
# ROTATING Render edge address, so keying on it makes every request look like a
# fresh client and the per-IP counter never accumulates — that's why the first
# D2 deploy's limiter silently never fired (13 hits at a 10/min cap, zero 429s
# in production). Keying on XFF[0] fixes it; fall back to remote_addr for
# direct/local calls with no proxy header. In-memory storage is correct: each
# node is a single process.
def _rate_limit_key():
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else get_remote_address()

limiter = Limiter(key_func=_rate_limit_key, app=app)
chain_lock = threading.Lock()  # guards every mutation below — a node is a single shared blockchain instance, and mining/tx-submission/sync/gossip can all race against each other without this
blockchain = Blockchain()
peers = set()  # other nodes' base URLs, e.g. "http://localhost:5101" — registered by hand for now, see README's roadmap for real peer discovery

# ── Persistence: Supabase Postgres, not local SQLite ────────────────────────
# A local chain_data_<port>.db file gets silently wiped on any host with an
# ephemeral filesystem (confirmed the hard way once already in this account,
# via trading-platform's candle-storage bug — same root cause, same fix).
# Reuses the exact DATABASE_URL/connect_timeout pattern trading-platform's
# server.py already uses in production, and keeps the file-based design's
# "one table per port" trick so two local nodes started for sync-testing
# still get independent chains instead of silently sharing rows.
DATABASE_URL = os.getenv("DATABASE_URL")
BLOCKS_TABLE = None  # set from --port in __main__; see init_db()/save_block()/load_chain() below

# ── Shared-secret gate ───────────────────────────────────────────────────────
# This node has no other auth/rate-limiting (see README's roadmap). In
# production it should only ever be called by trading-platform's server.py,
# proxying already-authenticated/rate-limited requests — this header is what
# actually enforces that "only Flask calls this" in practice, not just in
# intent. Optional (only enforced if the env var is set) so local dev/testing
# is unaffected.
NODE_SHARED_SECRET = os.getenv("OCOIN_NODE_SHARED_SECRET")
# Decentralization phase D3. /mine (in-process PoW search) and /pos/stake
# (manual single stake attempt) run heavy work inside the node's own process —
# a CPU-DoS lever on a public node, and real mining/staking never need them
# (use /mining/template + miner.py, and node.py --stake). They are now OFF by
# default and return 403; set OCOIN_ENABLE_LOCAL_MINE=true only on a local/dev
# node that deliberately wants them. This retires the last thing the shared
# secret meaningfully guarded on the node — after D1/D2, sync/gossip/reads are
# all public, so the secret's remaining job was gating exactly these two
# conveniences; disabling them by default makes the node safe even if the
# secret is unset or shared.
LOCAL_MINE_ENABLED = os.getenv("OCOIN_ENABLE_LOCAL_MINE", "").strip().lower() in ("1", "true", "yes", "on")
# /status: left open for an external keep-alive pinger; no sensitive data.
# /mining/template, /mining/submit: opened deliberately (2026-07-11) so
# anyone running the public miner.py download can actually reach the
# node directly, not just trading-platform's own server — this is the
# intended "public mining" front door, not an oversight. Safe to open:
# a submitted block still has to satisfy real proof-of-work and pass
# full chain validation to be accepted, same as any other miner talking
# to any other node on any real chain. Every other route (transactions,
# pool payouts, peer/node management) stays behind the shared secret.
# Routes anyone can call WITHOUT the operator's shared secret. Keyed on the
# Flask endpoint (view-function name), not the raw path, so parameterized
# routes like /balance/<address> and /blocks/<idx> are covered by one entry.
#
# Decentralization rollout (see DECENTRALIZATION.md). The secret is an ACCESS
# gate, not the consensus gate — every write path re-validates from scratch
# (mining/submit already runs untrusted blocks through accept_block), so
# reading public chain data needs no secret.
#   Phase D1 (DONE): all READ routes + pool mining are public, so anyone can
#     run a node that fully syncs from the live network and mine it.
#   Phase D2 (DONE): the gossip writes — new_transaction, receive_block,
#     register_nodes, resolve_conflicts — are public behind per-IP rate
#     limiting (see @limiter.limit on each) + a bounded mempool
#     (Blockchain.MEMPOOL_MAX), letting independent nodes fully peer. Each is
#     still fully re-validated (signature/fee/PoW), so the secret was never
#     what protected them.
#   Still gated (D3): mine_here (/mine) and stake_here (/pos/stake) are
#     CPU-DoS-prone operator conveniences that real mining/staking never need.
PUBLIC_ENDPOINTS = {
    # already public before the rollout
    "status", "mining_template", "mining_submit",
    # D1 — reads
    "get_chain", "get_balance", "pending_transactions",
    "pool_status", "pos_status", "stake_pool_status",
    "list_pools", "amm_pool_status",
    "blocks_page", "block_detail", "address_transactions",
    "stake_pool_history", "amm_pool_history",
    # D1 — pool mining (mirrors the already-public solo-mining endpoints)
    "pool_template", "pool_submit_share",
    # D2 — gossip/write, each rate-limited + fully re-validated
    "new_transaction", "receive_block", "register_nodes", "resolve_conflicts",
}


@app.before_request
def _require_shared_secret():
    if not NODE_SHARED_SECRET or request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if request.headers.get("X-Node-Auth") != NODE_SHARED_SECRET:
        return jsonify({"status": "failed", "reason": "Unauthorized"}), 401

# ── Mining pool state ───────────────────────────────────────────────────
# Shares are credited to `pool_pending_shares` as they come in during the
# CURRENT round. That tally only becomes a payout basis once the round's
# block is actually found — at which point it's promoted to
# `pool_payout_shares` and baked into the coinbase of the block templates
# for the NEXT round. This one-round delay is deliberate, not an
# oversight: the payout list has to be fixed (and merkle-committed)
# before any miner starts searching for a nonce, so it can't possibly be
# based on shares still being collected for the block being mined right
# now — see build_pool_block's docstring in blockchain.py.
pool_payout_shares = {}   # {address: share_count} — fixed basis for the CURRENT round's coinbase
pool_pending_shares = {}  # {address: share_count} — accumulating now, becomes next round's payout basis
POOL_SHARE_TARGET_MULTIPLIER = 8  # a share is valid work at 1/8th the real network difficulty


def get_pg():
    # connect_timeout matters: psycopg2 has no default connect timeout at
    # all, so a hung TCP-connect (a network blip between this node's host
    # and Supabase) blocks the calling thread forever instead of raising —
    # see trading-platform's server.py get_pg() / the candle-sync hang
    # incident this same fix already resolved once.
    return psycopg2.connect(DATABASE_URL, connect_timeout=10)


def init_db():
    conn = get_pg()
    try:
        cur = conn.cursor()
        cur.execute(f"CREATE TABLE IF NOT EXISTS {BLOCKS_TABLE} (idx INTEGER PRIMARY KEY, data JSONB NOT NULL)")
        conn.commit()
    finally:
        conn.close()


def save_block(block: Block):
    """One INSERT per block — O(1) regardless of chain length, unlike
    rewriting a single ever-growing JSON file on every block."""
    conn = get_pg()
    try:
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO {BLOCKS_TABLE} (idx, data) VALUES (%s, %s) "
            "ON CONFLICT (idx) DO UPDATE SET data = EXCLUDED.data",
            (block.index, psycopg2.extras.Json(block.to_dict())),
        )
        conn.commit()
    finally:
        conn.close()


def save_full_chain():
    """Used only after a chain replacement (peer sync adopted a longer
    chain) — that's the one case where more than one block changes at
    once, so a bulk rewrite is actually the right tool, not the default."""
    conn = get_pg()
    try:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM {BLOCKS_TABLE}")
        psycopg2.extras.execute_batch(
            cur,
            f"INSERT INTO {BLOCKS_TABLE} (idx, data) VALUES (%s, %s)",
            [(b.index, psycopg2.extras.Json(b.to_dict())) for b in blockchain.chain],
        )
        conn.commit()
    finally:
        conn.close()


def load_chain():
    init_db()
    conn = get_pg()
    try:
        cur = conn.cursor()
        # idx > 0: genesis is never written to the DB at all (Blockchain()
        # always regenerates an identical one deterministically in __init__ —
        # same index, same all-zero previous_hash, same fixed timestamp/nonce
        # — so there's nothing to persist there). Only blocks 1+ are real
        # history worth loading.
        cur.execute(f"SELECT data FROM {BLOCKS_TABLE} WHERE idx > 0 ORDER BY idx ASC")
        rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        return
    loaded_blocks = [Block.from_dict(r[0] if isinstance(r[0], dict) else json.loads(r[0])) for r in rows]
    candidate = [blockchain.chain[0]] + loaded_blocks
    if blockchain.is_chain_valid(candidate):
        blockchain.chain = candidate
        blockchain._rebuild_balance_index()
        # Pick each target from the last block of ITS OWN kind, not just
        # candidate[-1] — the tip could be either a PoW or a PoS block,
        # and blindly reading .target off whichever one happens to be
        # last would silently corrupt the other difficulty (same fix as
        # Blockchain.replace_chain, needed here for the same reason).
        last_pow = next((b for b in reversed(candidate) if b.staker_address is None), None)
        last_pos = next((b for b in reversed(candidate) if b.staker_address is not None), None)
        if last_pow is not None:
            blockchain.current_target = last_pow.target
        if last_pos is not None:
            blockchain.pos_target = last_pos.target
        print(f"Loaded {len(candidate)} blocks from {BLOCKS_TABLE}")
    else:
        print(f"WARNING: {BLOCKS_TABLE} failed validation, starting from genesis instead")


def _peer_headers():
    """Every peer-to-peer call needs the SAME shared-secret header a
    trusted client (trading-platform's server.py) sends — peer nodes are
    assumed to be other trusted members of one private cluster all
    configured with the same OCOIN_NODE_SHARED_SECRET, not arbitrary
    public nodes. Track A, Phase A6 found this was missing on BOTH
    peer-sync paths below (broadcast_block AND _resolve_with_peers) via a
    real two-node HTTP test — /blocks/receive and /chain both sit behind
    _require_shared_secret, so peer sync was silently 401ing on itself
    the moment a secret was ever configured, for every path, not just one."""
    return {"X-Node-Auth": NODE_SHARED_SECRET} if NODE_SHARED_SECRET else {}


def broadcast_block(block: Block):
    """Fire-and-forget push to every known peer — short timeout, errors
    swallowed, since a slow/offline peer should never hold up this node's
    own response to whoever just mined the block. A peer that misses the
    broadcast entirely (was offline) still catches up next time anyone
    calls /nodes/resolve, so this is a speed optimization, not a
    correctness dependency."""
    payload = block.to_dict()
    headers = _peer_headers()
    for peer in list(peers):
        def _send(url=peer):
            try:
                requests.post(f"{url}/blocks/receive", json=payload, headers=headers, timeout=2)
            except requests.RequestException:
                pass
        threading.Thread(target=_send, daemon=True).start()


@app.route("/status")
def status():
    return jsonify({
        "chain_length": len(blockchain.chain),
        "current_target": blockchain.current_target,
        "pos_target": blockchain.pos_target,
        "target_block_time": blockchain.TARGET_BLOCK_TIME,
        "current_reward": blockchain.reward_at_height(blockchain.latest_block.index + 1),
        "current_pos_reward": round(blockchain.reward_at_height(blockchain.latest_block.index + 1) * blockchain.POS_REWARD_FRACTION, 6),
        "mempool_size": len(blockchain.mempool),
        "peers": sorted(peers),
        "latest_block_hash": blockchain.latest_block.compute_hash(),
    })


_chain_cache = {"key": None, "body": None}

@app.route("/chain")
def get_chain():
    # Now a PUBLIC route (D1), so serialize the whole chain at most once per
    # chain change instead of on every hit — otherwise repeated /chain calls
    # would re-serialize hundreds of blocks each time, an easy amplification
    # DoS. Keyed on (height, tip hash) so a reorg that keeps the same length
    # still invalidates. Peer sync still receives the full chain unchanged.
    with chain_lock:
        n = len(blockchain.chain)
        tip = blockchain.latest_block.compute_hash() if n else None
        key = (n, tip)
        if _chain_cache["key"] != key:
            _chain_cache["key"] = key
            _chain_cache["body"] = json.dumps({"length": n, "chain": [b.to_dict() for b in blockchain.chain]})
        body = _chain_cache["body"]
    return app.response_class(body, mimetype="application/json")


@app.route("/balance/<address>")
def get_balance(address):
    """?asset_id=... (optional, default "OCN") — Track A, Phase A7. Without
    this, there was no way to check a stOCN/LP balance via the API at all,
    only aggregate pool-wide figures from /stake_pool/status or
    /pools/<pool_key>. Defaults to "OCN" so every existing caller (nothing
    passes asset_id today) gets byte-identical behavior to before."""
    asset_id = request.args.get("asset_id", "OCN")
    with chain_lock:
        return jsonify({
            "address": address,
            "asset_id": asset_id,
            "balance": blockchain.get_balance(address, asset_id=asset_id),
            "balance_with_pending": blockchain.get_balance(address, asset_id=asset_id, include_pending=True),
        })


@app.route("/transactions/pending")
def pending_transactions():
    return jsonify({"pending": [tx.to_dict() for tx in blockchain.mempool]})


@app.route("/transactions/new", methods=["POST"])
@limiter.limit("30 per minute")  # D2: public tx submission, per-IP flood cap
def new_transaction():
    body = request.get_json(silent=True) or {}
    required = ("sender", "recipient", "amount", "public_key", "signature")
    if not all(k in body for k in required):
        return jsonify({"status": "failed", "reason": f"Missing fields, need: {required}"}), 400
    tx = Transaction(
        body["sender"], body["recipient"], body["amount"], body.get("fee"),
        body["public_key"], body["signature"], body.get("timestamp"),
        body.get("op"), body.get("op_data"),
    )
    with chain_lock:
        try:
            tx_hash = blockchain.add_transaction(tx)
        except ValueError as e:
            return jsonify({"status": "failed", "reason": str(e)}), 400
    return jsonify({"status": "ok", "transaction_hash": tx_hash})


@app.route("/mining/template")
def mining_template():
    """What a real, external miner (miner.py) needs to start searching
    for a valid nonce: the previous block's hash, this block's would-be
    index, the transactions to include (already committed via the merkle
    root, so the miner can't quietly swap in different ones), and the
    difficulty target to search against."""
    miner_address = request.args.get("miner_address")
    if not miner_address:
        return jsonify({"error": "miner_address query param is required"}), 400
    with chain_lock:
        block = blockchain.build_candidate_block(miner_address)
    return jsonify({
        "index": block.index,
        "previous_hash": block.previous_hash,
        "merkle_root": block.merkle_root,
        "timestamp": block.timestamp,
        "transactions": [tx.to_dict() for tx in block.transactions],
        "target": block.target,
    })


@app.route("/mining/submit", methods=["POST"])
def mining_submit():
    """A miner found a valid nonce for a template it fetched earlier and
    is submitting the completed block. Re-validates everything from
    scratch server-side — a node never trusts a miner's own claim that a
    block is valid, the same way it never trusts a peer's claimed chain
    without independently checking it in /nodes/resolve below."""
    body = request.get_json(silent=True) or {}
    required = ("index", "previous_hash", "merkle_root", "timestamp", "transactions", "target", "nonce")
    if not all(k in body for k in required):
        return jsonify({"status": "failed", "reason": f"Missing fields, need: {required}"}), 400
    block = Block(
        body["index"],
        [Transaction.from_dict(t) for t in body["transactions"]],
        body["previous_hash"],
        body["target"],
        body["timestamp"],
        body["nonce"],
    )
    if block.merkle_root != body["merkle_root"]:
        return jsonify({"status": "failed", "reason": "merkle_root does not match the submitted transactions — template was tampered with"}), 400
    with chain_lock:
        try:
            blockchain.accept_block(block)
            save_block(block)
        except ValueError as e:
            return jsonify({"status": "failed", "reason": str(e)}), 400
    broadcast_block(block)
    return jsonify({"status": "ok", "block_hash": block.compute_hash(), "index": block.index})


@app.route("/pool/template")
def pool_template():
    """Same shape/contract as /mining/template, except the coinbase is
    already split across the previous round's contributors instead of
    paying a single miner_address — a pool participant doesn't choose
    who gets paid, the round's already-closed share tally does. Bootstrap
    case: before any round has ever completed, there's no prior share
    tally to pay out from, so the very first pool round behaves like a
    plain solo block, paid to the chain's own genesis/premine address —
    round 2 onward always has a real tally (last round always adds at
    least the winning share itself) so this fallback only ever fires once
    per node's lifetime."""
    with chain_lock:
        shares = pool_payout_shares or {Blockchain.GENESIS_PREMINE_ADDRESS: 1}
        block = blockchain.build_pool_block(shares)
        share_target = min(block.target * POOL_SHARE_TARGET_MULTIPLIER, 2**256 - 1)
        payload = {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "merkle_root": block.merkle_root,
            "timestamp": block.timestamp,
            "target": block.target,
            "share_target": share_target,
            "transactions": [t.to_dict() for t in block.transactions],
            "payout_basis": shares,
        }
    return jsonify(payload)


@app.route("/pool/submit_share", methods=["POST"])
def pool_submit_share():
    """A pool participant found a nonce meeting at least the (easier)
    share_target. Every field here is echoed back exactly as received
    from /pool/template, mirroring /mining/submit's stateless
    re-derive-and-verify pattern — the node never trusts a miner's own
    claim, it recomputes merkle_root and the hash itself. `address` is
    whose tally the share gets credited to. If the nonce is good enough
    to ALSO meet the full network target, this share is simultaneously a
    winning block: it's accepted onto the chain immediately and the
    round rolls over (this round's shares, including the winning one,
    become the payout basis for the next round's coinbase)."""
    global pool_payout_shares, pool_pending_shares
    body = request.get_json(silent=True) or {}
    required = ("index", "previous_hash", "merkle_root", "timestamp", "transactions", "target", "nonce", "address")
    if not all(k in body for k in required):
        return jsonify({"status": "failed", "reason": f"Missing fields, need: {required}"}), 400
    address = body["address"]
    block = Block(
        body["index"], [Transaction.from_dict(t) for t in body["transactions"]],
        body["previous_hash"], body["target"], body["timestamp"], body["nonce"],
    )
    if block.merkle_root != body["merkle_root"]:
        return jsonify({"status": "failed", "reason": "merkle_root does not match the submitted transactions — template was tampered with"}), 400
    share_target = min(block.target * POOL_SHARE_TARGET_MULTIPLIER, 2**256 - 1)
    block_hash_int = int(block.compute_hash(), 16)
    if block_hash_int >= share_target:
        return jsonify({"status": "failed", "reason": "hash does not meet the (easier) share target"}), 400

    won_block = False
    with chain_lock:
        pool_pending_shares[address] = pool_pending_shares.get(address, 0) + 1
        if block_hash_int < block.target:
            try:
                blockchain.accept_block(block)
                save_block(block)
                won_block = True
                pool_payout_shares = pool_pending_shares
                pool_pending_shares = {}
            except ValueError as e:
                # Hash met the full target, but someone else's block (pool
                # or solo) already advanced the chain out from under this
                # one — the share above still counts, it just isn't also
                # a block win. Not an error from the miner's perspective.
                return jsonify({"status": "ok", "share_accepted": True, "won_block": False, "reason": str(e)})
    if won_block:
        broadcast_block(block)
    return jsonify({
        "status": "ok", "share_accepted": True, "won_block": won_block,
        "block_index": block.index if won_block else None,
    })


@app.route("/pool/status")
def pool_status():
    with chain_lock:
        return jsonify({
            "current_round_payout_basis": pool_payout_shares or {Blockchain.GENESIS_PREMINE_ADDRESS: 1},
            "pending_shares_next_round": pool_pending_shares,
            "share_target_multiplier": POOL_SHARE_TARGET_MULTIPLIER,
        })


@app.route("/blocks/receive", methods=["POST"])
@limiter.limit("120 per minute")  # D2: block gossip (~1/15s normally); each is re-validated
def receive_block():
    """A peer pushed us a freshly-mined OR freshly-staked block (see
    broadcast_block). If it cleanly extends our current tip, accept it
    directly — this is the fast path that makes propagation quick. If it
    doesn't (we're behind, or there's a fork), fall back to a full
    /nodes/resolve-style comparison instead of just rejecting it
    outright. staker_address must be forwarded here (unlike
    /mining/submit and /pool/submit_share, which only ever construct PoW
    blocks) — a peer's staked block needs it to validate as a stake
    proof instead of being checked against the wrong thing (a PoW
    target it was never mined against)."""
    body = request.get_json(silent=True) or {}
    try:
        block = Block(
            body["index"], [Transaction.from_dict(t) for t in body["transactions"]],
            body["previous_hash"], body["target"], body["timestamp"], body["nonce"],
            staker_address=body.get("staker_address"),
        )
    except KeyError as e:
        return jsonify({"status": "failed", "reason": f"Malformed block, missing {e}"}), 400
    with chain_lock:
        try:
            blockchain.accept_block(block)
            save_block(block)
            return jsonify({"status": "ok", "accepted": "direct"})
        except ValueError:
            pass  # doesn't cleanly extend our tip — fall through to full resolve
    resolved = _resolve_with_peers()
    return jsonify({"status": "ok", "accepted": "resolved", "replaced": resolved})


# ── Peer sync — the actual "network" half of "blockchain network" ──────────
@app.route("/nodes/register", methods=["POST"])
@limiter.limit("10 per minute")  # D2: peer registration is rare; tight cap curbs sybil flooding
def register_nodes():
    body = request.get_json(silent=True) or {}
    urls = body.get("nodes", [])
    if not urls:
        return jsonify({"status": "failed", "reason": "Provide a 'nodes' list of base URLs"}), 400
    for url in urls:
        peers.add(url.rstrip("/"))
    return jsonify({"status": "ok", "peers": sorted(peers)})


def _resolve_with_peers():
    """The real consensus algorithm: ask every known peer for their
    chain, and adopt the longest one that's actually valid — this is
    what lets two nodes that mined different blocks around the same time
    (a natural, expected occurrence, not an error) converge back onto a
    single agreed history once one side pulls further ahead."""
    replaced = False
    headers = _peer_headers()
    with chain_lock:
        for peer in list(peers):
            try:
                # 60s, not the 2-5s the gossip paths use: /chain ships the
                # peer's ENTIRE chain, and a cloud-hosted peer serving
                # hundreds of blocks (plus a possible cold start) can
                # legitimately take longer than a quick status ping. This
                # call only happens on startup catch-up, explicit
                # /nodes/resolve, and peer_sync_loop's already-throttled
                # once-per-2-min check — never in a request hot path.
                resp = requests.get(f"{peer}/chain", headers=headers, timeout=60)
                # A peer that returns anything other than a real chain payload
                # (a 401 from a secret mismatch, a 5xx, a cold-start HTML page,
                # malformed JSON) must be SKIPPED, never fatal. Previously
                # `data["chain"]` on a `{"reason":"Unauthorized"}` body raised
                # KeyError straight out of the startup call in __main__ and
                # crashed the whole node on boot — exactly the kind of thing
                # that turns one peer being briefly down or out-of-sync into a
                # total outage. A node always has its own persisted chain to
                # fall back on, so skipping a bad peer is safe.
                if resp.status_code != 200:
                    print(f"Peer {peer} returned {resp.status_code} for /chain; skipping")
                    continue
                data = resp.json()
                if not isinstance(data, dict) or "chain" not in data:
                    print(f"Peer {peer} /chain response has no chain; skipping")
                    continue
                candidate = [Block.from_dict(b) for b in data["chain"]]
                if blockchain.replace_chain(candidate):
                    replaced = True
            except (requests.RequestException, ValueError, KeyError, TypeError) as e:
                print(f"Could not sync from peer {peer}: {e}")
        if replaced:
            save_full_chain()
    return replaced


@app.route("/nodes/resolve")
@limiter.limit("6 per minute")  # D2: expensive (fetches every peer's full chain); tight cap
def resolve_conflicts():
    replaced = _resolve_with_peers()
    return jsonify({"status": "ok", "replaced": replaced, "chain_length": len(blockchain.chain)})


def peer_sync_loop():
    """Self-healing reconciliation for env-seeded peers (OCOIN_PEERS) —
    gossip (broadcast_block) is fire-and-forget, so a peer that was
    asleep/restarting when a block was pushed would otherwise stay behind
    until something happened to call /nodes/resolve. This loop closes that
    gap every 2 minutes, with a cheap /status length check first so the
    full /chain download (the expensive part, whole chain every time — fine
    at today's size, revisit with an incremental fetch if the chain gets
    long) only happens when a peer actually claims a longer chain."""
    headers = _peer_headers()
    while True:
        time.sleep(120)
        try:
            for peer in list(peers):
                try:
                    resp = requests.get(f"{peer}/status", timeout=30)
                    if resp.json().get("chain_length", 0) > len(blockchain.chain):
                        _resolve_with_peers()
                        break
                except requests.RequestException:
                    pass
        except Exception as e:
            print("peer_sync_loop tick failed:", e)


@app.route("/mine")
def mine_here():
    """Convenience endpoint: the node does the proof-of-work search
    itself, in-process, and mines a block immediately. Useful for local
    testing and for a node with no separate miner attached — real/serious
    mining should go through /mining/template + miner.py instead, which
    doesn't block the node's own HTTP responsiveness while searching."""
    if not LOCAL_MINE_ENABLED:
        return jsonify({"status": "failed", "reason": "/mine is disabled on this node. Real mining uses /mining/template + miner.py; set OCOIN_ENABLE_LOCAL_MINE=true only for local dev."}), 403
    miner_address = request.args.get("miner_address")
    if not miner_address:
        return jsonify({"error": "miner_address query param is required"}), 400
    with chain_lock:
        block = blockchain.mine_block(miner_address)
        save_block(block)
    broadcast_block(block)
    return jsonify({"status": "ok", "block": block.to_dict()})


@app.route("/pos/status")
def pos_status():
    """pos_target plus, if ?address=... is given, that address's current
    stake weight and a rough expected-seconds-to-block estimate — handy
    for checking "is this even worth staking with" before running a
    staking loop for real."""
    address = request.args.get("address")
    with chain_lock:
        payload = {"pos_target": blockchain.pos_target, "target_block_time": blockchain.TARGET_BLOCK_TIME}
        if address:
            weight = blockchain.stake_weight_of(address)
            payload["address"] = address
            payload["stake_weight"] = weight
            if weight >= 1:
                probability_per_second = min(1.0, (blockchain.pos_target * weight) / (2 ** 256))
                payload["expected_seconds_to_block"] = round(1 / probability_per_second, 1) if probability_per_second > 0 else None
            else:
                payload["expected_seconds_to_block"] = None
    return jsonify(payload)


@app.route("/stake_pool/status")
def stake_pool_status():
    """Track A, Phase A4/A7 — read-only liquid-staking-pool snapshot
    (exchange rate, total OCN staked, total stOCN outstanding). No address
    param, unlike /pos/status: the pool address is a fixed protocol
    constant (Blockchain.STAKE_POOL_ADDRESS), not something a caller picks."""
    with chain_lock:
        return jsonify(blockchain.stake_pool_status())


@app.route("/pools")
def list_pools():
    """Track A, Phase A5/A7 — every pool_key that currently has (or has
    ever had) liquidity, for a client to then call /pools/<pool_key> on."""
    with chain_lock:
        return jsonify({"pools": blockchain.list_pools()})


@app.route("/pools/<pool_key>")
def amm_pool_status(pool_key):
    """Track A, Phase A5/A7 — read-only AMM pool snapshot (reserves, LP
    supply, spot price). pool_key is 'asset_a:asset_b' in canonical sorted
    order, e.g. /pools/OCN:TEST — matches the same op_data.pool_key format
    pool_add_liquidity/pool_swap/pool_remove_liquidity transactions use.
    Named distinctly from pool_status() above (this chain's PRE-EXISTING
    PoW MINING pool, /pool/status, singular — a completely unrelated
    feature that predates Track A) to avoid a Flask endpoint-name
    collision; the URL paths were already distinct (/pool/ vs /pools/),
    only the Python function names needed disambiguating."""
    with chain_lock:
        try:
            return jsonify(blockchain.pool_status(pool_key))
        except ValueError as e:
            return jsonify({"status": "failed", "reason": str(e)}), 400


# History replays walk the whole chain — cheap at today's length but not
# something to redo on every poll of an analytics chart. Cached per chain
# length: any accepted/replaced block changes len(blockchain.chain), which
# simply keys a fresh entry (and a reorg that REPLACES history at the same
# length is impossible to serve stale here, because replace_chain only ever
# adopts strictly LONGER chains). Tiny dict, pruned to the current length.
_history_cache = {}


def _cached_history(kind, builder):
    with chain_lock:
        key = (kind, len(blockchain.chain))
        if key not in _history_cache:
            for stale in [k for k in _history_cache if k[0] == kind and k != key]:
                del _history_cache[stale]
            _history_cache[key] = builder()
        return _history_cache[key]


# ── Explorer routes — read-only views over the chain for the site's block
# explorer. Deliberately paginated (newest-first, ?before= cursor) so the
# payload stays bounded no matter how long the chain gets, unlike /chain
# (which ships the entire thing and exists for peer sync, not browsing).
@app.route("/blocks")
def blocks_page():
    try:
        limit = max(1, min(int(request.args.get("limit", 20)), 100))
        before = request.args.get("before")
        before = int(before) if before is not None else None
    except ValueError:
        return jsonify({"status": "failed", "reason": "limit/before must be integers"}), 400
    with chain_lock:
        tip = len(blockchain.chain) - 1
        end = tip if before is None else min(before - 1, tip)
        if end < 0:
            return jsonify({"chain_length": tip + 1, "blocks": []})
        start = max(0, end - limit + 1)
        page = blockchain.chain[start:end + 1]
        payload = [{
            "index": b.index,
            "timestamp": b.timestamp,
            "hash": b.compute_hash(),
            "staker_address": b.staker_address,  # None -> PoW block
            "tx_count": len(b.transactions),
            # Who this block paid: the staker for PoS, else the first
            # coinbase recipient (solo miner, or a pool's top contributor).
            "producer": b.staker_address or next((t.recipient for t in b.transactions if t.sender == "0"), None),
            "coinbase_total": sum(t.amount for t in b.transactions if t.sender == "0"),
        } for b in reversed(page)]
        return jsonify({"chain_length": tip + 1, "blocks": payload})


@app.route("/blocks/<int:idx>")
def block_detail(idx):
    with chain_lock:
        if idx < 0 or idx >= len(blockchain.chain):
            return jsonify({"status": "failed", "reason": f"No block at index {idx}"}), 404
        return jsonify(blockchain.chain[idx].to_dict())


@app.route("/address/<address>/transactions")
def address_transactions(address):
    """Newest-first transactions touching one address (as sender or
    recipient). Linear chain walk per request — fine at current chain
    length; revisit with an index if the chain grows enough to matter
    (same judgment call as A1's original balance index)."""
    try:
        limit = max(1, min(int(request.args.get("limit", 25)), 100))
    except ValueError:
        return jsonify({"status": "failed", "reason": "limit must be an integer"}), 400
    with chain_lock:
        results = []
        for b in reversed(blockchain.chain):
            for tx in b.transactions:
                if tx.sender == address or tx.recipient == address:
                    d = tx.to_dict()
                    d["block_index"] = b.index
                    d["block_timestamp"] = b.timestamp
                    results.append(d)
            if len(results) >= limit:
                break
        return jsonify({"address": address, "transactions": results[:limit]})


@app.route("/stake_pool/history")
def stake_pool_history():
    """Read-only time series of the staking pool (rate/staked/supply at
    every block that changed them) — the data an exchange-rate chart wants.
    Replayed from the chain itself, so it needs no storage and can't drift
    from consensus state."""
    return jsonify({"history": _cached_history("stake", blockchain.stake_pool_history)})


@app.route("/pools/<pool_key>/history")
def amm_pool_history(pool_key):
    """Read-only time series of one AMM pool (reserves/price/LP supply/
    per-block swap volume at every block that changed the pool)."""
    try:
        history = _cached_history(f"pool:{pool_key}", lambda: blockchain.pool_history(pool_key))
    except ValueError as e:
        return jsonify({"status": "failed", "reason": str(e)}), 400
    return jsonify({"pool_key": pool_key, "history": history})


@app.route("/pos/stake")
def stake_here():
    """Convenience endpoint mirroring /mine: one single kernel-check
    attempt, right now, for ?address=... — real/ongoing staking should
    use --stake at startup instead (see __main__ below), which retries
    roughly once per second in a background thread the same way a real
    wallet's staking loop would, rather than needing to be polled from
    outside."""
    if not LOCAL_MINE_ENABLED:
        return jsonify({"status": "failed", "reason": "/pos/stake is disabled on this node. Ongoing staking uses node.py --stake; set OCOIN_ENABLE_LOCAL_MINE=true only for local dev."}), 403
    address = request.args.get("address")
    if not address:
        return jsonify({"error": "address query param is required"}), 400
    with chain_lock:
        try:
            block = blockchain.try_stake(address)
        except ValueError as e:
            return jsonify({"status": "failed", "reason": str(e)}), 400
        if block is not None:
            save_block(block)
    if block is not None:
        broadcast_block(block)
        return jsonify({"status": "ok", "staked": True, "block": block.to_dict()})
    return jsonify({"status": "ok", "staked": False})


def staking_loop(address):
    """Runs for the lifetime of the process when the node is started
    with --stake. One try_stake attempt per second — matches
    compute_stake_kernel_hash's own whole-second granularity exactly, so
    there is nothing to gain from checking any faster than this (see
    that method's docstring for why). This is real, cheap, background
    proof-of-stake block production coexisting with whatever PoW mining
    (miner.py, elsewhere) is also happening against this same node."""
    print(f"Staking loop started for {address}")
    while True:
        time.sleep(1)
        with chain_lock:
            try:
                block = blockchain.try_stake(address)
            except ValueError as e:
                print(f"Staking stopped: {e}")
                return
            if block is not None:
                save_block(block)
        if block is not None:
            print(f"Staked block #{block.index}!")
            broadcast_block(block)


def keeper_loop(address):
    """Chain-liveness keeper — a deliberately gentle, in-process PoW miner
    that only works when the chain actually needs a block. Exists because
    the chain has stalled in practice whenever the operator's external
    miner (miner.py on a home machine) wasn't running: pending transactions
    sat in the mempool indefinitely and every wallet/pool action appeared
    frozen (2026-07-19, twice, including during the premine burn).

    Inert unless OCOIN_KEEPER_ADDRESS is set (same opt-in pattern as
    --stake). Mines only when:
      - the mempool is non-empty and the tip is older than
        OCOIN_KEEPER_TX_WAIT_SECONDS (default 20) — i.e. a real transaction
        is waiting and no faster external miner has picked it up; or
      - the tip is older than OCOIN_KEEPER_HEARTBEAT_SECONDS (default 600)
        — a slow heartbeat so difficulty retargets toward this node's own
        modest hash rate instead of staying stranded at whatever a much
        faster external miner left it at (which would otherwise make the
        FIRST keeper block after that miner stops take hours).

    The search runs OUTSIDE chain_lock in small batches with sleeps in
    between, so HTTP responsiveness on a small cloud instance is preserved
    and an external miner submitting first simply wins the block — the
    keeper notices the tip moved and abandons its stale candidate. Rewards
    go to OCOIN_KEEPER_ADDRESS; pointing that at the faucet's address turns
    keeper rewards into community faucet funding rather than operator
    accumulation (fair-launch posture, see BURN.md).
    """
    from pow_hash import header_fields_to_hash
    tx_wait = max(5, int(os.getenv("OCOIN_KEEPER_TX_WAIT_SECONDS", "20")))
    heartbeat = max(30, int(os.getenv("OCOIN_KEEPER_HEARTBEAT_SECONDS", "600")))
    batch = 120          # nonces per burst — small on purpose (Scrypt is slow)
    pause = 0.15         # sleep between bursts: keeps CPU mostly idle
    print(f"Keeper loop started — rewards to {address}, tx-wait {tx_wait}s, heartbeat {heartbeat}s")
    while True:
        time.sleep(5)
        try:
            with chain_lock:
                tip_age = time.time() - blockchain.latest_block.timestamp
                mempool_size = len(blockchain.mempool)
            if not (mempool_size and tip_age > tx_wait) and tip_age < heartbeat:
                continue
            with chain_lock:
                candidate = blockchain.build_candidate_block(address)
            target = int(candidate.target)
            nonce, last_tip_check = 0, time.time()
            while True:
                for _ in range(batch):
                    digest = header_fields_to_hash(candidate.index, candidate.timestamp,
                                                   candidate.merkle_root, candidate.previous_hash,
                                                   candidate.target, nonce)
                    if int(digest, 16) < target:
                        candidate.nonce = nonce
                        with chain_lock:
                            blockchain.accept_block(candidate)
                            save_block(candidate)
                        broadcast_block(candidate)
                        print(f"Keeper mined block #{candidate.index} ({mempool_size} tx(s) were pending)")
                        nonce = None
                        break
                    nonce += 1
                if nonce is None:
                    break
                time.sleep(pause)
                # Abandon a stale candidate: someone else (external miner or a
                # peer) already produced this block while we were searching.
                if time.time() - last_tip_check > 5:
                    with chain_lock:
                        if blockchain.latest_block.compute_hash() != candidate.previous_hash:
                            break
                    last_tip_check = time.time()
        except ValueError as e:
            # accept_block rejecting our own candidate (tip moved between the
            # final search burst and the lock) is normal contention, not a fault.
            print(f"keeper: candidate rejected ({e}) — retrying on the new tip")
        except Exception as e:
            print(f"keeper tick failed: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5100)
    parser.add_argument("--host", default="0.0.0.0", help="Bind address — defaults to 0.0.0.0 (reachable off-machine), not Flask's own 127.0.0.1 default, since a cloud-hosted node must accept connections from outside its own container.")
    parser.add_argument("--stake", help="Address to stake with — starts a background PoS thread alongside the node (see staking_loop). Optional; a node with no --stake just never produces PoS blocks itself, but still validates and syncs ones it hears about from peers.")
    args = parser.parse_args()
    if not DATABASE_URL:
        raise SystemExit("DATABASE_URL env var is required — the chain persists to Postgres now, not a local SQLite file (see get_pg()/init_db() above).")
    # Deliberately NOT a fixed default table name — two nodes started
    # against the same database for local sync-testing (exactly the "run a
    # second node locally to test sync" scenario this whole peer-sync
    # feature exists for) would otherwise silently share one chain and
    # appear to sync perfectly without ever actually talking to each other
    # over HTTP at all. Same trick the old per-port SQLite filename played.
    # OCOIN_BLOCKS_TABLE overrides for hosted redundancy: two Render
    # services share one Supabase database AND both bind the same port
    # number, so the port-derived name would silently collide — each
    # service names its own table explicitly instead.
    BLOCKS_TABLE = os.getenv("OCOIN_BLOCKS_TABLE") or f"ocoin_blocks_{args.port}"
    if not re.fullmatch(r"[a-z0-9_]+", BLOCKS_TABLE):
        raise SystemExit(f"OCOIN_BLOCKS_TABLE must be a plain lowercase identifier, got: {BLOCKS_TABLE!r}")
    load_chain()
    # OCOIN_PEERS: comma-separated peer base URLs, seeded at startup —
    # /nodes/register still works but only lives in memory, which on a
    # host that sleeps/redeploys means peers silently un-peer on every
    # restart. Env-seeded peers survive restarts, an immediate resolve
    # catches up a fresh/behind node before it starts serving, and
    # peer_sync_loop keeps reconciling from there.
    for peer_url in (os.getenv("OCOIN_PEERS") or "").split(","):
        peer_url = peer_url.strip().rstrip("/")
        if peer_url:
            peers.add(peer_url)
    if peers:
        print(f"Seeded {len(peers)} peer(s) from OCOIN_PEERS: {sorted(peers)}")
        # Startup peer-sync is BEST-EFFORT and must never be fatal: this node
        # already loaded its own persisted chain above, and peer_sync_loop will
        # keep reconciling once it's serving. A boot-time resolve failure (a
        # peer down, gated, mid-redeploy, or returning anything unexpected)
        # must not stop this node from coming up — otherwise two nodes can
        # deadlock each other on restart. Belt-and-suspenders around the
        # per-peer guards already inside _resolve_with_peers.
        try:
            if _resolve_with_peers():
                print(f"Startup resolve adopted a longer peer chain — now at {len(blockchain.chain)} blocks")
        except Exception as e:
            print(f"Startup peer resolve failed (non-fatal, continuing): {e}")
        threading.Thread(target=peer_sync_loop, daemon=True).start()
    # Track A, Phase A6 — test-only override, completely inert unless
    # someone deliberately sets this env var (Render's production
    # environment never does). Lets a LOCAL test node exercise op-bearing
    # transactions for real over HTTP without ever touching the actual
    # committed TX_SCHEMA_ACTIVATION_HEIGHT constant that gates the real,
    # deployed chain — see test_live_network.py.
    test_activation_height = os.getenv("OCOIN_TEST_ACTIVATION_HEIGHT")
    if test_activation_height is not None:
        blockchain.TX_SCHEMA_ACTIVATION_HEIGHT = int(test_activation_height)
        print(f"TEST OVERRIDE: TX_SCHEMA_ACTIVATION_HEIGHT set to {blockchain.TX_SCHEMA_ACTIVATION_HEIGHT} via OCOIN_TEST_ACTIVATION_HEIGHT")
    print(f"O-Coin node starting on {args.host}:{args.port} — target block time {blockchain.TARGET_BLOCK_TIME}s, {len(blockchain.chain)} block(s) loaded, persisting to Postgres table {BLOCKS_TABLE}")
    if args.stake:
        threading.Thread(target=staking_loop, args=(args.stake,), daemon=True).start()
    keeper_address = (os.getenv("OCOIN_KEEPER_ADDRESS") or "").strip()
    if keeper_address:
        threading.Thread(target=keeper_loop, args=(keeper_address,), daemon=True).start()
    app.run(host=args.host, port=args.port)
