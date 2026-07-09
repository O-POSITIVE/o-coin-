# O-Coin

A real, working blockchain — not a simulation, not a database table pretending
to be one. Built in the spirit of Dogecoin: cheap, fast, casual "just send
it" transactions, with real cryptography and real proof-of-work/proof-of-stake
underneath. Deliberately lean rather than a fork of Bitcoin/Dogecoin/Litecoin's
own C++ codebase — this README's [Roadmap](#roadmap-toward-btcdogelitecoin-level-infrastructure)
section is the honest list of what heavier infrastructure would still need to
be added to actually get there.

This is its own project, separate from the `trading-platform` repo it lives
alongside on the same machine — O-Coin isn't tracked in that repo, and
shouldn't be.

## Quick start

```
pip install -r requirements.txt

# generate a wallet (prints an address + private key — keep the key secret)
python wallet.py

# start a node (defaults to port 5100)
python node.py

# in another terminal: mine against it with a real external miner process
python miner.py --node http://localhost:5100 --address <your address>

# or stake instead of (or alongside) mining — no separate process needed,
# runs a background thread inside the node itself:
python node.py --stake <your address>
```

Open a second node on the same machine to test peer sync:

```
python node.py --port 5101
curl -X POST http://localhost:5100/nodes/register -H "Content-Type: application/json" -d "{\"nodes\": [\"http://localhost:5101\"]}"
curl -X POST http://localhost:5101/nodes/register -H "Content-Type: application/json" -d "{\"nodes\": [\"http://localhost:5100\"]}"
```

## Architecture

| File | Role |
|---|---|
| `transaction.py` | A signed transfer — real ECDSA (SECP256k1), the same curve Bitcoin uses. `sender == "0"` is the one special case: a coinbase (newly-minted reward), no signature needed. |
| `wallet.py` | A key pair + address (`sha256(pubkey)[:40]`). Standalone — `python wallet.py` generates one from the command line. |
| `pow_hash.py` | The ONE place the proof-of-work hash is defined (Scrypt, Litecoin/Dogecoin's real parameters) — shared by `blockchain.py` and `miner.py` so they can never silently drift out of sync with each other. |
| `blockchain.py` | The actual chain: `Block`, `Blockchain`, proof-of-work search, proof-of-stake kernel checks, difficulty retargeting (both PoW and PoS have their own, independent), full from-scratch chain re-validation. No I/O — pure functions/classes, reusable from both the live node and any future offline tooling. |
| `node.py` | The always-on HTTP server: mempool, mining/staking/pool endpoints, SQLite persistence (one row per block), block gossip, peer sync (`/nodes/resolve` — longest valid chain wins). |
| `miner.py` | A standalone external miner — talks to a node purely over HTTP, so it can run on a different machine than the node itself. |

## What's built

- **Real cryptography** — every non-coinbase transaction is ECDSA-signed and independently re-verified; a Merkle root commits each block to its exact transaction set; tampering with anything breaks a hash chain that's cheap to verify and expensive to fake.
- **ASIC-resistant proof-of-work** — Scrypt (Litecoin/Dogecoin's real parameters), not a placeholder, with difficulty retargeting toward a 15-second target block time.
- **Hybrid PoW + PoS consensus** (Peercoin-style, adapted to this chain's account-based ledger) — anyone holding a large-enough balance can also produce blocks by staking, at zero energy cost, for a smaller reward than mining (`POS_REWARD_FRACTION`). PoS gets its own independently-retargeted difficulty (`pos_target`) so it never interferes with PoW's.
- **Smooth, real-inflation-tied emission curve** — not a Bitcoin-style halving cliff. The block reward decays *exponentially*, asymptotically approaching (never reaching) a permanent floor, at a rate calibrated to the long-run historical average US CPI inflation rate (3%/year) rather than an arbitrary number. Implemented in pure fixed-point integer math specifically so every node computes bit-identical rewards regardless of platform (see `Blockchain._fixed_pow`'s docstring for why floating-point exponentiation is unsafe in consensus code).
- **Genesis premine** — a one-time, fully transparent allocation at block 0 (real precedent: this is exactly how XRP Ledger's entire supply was created).
- **Mining pool** — share-based proportional payout (`/pool/*` routes), PPLNS-style one-round delay so the payout list can be fixed *before* mining starts for a round (the same fix real pools use to avoid a chicken-and-egg problem with the coinbase transaction).
- **Cheap, fast, efficient by design** — flat (not percentage) transaction fees kept deliberately tiny, highest-fee-first block filling, a 15-second target block time.
- **Checkpointing** — the standard small-chain mitigation for 51%-attack risk: blocks older than `CHECKPOINT_DEPTH` are permanent, full stop, regardless of how long or validly-mined a competing chain is. (51% hashpower can contest *which valid history wins*, via a longer chain — it can never forge a transaction, since that's already blocked by ECDSA signatures regardless of hashpower.)
- **Replay protection** — a signed transaction can only ever be honored once, both at mempool-submission time and independently re-checked inside every block validation. (Found and fixed during this project's own end-to-end testing — see git-adjacent notes in `blockchain.py`'s `add_transaction`/`accept_block` for the full story.)
- **Scalable persistence + fast propagation** — one SQLite row per block (O(1) writes, not a full-chain rewrite every block), plus fire-and-forget gossip to peers on every new block so the network doesn't have to wait for someone to poll `/nodes/resolve`.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /status` | Chain length, both difficulty targets, current PoW/PoS rewards, mempool size, peers |
| `GET /chain` | Full chain, serialized |
| `GET /balance/<address>` | Confirmed balance |
| `POST /transactions/new` | Submit a signed transaction |
| `GET /transactions/pending` | Current mempool |
| `GET /mining/template`, `POST /mining/submit` | Solo mining (what `miner.py` talks to) |
| `GET /pool/template`, `POST /pool/submit_share`, `GET /pool/status` | Mining pool |
| `GET /pos/status`, `GET /pos/stake` | PoS staking status / one manual stake attempt |
| `GET /mine` | Convenience: node mines in-process (blocks the request until found — testing only) |
| `POST /blocks/receive` | Gossip receiver (peer pushed a new block) |
| `POST /nodes/register`, `GET /nodes/resolve` | Peer management / longest-valid-chain sync |

## Roadmap toward BTC/DOGE/Litecoin-level infrastructure

Everything above is real, not a toy — but there's an honest gap between "a
real chain that works" and what Bitcoin/Dogecoin/Litecoin actually run in
production. In roughly the order it'd make sense to tackle:

1. **Real P2P discovery.** Peers are registered by hand right now
   (`/nodes/register`). A real network needs DNS seeds or a gossip-based peer
   discovery protocol so nodes can find each other without a human wiring
   them together.
2. **Balance index / UTXO set.** `get_balance` and `stake_weight_of` walk the
   *entire* chain from genesis on every call — fine at hobby scale, a real
   bottleneck once the chain is long. A maintained running index (or a real
   UTXO model instead of the current account model) turns this from O(chain
   length) into O(1).
3. **Retargeting history re-simulation.** `is_chain_valid` trusts each
   block's own recorded difficulty target rather than replaying
   `_maybe_retarget`/`_maybe_retarget_pos` block-by-block to confirm every
   historical target was actually the correct one for its era. Real chains
   do this replay as part of full validation.
4. **Light clients / SPV wallets.** Right now the only way to check a
   balance or send a transaction is to talk to a full node. Real usability
   at scale means a wallet that can verify just enough (Merkle proofs
   against block headers) without downloading and replaying the entire
   chain itself.
5. **Mempool policy.** No transaction expiry, no eviction under memory
   pressure, no fee estimation — a production mempool needs all three.
6. **A block explorer and a public read API**, separate from the
   transaction-accepting node endpoints, since a chain nobody but its own
   node operator can inspect isn't really usable by anyone else yet.
7. **Testnet/mainnet split.** There's currently exactly one network. Real
   coins need a disposable, worthless-by-design testnet for exactly the kind
   of experimentation this project has been doing throughout development,
   kept clearly separate from anything meant to hold real value.
8. **Operational hardening.** Rate-limiting and basic DoS protection on the
   HTTP API, TLS between nodes, and — if the node's admin-style endpoints
   (`/nodes/register` in particular) are ever exposed beyond a trusted
   local network — real authentication on them.
9. **A written consensus spec**, independent of this specific Python
   implementation. The real mark of infrastructure maturity: someone should
   be able to write a second, independent implementation in another
   language and have it agree with this one on every block, using nothing
   but a spec document — the same way Bitcoin Core isn't the *only* thing
   that understands the Bitcoin protocol.
10. **A BFT validator-committee consensus layer**, modeled on systems like
    Hyperliquid's HyperBFT (HotStuff-derived: a known/bounded validator set,
    explicit quorum voting, deterministic finality once 2/3+ voting weight
    signs a block) — a genuinely different consensus family from the
    Nakamoto/longest-chain-wins model everything above uses, not an
    incremental extension of PoW/PoS. Explicitly wanted as a future
    experiment, not yet scoped in detail; likely needs its own
    validator-membership model (probably stake-weighted) and a real slashing
    mechanism for provable misbehavior/downtime.

None of this is required for O-Coin to keep being real and useful at its
current scale — it's the honest list of what "keep growing this toward
BTC/DOGE/Litecoin's own level of infrastructure" actually means, so future
work has a map instead of starting from scratch each time.
