# Decentralization: opening the network to independent nodes

**Status: D1–D4 SHIPPED AND LIVE (2026-07-20). D5 (docs) done — see the
README's "Run your own node" section for the actual join instructions.** This
closed the real gap between "a chain one person operates" and "a chain anyone
can run a node on." It ties to the trading-platform repo's `docs/13` finding
F5, and to the fair-launch posture in `BURN.md`: the premine burn bought *"no
founder premine"*; this work buys *"not reversible or controllable by one
person."*

**The permissionless network is real, today:** any node running `python
node.py` with `OCOIN_PEERS` set to the two hosted URLs below fully syncs the
live chain, submits transactions, gossips blocks, and mines — with no secret.
What remains beyond this document is a social/adoption problem (getting
independent operators to actually run nodes and contribute real hash power),
not a code or access problem.

## The blocker, precisely

On a node with `OCOIN_NODE_SHARED_SECRET` set (the two hosted nodes), only
three routes are public (`PUBLIC_PATHS` in `node.py`): `/status`,
`/mining/template`, `/mining/submit`. **Every other route requires the
operator's secret.** So an outsider can *mine* the live chain permissionlessly,
but cannot *read the chain*, *receive/gossip blocks*, *submit a transaction*,
or *register as a peer* without a secret only the operator holds. Independent
full nodes therefore can't actually join the live network.

## The key realization (why this is safe to fix)

**The shared secret is an *access* gate, not the *consensus* gate.** Proof:
`/mining/submit` is already public, and it feeds attacker-controlled blocks
straight into `accept_block`, which re-validates proof-of-work, the target,
the merkle root, and every transaction from scratch. If that weren't safe, the
live network would already be exploitable through the one door that's open.
It isn't — because **validation, not the secret, is what protects consensus.**
Opening the other read/gossip routes exposes nothing that validation doesn't
already guard. The secret was only ever "keep randoms from talking to my
node," which is precisely the property a permissionless chain must give up.

## Route-by-route plan

| Route | Category | Action |
|---|---|---|
| `/status`, `/mining/template`, `/mining/submit` | already public | keep |
| `/chain`, `/blocks`, `/blocks/<idx>` | public read | **open** (paginate `/chain`) |
| `/balance/<address>`, `/transactions/pending` | public read | **open** |
| `/pools`, `/pools/<key>`, `/stake_pool/status`, `/pos/status`, `/pool/status` | public read | **open** |
| `/address/<a>/transactions`, `/stake_pool/history`, `/pools/<k>/history` | public read | **open** |
| `/pool/template`, `/pool/submit_share` | mining (like /mining/*) | **open** |
| `/transactions/new` | gossip — validated (sig+fee) | **open + rate-limit** |
| `/blocks/receive` | gossip — validated (`accept_block`) | **open + rate-limit** |
| `/nodes/resolve`, `/nodes/register` | gossip/peering | **open + rate-limit** |
| `/mine` | in-process PoW — CPU DoS vector, convenience only | **stay gated / disable in prod** |
| `/pos/stake` | manual single stake attempt — operator convenience | **stay gated** |

Real mining/staking never needs `/mine` or `/pos/stake` (those are local
conveniences; production uses `/mining/*` + the `--stake` background thread),
so keeping them gated costs participants nothing.

## New risks opening introduces, and mitigations

1. **DoS / spam** on the newly-public write routes. Today the node has **no
   rate limiting** and **no mempool size cap** (the block builder caps txs
   *per block*, but the mempool itself can grow unbounded). Mitigations, both
   required before D2:
   - Add `flask-limiter` (new dep) with per-IP limits on `/transactions/new`,
     `/blocks/receive`, `/nodes/register`.
   - Add a mempool cap in `blockchain.py` (evict lowest-fee when over N).
   - Invalid txs/blocks are already rejected cheaply (bad signature / bad PoW),
     so the attack surface is volume, which rate limits handle.
2. **Eclipse / sybil peering** via public `/nodes/register` (an attacker
   floods a node with sybil peers to isolate it). Mitigations: treat
   `OCOIN_PEERS` (env-seeded) as always-trusted anchors that are never dropped;
   cap the dynamic peer list; prefer seed peers during resolution. Document the
   assumption honestly.
3. **`/chain` payload size** grows with the chain (already 1,000+ blocks).
   `/blocks` is already paginated; `/chain` must be paginated or capped before
   it's public so it isn't a bandwidth amplifier.

## Phased rollout (each phase independently shippable + testable)

- **D1 — Open the reads. ✅ SHIPPED 2026-07-20.** Gating switched from
  exact-path to endpoint-based (`PUBLIC_ENDPOINTS`) so parameterized routes are
  covered; all read routes + pool mining are now public; `/chain` got a
  (height, tip-hash)-keyed response cache so opening it can't be an
  amplification DoS (peer sync still gets the full chain). Verified on an
  isolated secret-configured node: reads return 200 without the secret, while
  `/nodes/resolve`, `/mine`, and `/transactions/new` still return 401. *Anyone
  can now run a node that fully SYNCS from the live network and mine it.*
  (Full `/chain` pagination for very large chains remains a later optimization;
  the cache handles today's scale.)
  **LIVE + VERIFIED IN PRODUCTION 2026-07-20:** both hosted nodes serve
  `/chain` publicly (200, no secret), heights tracking within ±1. Shipping it
  surfaced a pre-existing latent bug — `_resolve_with_peers` crashed the node
  on boot if a peer's `/chain` returned a non-chain body (a 401 from the
  post-rotation secret mismatch); fixed to skip bad peers, plus the whole
  startup resolve is now wrapped so it can never be fatal (a node always has
  its own persisted chain). This is exactly why each phase deploys and gets
  verified in production before the next.
- **D2 — Open the gossip. ✅ SHIPPED 2026-07-20.** Guards first: added
  `flask-limiter` (per-IP, in-memory; `ProxyFix` so the real client IP is used
  behind Render's proxy) with `@limiter.limit` on each gossip route
  (`/transactions/new` 30/min, `/blocks/receive` 120/min, `/nodes/register`
  10/min, `/nodes/resolve` 6/min), plus a bounded mempool
  (`Blockchain.MEMPOOL_MAX = 5000`, fee-priority eviction). Then moved the four
  routes into `PUBLIC_ENDPOINTS`. Verified on an isolated node: gossip routes
  reachable without the secret (400 on bad body, not 401), `/mine` + `/pos/stake`
  still 401, and the rate limiter returns 429 past the cap. *Independent nodes
  can now fully participate — submit transactions, gossip blocks, peer — no
  secret.*
- **D3 — Lock the DoS endpoints. ✅ SHIPPED 2026-07-20.** `/mine` (in-process
  PoW) and `/pos/stake` (manual stake attempt) now return 403 unless
  `OCOIN_ENABLE_LOCAL_MINE=true` — OFF in production. Real mining/staking use
  `/mining/*` + `--stake` and are unaffected. This retires the last thing the
  shared secret meaningfully guarded on the node (after D1/D2 everything else
  is public), so the node is safe even if the secret is unset. Verified on an
  isolated node: flag off → 403 even with the secret; flag on → reachable and
  still secret-gated.

  Rate-limiter follow-up (D2): the first D2 deploy's limiter silently never
  fired in production because `ProxyFix` keyed on Render's rotating edge IP;
  fixed to key on the leftmost `X-Forwarded-For` (real client) and verified
  live (429 past the cap).
- **D4 — Retire the secret's peering role.** With reads + gossip public, the
  hosted nodes peer with strangers over public routes and no longer need the
  secret to sync. The secret now guards only the admin endpoints (D3). The
  trading-platform server keeps sending its `X-Node-Auth` header harmlessly
  (public routes ignore it) — **no change required there**, and it can be
  cleaned up later.
- **D5 — Bootstrap docs + published seeds. ✅ SHIPPED.** README's "Run your
  own node" section rewritten from "help wanted" to a real how-to: both hosted
  node URLs published as seed peers
  (`OCOIN_PEERS=https://o-coin.onrender.com,https://o-coin-backup.onrender.com`),
  plus the actual sync/mine/submit commands.

## Capstone verification — a real stranger, not a simulation (2026-07-20)

Ran the acceptance test for real against the live network, not an isolated
sandbox: started a brand-new `node.py` process with **`OCOIN_NODE_SHARED_SECRET`
entirely unset** (a true stranger — no relationship to the operator) and a
**fresh, empty database table** (zero prior chain state), pointed at
`https://o-coin.onrender.com` as its only peer.

Results:
- **Synced the real chain from scratch**: adopted all 1,300 real blocks on
  startup via the public `/chain`, tip hash matching the live network within
  the normal real-time lag (it advanced to 1,301 while the test ran).
- **Write paths reachable with no secret, and correctly validated (not just
  "not 401")**: `/transactions/new` with a malformed signature → `400`, a real
  validation rejection, not a mempool entry. `/blocks/receive` with a
  fabricated block → `200` with `replaced: false` — `accept_block` rejected it,
  the node fell through to its designed `_resolve_with_peers` reconciliation
  against its REAL peers, and correctly found nothing to adopt. The chain was
  provably untouched by the bogus payload.
- **`/nodes/resolve`** reachable with no secret, `200`.
- **D3 still holds**: `/mine` and `/pos/stake` both `401` with no secret.
- **Live chain unaffected**: height sane and advancing after the probes.

This is the real proof, not a stand-in for it: an outside participant with
zero prior relationship to the operator can join, fully sync, and interact
with the live network today.

## Acceptance test (the proof it worked)

An isolated two-node test where **node B has NO shared secret** and must, over
HTTP against node A: pull and validate the chain, receive a gossiped block,
submit a signed transaction that lands in A's mempool, register as a peer, and
win a longest-chain resolution. Mirrors the existing `test_live_network.py`
style but asserts the *permissionless* path. This is the definition of done.

## The honest caveat

Opening the doors makes the network **permissionless to join** — a real and
necessary step. It does **not**, by itself, make the chain *secure against a
determined attacker*: that still requires genuinely independent hash power and
multiple operators actually showing up. This work removes the barrier; the
community has to walk through it. Said plainly so no one mistakes "anyone *can*
run a node" for "the chain is already decentralized."

## Note on process

This changes the live network's access posture but **not its consensus rules**
(no validation logic changes), so it's lower-risk than a consensus change —
but it still must be rolled out carefully, phase by phase, each verified on an
isolated network first, and (per the repo's standing rule) with the operator's
explicit go before anything touches the live nodes.
