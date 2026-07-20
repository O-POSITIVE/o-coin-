# Decentralization: opening the network to independent nodes

**Status: SCOPED, not yet implemented.** This is the plan to close the one
real gap between "a chain one person operates" and "a chain anyone can run a
node on." It ties to the trading-platform repo's `docs/13` finding F5, and to
the fair-launch posture in `BURN.md`: the premine burn bought *"no founder
premine"*; this work buys *"not reversible or controllable by one person."*

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

- **D1 — Open the reads (zero consensus risk).** Add all read + pool-mining
  routes to `PUBLIC_PATHS`; paginate `/chain`. Ship. *Now anyone can run a node
  that fully SYNCS from the live network and mine.* This alone creates real
  independent full nodes.
- **D2 — Open the gossip (add the guards first).** Add `flask-limiter` + the
  mempool cap, then make `/transactions/new`, `/blocks/receive`,
  `/nodes/resolve`, `/nodes/register` public. *Now independent nodes fully
  participate in propagation and mempool.*
- **D3 — Lock the DoS endpoints.** Ensure `/mine` and `/pos/stake` stay gated,
  and add an env flag to disable `/mine` entirely in production.
- **D4 — Retire the secret's peering role.** With reads + gossip public, the
  hosted nodes peer with strangers over public routes and no longer need the
  secret to sync. The secret now guards only the admin endpoints (D3). The
  trading-platform server keeps sending its `X-Node-Auth` header harmlessly
  (public routes ignore it) — **no change required there**, and it can be
  cleaned up later.
- **D5 — Bootstrap docs + published seeds.** Publish the hosted node URLs as
  seed peers, and document the real join flow (`python node.py` +
  `OCOIN_PEERS=https://o-coin.onrender.com,...`). Update the README's
  "run your own node" section from "help wanted" to "here's how."

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
