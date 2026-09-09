# Genesis premine burn

## Policy

O-Coin's genesis block (block 0) minted a one-time premine of
**5,000,000,000 OCN** to a single address. Under the project's fair-launch
policy, that premine is **burned** — permanently removed from circulation by
sending it to an address that no private key can ever control. After the burn,
all OCN in circulation originates only from public mining (PoW) and staking
(PoS) rewards that any participant can earn.

## The burn address

```
500690f39f2bb75e1c740c58c0409dbaa85103ee
```

This address is **provably unspendable**. O-Coin addresses are
`sha256(public_key)[:40]` (see `wallet.py`). This burn address is instead the
SHA-256 of a fixed, public string — not of any public key — so spending from it
would require finding a public key whose SHA-256 collides with it in the first
160 bits, which is computationally infeasible. Anyone can reproduce it:

```python
import hashlib
hashlib.sha256(b"OCN:BURN:GENESIS-PREMINE").hexdigest()[:40]
# -> 500690f39f2bb75e1c740c58c0409dbaa85103ee
```

This is the same keyless construction the staking and AMM pool addresses use
(`sha256("STAKE_POOL:OCN")`, etc.) — no keypair exists for it, and none can.

## Transaction

- **Amount burned:** 4,999,100,700 OCN
- **From (premine address):** `3b770ab425c217f6615442fcc0517ad8445cf4ba`
- **To (burn address):** `500690f39f2bb75e1c740c58c0409dbaa85103ee`
- **Burn transaction hash:** `16aba080581f5f62bf99a77859dd906f1208f7c8c2b14afc7753882991884514`
- **Confirmed in block:** #1169, mined 2026-07-19 15:01:05 UTC. **Final and
  irreversible.** (This document previously said #1173, which was wrong —
  #1173 is an ordinary mining-reward block three minutes later and contains
  no burn. Corrected 2026-09-09 against the live chain; the transaction hash
  and burn address above were re-verified at the same time and are correct.)

### Accounting note

The genesis block minted a 5,000,000,000 OCN premine. By the time of the burn
the premine wallet held **4,999,101,449.41 OCN** — the small difference from
5,000,000,000 had already been dispersed through ordinary chain activity
(faucet funding, staking/AMM pool operations that were later unwound, etc.),
not retained. Of that, **4,999,100,700 OCN** was burned in the transaction
above, leaving roughly **749 OCN** of dust in the wallet (plus the 0.01 OCN
network fee). The founder wallet is thereby emptied of its premine.

**The premine address is not frozen, and its balance is not still 749 OCN.**
It remains an ordinary wallet, and it has gone on earning ordinary mining
rewards since the burn like any other address pointing a miner at the chain
— so its balance grows over time (it held ~7,849 OCN on 2026-09-09). None of
that is premine: every coin in it after block #1169 was mined under the same
rules available to anyone. What the burn permanently removed is the 5-billion
genesis allocation, and that is the claim to check — by confirming the burn
address still holds ~4.999 billion, not by expecting the founder address to
sit at zero forever.

## Verifying the burn

Anyone can verify by checking, via the node's balance endpoint or the block
explorer, that the burn address `500690f3…85103ee` now holds ~4.999 billion
OCN. Because the burn address is provably keyless (see above), those coins can
never move again.

Directly, against the live network — no account, no tooling, just a browser:

- <https://o-coin.onrender.com/balance/500690f39f2bb75e1c740c58c0409dbaa85103ee>
  — the burned coins, still sitting in the keyless address.
- <https://o-coin.onrender.com/blocks/1169> — the block containing the burn
  transaction itself.

Both are public read routes on the primary node; the backup node
(`o-coin-backup.onrender.com`) answers the same paths with the same data, which
is itself worth checking, since agreement between two independently running
nodes is the point of the thing.
