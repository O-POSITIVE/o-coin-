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

### Accounting note

The genesis block minted a 5,000,000,000 OCN premine. By the time of the burn
the premine wallet held **4,999,101,449.41 OCN** — the small difference from
5,000,000,000 had already been dispersed through ordinary chain activity
(faucet funding, staking/AMM pool operations that were later unwound, etc.),
not retained. Of that, **4,999,100,700 OCN** was burned in the transaction
above, leaving roughly **749 OCN** of dust in the wallet (plus the 0.01 OCN
network fee). The founder wallet is thereby emptied of its premine.

## Verifying the burn

Anyone can verify by checking, via the node's balance endpoint or the block
explorer, that the burn address `500690f3…85103ee` now holds ~4.999 billion OCN
and the former premine wallet `3b770ab…5cf4ba` holds only dust. Because the burn
address is provably keyless (see above), those coins can never move again.
