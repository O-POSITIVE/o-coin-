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

- **Amount burned:** 5,000,000,000 OCN
- **From (genesis premine address):** `3b770ab425c217f6615442fcc0517ad8445cf4ba`
- **To (burn address):** `500690f39f2bb75e1c740c58c0409dbaa85103ee`
- **Burn transaction hash:** _(to be filled in once the burn transaction
  confirms — paste the `transaction_hash` returned by `send_ocoin.py`, and the
  block height it confirms in, here)_

Only the 5,000,000,000 premine is burned. Any OCN the same wallet earned
afterward through ordinary PoW mining is not part of the premine and is left
untouched.

## Verifying the burn

Once confirmed, anyone can verify the premine is gone by checking that the burn
address holds 5,000,000,000 OCN and the original premine address no longer does,
via the node's balance endpoint or the block explorer.
