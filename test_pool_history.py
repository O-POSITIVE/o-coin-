"""Verifies the read-only history/analytics replays (stake_pool_history /
pool_history) added for the site's pool-analytics charts. Same
no-networking, direct-object style as the other test_*.py files.

The core property under test: a history's FINAL snapshot must equal the
live status the index reports (same numbers, derived two independent ways
— incremental index vs. from-scratch chain replay), and blocks that don't
touch a pool must contribute no snapshots.
"""
from blockchain import Blockchain
from transaction import Transaction
from wallet import Wallet


def fresh_active_chain():
    bc = Blockchain()
    bc.TX_SCHEMA_ACTIVATION_HEIGHT = 0
    return bc


print("=== Scenario 1: stake_pool_history matches live status, only change-blocks snapshot ===")
bc = fresh_active_chain()
staker = Wallet()
bc.mine_block(staker.address)          # block 1: staker earns ~100 OCN (no pool change)
bc.mine_block("unrelated-miner")       # block 2: no pool change
dep = Transaction(staker.address, Blockchain.STAKE_POOL_ADDRESS, 60, op="stake_pool_deposit")
dep.sign(staker)
bc.add_transaction(dep)
bc.mine_block("unrelated-miner")       # block 3: deposit lands
bc.mine_block("unrelated-miner")       # block 4: no pool change
hist = bc.stake_pool_history()
assert len(hist) == 1, f"expected exactly 1 change-block snapshot, got {len(hist)}: {hist}"
assert hist[-1]["height"] == 3
live = bc.stake_pool_status()
assert hist[-1]["total_staked_ocn"] == live["total_staked_ocn"] == 60
assert hist[-1]["total_stocn_supply"] == live["total_stocn_supply"]
assert hist[-1]["exchange_rate"] == live["exchange_rate"]
print(f"  1 snapshot at height 3, matches live status: staked={live['total_staked_ocn']}, rate={live['exchange_rate']}")


print("\n=== Scenario 2: a second deposit and a withdrawal each add exactly one snapshot ===")
dep2 = Transaction(staker.address, Blockchain.STAKE_POOL_ADDRESS, 30, op="stake_pool_deposit")
dep2.sign(staker)
bc.add_transaction(dep2)
bc.mine_block("unrelated-miner")
wd = Transaction(staker.address, staker.address, 10, op="stake_pool_withdraw")
wd.sign(staker)
bc.add_transaction(wd)
bc.mine_block("unrelated-miner")
hist = bc.stake_pool_history()
assert len(hist) == 3, [h["height"] for h in hist]
assert hist[-1]["total_staked_ocn"] == bc.stake_pool_status()["total_staked_ocn"] == 80
print(f"  3 snapshots, final staked={hist[-1]['total_staked_ocn']} (60 + 30 - 10)")


print("\n=== Scenario 3: pool_history tracks reserves/price/LP and per-block swap volume ===")
bc2 = fresh_active_chain()
lp = Wallet()
bc2.mine_block(lp.address)
# Mint real stOCN (fully chain-derivable, unlike a hand-seeded test asset)
dep = Transaction(lp.address, Blockchain.STAKE_POOL_ADDRESS, 50, op="stake_pool_deposit")
dep.sign(lp)
bc2.add_transaction(dep)
bc2.mine_block("m")
pool_key = Blockchain._pool_key("OCN", "stOCN")
pool_addr = Blockchain._pool_address(pool_key)
add = Transaction(lp.address, pool_addr, 0, op="pool_add_liquidity",
                  op_data={"pool_key": pool_key, "amount_a": 20, "amount_b": 20})
add.sign(lp)
bc2.add_transaction(add)
bc2.mine_block("m")
trader = Wallet()
bc2.mine_block(trader.address)
swap = Transaction(trader.address, trader.address, 0, op="pool_swap",
                   op_data={"pool_key": pool_key, "asset_in": "OCN", "amount_in": 5, "min_amount_out": 0.1})
swap.sign(trader)
bc2.add_transaction(swap)
bc2.mine_block("m")
hist = bc2.pool_history(pool_key)
live = bc2.pool_status(pool_key)
assert hist[-1]["reserve_a"] == live["reserve_a"] and hist[-1]["reserve_b"] == live["reserve_b"], (hist[-1], live)
assert hist[-1]["lp_supply"] == live["lp_supply"]
assert hist[-1]["price_a_in_b"] == live["price_a_in_b"]
assert hist[-1]["swap_volume_in"] == 5, hist[-1]
assert hist[0]["swap_volume_in"] == 0  # the liquidity-add block had no swaps
assert len(hist) == 2, [h["height"] for h in hist]  # add block + swap block, nothing else
print(f"  final snapshot == live status (reserves {live['reserve_a']}/{round(live['reserve_b'],6)}, LP {live['lp_supply']}), swap block volume=5")


print("\n=== Scenario 4: unknown-but-valid pool key -> empty history; malformed key -> ValueError ===")
assert bc2.pool_history("AAA:ZZZ") == []
try:
    bc2.pool_history("not-a-pool-key")
    raise AssertionError("malformed pool key should have raised")
except ValueError as e:
    print(f"  malformed key correctly rejected: {e}")
assert bc2.stake_pool_history()[-1]["total_staked_ocn"] == bc2.stake_pool_status()["total_staked_ocn"]


print("\n=== ALL SCENARIOS PASSED ===")
