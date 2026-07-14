"""Verifies Track A Phase A5 (native AMM pools: pool_add_liquidity /
pool_swap / pool_remove_liquidity, constant-product x*y=k with a 0.3% input
fee, LP share tokens). Same no-networking, direct-object style as the other
test_*.py files in this repo.

Note: this implementation intentionally does NOT include a separate
pool_create op the original plan sketched — a pool auto-creates on its
first pool_add_liquidity (there's no meaningful state to "create" ahead of
that, since pool state is entirely derived from balances/asset_supply, the
same way A1's balance index derives everything from transaction history).
Flagged here, not silently dropped.
"""
from blockchain import Block, Blockchain, proof_of_work
from transaction import Transaction
from wallet import Wallet


def fresh_active_chain():
    bc = Blockchain()
    bc.TX_SCHEMA_ACTIVATION_HEIGHT = 0
    return bc


def give_asset(bc, address, asset_id, amount):
    """Test-only seed — no mint op for arbitrary assets exists (by design,
    see docs/07-onchain-dex-plan.md's 'no open mint' rule); real usage
    would get TEST-like balances from an actual transfer_asset chain of
    custody, irrelevant to what THIS file is testing.

    IMPORTANT: this writes directly into bc.balances with no corresponding
    transaction, so any chain built using it will correctly FAIL
    is_chain_valid (which can only ever trust balances it can re-derive
    from genesis) — don't call is_chain_valid on a chain seeded this way;
    see Scenario 8 for a from-scratch-derivable alternative."""
    key = (address, asset_id)
    bc.balances[key] = bc.balances.get(key, 0) + amount


print('=== Scenario 1: pool/LP addresses are canonical regardless of asset order ===')
assert Blockchain._pool_key("OCN", "TEST") == Blockchain._pool_key("TEST", "OCN") == "OCN:TEST"
assert Blockchain._pool_address("OCN:TEST") == Blockchain._pool_address(Blockchain._pool_key("TEST", "OCN"))
print(f"  pool_key('OCN','TEST') == pool_key('TEST','OCN') == 'OCN:TEST', address = {Blockchain._pool_address('OCN:TEST')}")


print('\n=== Scenario 2: first liquidity add bootstraps via sqrt(a*b), mints LP 1:1 with contribution value ===')
bc = fresh_active_chain()
lp1 = Wallet()
bc.mine_block(lp1.address)
give_asset(bc, lp1.address, "TEST", 1000)
pool_key = "OCN:TEST"
pool_addr = Blockchain._pool_address(pool_key)
add1 = Transaction(lp1.address, pool_addr, 0, op="pool_add_liquidity", op_data={"pool_key": pool_key, "amount_a": 40, "amount_b": 90})
add1.sign(lp1)
bc.add_transaction(add1)
bc.mine_block("miner-1")
status = bc.pool_status(pool_key)
assert status["reserve_a"] == 40 and status["reserve_b"] == 90, status
expected_lp = round((40 * 90) ** 0.5, 6)
assert bc.get_balance(lp1.address, asset_id=status["lp_asset"]) == expected_lp
assert bc.asset_supply.get(status["lp_asset"]) == expected_lp
print(f"  reserves after first add: {status['reserve_a']} OCN / {status['reserve_b']} TEST, LP minted: {expected_lp}")


print('\n=== Scenario 3: swap follows constant-product math with the 0.3% fee, respects min_amount_out ===')
trader = Wallet()
bc.mine_block(trader.address)
reserve_a_before = bc.pool_status(pool_key)["reserve_a"]
reserve_b_before = bc.pool_status(pool_key)["reserve_b"]
amount_in = 10
amount_in_after_fee = amount_in * 997
expected_out = round((amount_in_after_fee * reserve_b_before) / (reserve_a_before * 1000 + amount_in_after_fee), 6)
swap = Transaction(trader.address, trader.address, 0, op="pool_swap",
                    op_data={"pool_key": pool_key, "asset_in": "OCN", "amount_in": amount_in, "min_amount_out": expected_out})
swap.sign(trader)
bc.add_transaction(swap)
bc.mine_block("miner-2")
assert bc.get_balance(trader.address, asset_id="TEST") == expected_out, (bc.get_balance(trader.address, asset_id="TEST"), expected_out)
status_after_swap = bc.pool_status(pool_key)
assert status_after_swap["reserve_a"] == reserve_a_before + amount_in
assert status_after_swap["reserve_b"] == round(reserve_b_before - expected_out, 6)
print(f"  swapped {amount_in} OCN -> {expected_out} TEST (0.3% fee applied), reserves now {status_after_swap['reserve_a']}/{status_after_swap['reserve_b']}")

# Constant product k should have INCREASED slightly (the 0.3% fee accrues
# to the pool, benefiting existing LPs) — never decreased.
k_before = reserve_a_before * reserve_b_before
k_after = status_after_swap["reserve_a"] * status_after_swap["reserve_b"]
assert k_after >= k_before, (k_before, k_after)
print(f"  constant product k: {k_before:.4f} -> {k_after:.4f} (rose, as expected — the fee accrues to reserves)")


print('\n=== Scenario 4: slippage protection rejects a swap that would underpay min_amount_out ===')
greedy = Wallet()
bc.mine_block(greedy.address)
unrealistic = Transaction(greedy.address, greedy.address, 0, op="pool_swap",
                           op_data={"pool_key": pool_key, "asset_in": "OCN", "amount_in": 1, "min_amount_out": 999999})
unrealistic.sign(greedy)
try:
    bc.add_transaction(unrealistic)
    mempool_raised = False
except ValueError as e:
    mempool_raised = True
    print(f"  mempool correctly rejected an unmeetable min_amount_out: {e}")
assert mempool_raised

reward_for_bad_swap = bc.reward_at_height(bc.latest_block.index + 1) + unrealistic.fee
bad_swap_block = Block(
    index=bc.latest_block.index + 1,
    transactions=[Transaction("0", "miner-3", reward_for_bad_swap), unrealistic],
    previous_hash=bc.latest_block.compute_hash(),
    target=bc.current_target,
)
bad_swap_block = proof_of_work(bad_swap_block)
try:
    bc.accept_block(bad_swap_block)
    block_raised = False
except ValueError as e:
    block_raised = True
    print(f"  accept_block also independently rejected the same directly-submitted block: {e}")
assert block_raised
# and is_chain_valid must independently reach the same verdict, from scratch
candidate = bc.chain + [bad_swap_block]
assert bc.is_chain_valid(candidate) is False, "is_chain_valid must independently catch the same slippage violation"
print("  is_chain_valid independently rejects the same candidate chain (not just accept_block)")


print('\n=== Scenario 5: remove_liquidity burns LP and returns a proportional share of BOTH reserves ===')
status_before_remove = bc.pool_status(pool_key)
lp_asset = status_before_remove["lp_asset"]
lp1_lp_balance = bc.get_balance(lp1.address, asset_id=lp_asset)
half = round(lp1_lp_balance / 2, 6)
remove = Transaction(lp1.address, lp1.address, 0, op="pool_remove_liquidity", op_data={"pool_key": pool_key, "lp_amount": half})
remove.sign(lp1)
lp1_ocn_before = bc.get_balance(lp1.address)
lp1_test_before = bc.get_balance(lp1.address, asset_id="TEST")
bc.add_transaction(remove)
bc.mine_block("miner-4")
status_after_remove = bc.pool_status(pool_key)
share = half / status_before_remove["lp_supply"]
expected_out_a = round(status_before_remove["reserve_a"] * share, 6)
expected_out_b = round(status_before_remove["reserve_b"] * share, 6)


def close(a, b, eps=1e-6):
    """Same tolerance convention accept_block/is_chain_valid already use
    for reward-sum comparisons — chained float arithmetic across several
    operations isn't guaranteed bit-exactly reversible, so exact equality
    is the wrong tool here, same reasoning as everywhere else in this repo
    that compares a computed amount."""
    return abs(a - b) <= eps


assert close(bc.get_balance(lp1.address), lp1_ocn_before - remove.fee + expected_out_a), bc.get_balance(lp1.address)
assert close(bc.get_balance(lp1.address, asset_id="TEST"), lp1_test_before + expected_out_b)
assert close(bc.get_balance(lp1.address, asset_id=lp_asset), lp1_lp_balance - half)
assert close(status_after_remove["reserve_a"], status_before_remove["reserve_a"] - expected_out_a)
print(f"  burned {half} LP -> got back {expected_out_a} OCN + {expected_out_b} TEST")


print('\n=== Scenario 6: a second liquidity provider gets LP proportional to reserves, not sqrt again ===')
lp2 = Wallet()
bc.mine_block(lp2.address)
give_asset(bc, lp2.address, "TEST", 1000)
status = bc.pool_status(pool_key)
# Contribute at the exact current ratio so neither side is the binding constraint.
contribute_a = 5
contribute_b = round(contribute_a * status["reserve_b"] / status["reserve_a"], 6)
add2 = Transaction(lp2.address, pool_addr, 0, op="pool_add_liquidity", op_data={"pool_key": pool_key, "amount_a": contribute_a, "amount_b": contribute_b})
add2.sign(lp2)
bc.add_transaction(add2)
bc.mine_block("miner-5")
expected_lp2 = round((contribute_a / status["reserve_a"]) * status["lp_supply"], 6)
assert close(bc.get_balance(lp2.address, asset_id=lp_asset), expected_lp2), (bc.get_balance(lp2.address, asset_id=lp_asset), expected_lp2)
print(f"  second LP contributed {contribute_a}/{contribute_b} at the current ratio -> {expected_lp2} LP (proportional, not sqrt bootstrap)")


print('\n=== Scenario 7: op_data validation — canonical pool_key, self-redeem, positive amounts ===')
bc2 = fresh_active_chain()
victim = Wallet()
bc2.mine_block(victim.address)
give_asset(bc2, victim.address, "TEST", 100)
non_canonical = Transaction(victim.address, Blockchain._pool_address("TEST:OCN"), 0, op="pool_add_liquidity",
                             op_data={"pool_key": "TEST:OCN", "amount_a": 1, "amount_b": 1})
non_canonical.sign(victim)
try:
    bc2.add_transaction(non_canonical)
    r1 = False
except ValueError as e:
    r1 = True
    print(f"  correctly rejected non-canonical pool_key ordering: {e}")
assert r1

wrong_target_swap = Transaction(victim.address, Wallet().address, 0, op="pool_swap",
                                 op_data={"pool_key": "OCN:TEST", "asset_in": "OCN", "amount_in": 1})
wrong_target_swap.sign(victim)
try:
    bc2.add_transaction(wrong_target_swap)
    r2 = False
except ValueError as e:
    r2 = True
    print(f"  correctly rejected pool_swap crediting someone other than the sender: {e}")
assert r2

self_pair = Transaction(victim.address, Blockchain._pool_address("OCN:OCN"), 0, op="pool_add_liquidity",
                         op_data={"pool_key": "OCN:OCN", "amount_a": 1, "amount_b": 1})
self_pair.sign(victim)
try:
    bc2.add_transaction(self_pair)
    r3 = False
except ValueError as e:
    r3 = True
    print(f"  correctly rejected a pool pairing an asset with itself: {e}")
assert r3


print('\n=== Scenario 8: full is_chain_valid regression, using ONLY chain-derivable assets (no give_asset seeding) ===')
# bc/bc2 above used give_asset() to seed a "TEST" balance with no real
# transaction history behind it — perfect for isolating pool math, but
# is_chain_valid correctly refuses to validate a chain containing a
# balance it can't independently re-derive from genesis (that's not a
# bug, it's the exact "trust nothing, verify everything" property this
# function exists to enforce — the same thing would happen to a REAL
# chain someone tried to inject a phantom balance into). So this
# scenario builds a fully legitimate chain instead: a real
# stake_pool_deposit mints real stOCN, which is then used as one leg of
# an OCN:stOCN pool — every balance involved is genuinely derivable from
# genesis onward.
bc3 = fresh_active_chain()
lp3 = Wallet()
bc3.mine_block(lp3.address)
stdeposit = Transaction(lp3.address, Blockchain.STAKE_POOL_ADDRESS, 50, op="stake_pool_deposit")
stdeposit.sign(lp3)
bc3.add_transaction(stdeposit)
bc3.mine_block("miner-6")
assert bc3.get_balance(lp3.address, asset_id="stOCN") == 50
stocn_pool_key = Blockchain._pool_key("OCN", "stOCN")
stocn_pool_addr = Blockchain._pool_address(stocn_pool_key)
stocn_add = Transaction(lp3.address, stocn_pool_addr, 0, op="pool_add_liquidity",
                         op_data={"pool_key": stocn_pool_key, "amount_a": 10, "amount_b": 20})
stocn_add.sign(lp3)
bc3.add_transaction(stocn_add)
bc3.mine_block("miner-7")
assert bc3.is_chain_valid(bc3.chain) is True, "a fully legitimate pool-activity chain (no seeded balances) must validate"
rebuilt = Blockchain()
rebuilt.TX_SCHEMA_ACTIVATION_HEIGHT = 0
rebuilt.chain = bc3.chain
rebuilt._rebuild_balance_index()
assert rebuilt.pool_status(stocn_pool_key) == bc3.pool_status(stocn_pool_key), (rebuilt.pool_status(stocn_pool_key), bc3.pool_status(stocn_pool_key))
print("  is_chain_valid: True over a fully chain-derived OCN:stOCN pool history; from-scratch rebuild matches the live index exactly")


print('\n=== ALL SCENARIOS PASSED ===')
