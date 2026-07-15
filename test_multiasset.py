"""Verifies Track A Phases A2 (backward-compatible tx schema: op/op_data +
activation height) and A3 (multi-asset ledger) against the real chain and
synthetic adversarial scenarios. Same no-networking, direct-object style as
test_bft_consensus.py / test_balance_index.py.

Scenario 1 is the single most important check in this whole file: every
already-mined, already-signed transaction on the REAL production chain must
still produce the exact same signing string and still verify, under the new
Transaction class that now has op/op_data fields it didn't have before.
"""
import os

from dotenv import load_dotenv

from blockchain import Block, Blockchain
from transaction import Transaction
from wallet import Wallet

load_dotenv()


def old_style_signing_string(tx):
    """Ground truth: the EXACT 5-key format every transaction was signed
    against before op/op_data existed — a literal copy of the pre-A2
    to_signing_string, not a call into the new (possibly buggy) one."""
    import json
    return json.dumps({
        "sender": tx.sender, "recipient": tx.recipient, "amount": tx.amount,
        "fee": tx.fee, "timestamp": tx.timestamp,
    }, sort_keys=True)


def old_style_get_balance(chain, address):
    """Ground truth: the EXACT pre-A3 full-scan loop, hand-copied here so
    Scenario 1 has an oracle that couldn't have inherited any bug from the
    new _apply_transaction_to_balance_dict it's checking against."""
    balance = 0
    for block in chain:
        for tx in block.transactions:
            if tx.sender == address:
                balance -= tx.total_cost()
            if tx.recipient == address:
                balance += tx.amount
    return balance


print("=== Scenario 1: every REAL mined transaction still signs/verifies/balances identically ===")
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("  SKIPPED: no DATABASE_URL in .env")
else:
    import psycopg2

    conn = psycopg2.connect(DATABASE_URL, connect_timeout=10)
    try:
        cur = conn.cursor()
        cur.execute("SELECT data FROM ocoin_blocks_10000 WHERE idx > 0 ORDER BY idx ASC")
        rows = cur.fetchall()
    finally:
        conn.close()
    real_chain_obj = Blockchain()
    loaded_blocks = [Block.from_dict(r[0]) for r in rows]
    candidate = [real_chain_obj.chain[0]] + loaded_blocks
    assert real_chain_obj.is_chain_valid(candidate) is True, "real chain must still validate under the new rules"
    print(f"  is_chain_valid: True over {len(candidate)} real blocks")

    # The live chain now contains BOTH eras for real: plain transactions
    # (which must still produce the exact pre-A2 signing string) and
    # post-activation op-bearing ones (the user's actual stake/liquidity/
    # swap history — must verify, but is NOT expected to match the old
    # signing format: op fields are deliberately part of what gets
    # signed). This scenario originally asserted no op transaction could
    # exist on the real chain at all; that stopped being true the day the
    # fork activated at height 90 and real op transactions were mined.
    signature_mismatches = 0
    validity_failures = 0
    checked_signed = 0
    checked_op = 0
    for block in candidate:
        for tx in block.transactions:
            if tx.sender == "0":
                continue
            if tx.op is not None:
                checked_op += 1
                if not tx.is_valid():
                    validity_failures += 1
                continue
            checked_signed += 1
            if tx.to_signing_string() != old_style_signing_string(tx):
                signature_mismatches += 1
            if not tx.is_valid():
                validity_failures += 1
    print(f"  {checked_signed} real plain + {checked_op} real op-bearing signed transactions: "
          f"{signature_mismatches} signing-string mismatches, {validity_failures} now-invalid")
    assert signature_mismatches == 0, "op=None must reproduce the exact pre-A2 signing string, or every historical signature breaks"
    assert validity_failures == 0, "no historical transaction should have become invalid"

    # The old-style scanner predates ops — it reads every transaction as a
    # plain OCN move of tx.amount, which is simply wrong for op
    # transactions (their real quantities live in op_data). So this
    # regression comparison is only meaningful over the chain's PRE-FORK
    # PREFIX: every block before the first op-bearing one. That still
    # tests exactly what it was written to test — that op=None accounting
    # is bit-for-bit unchanged — it just no longer pretends the old
    # scanner understands transaction types that didn't exist in its era.
    first_op_height = next(
        (b.index for b in candidate if any(tx.op is not None for tx in b.transactions)),
        len(candidate),
    )
    prefix = candidate[:first_op_height]
    addresses = {tx.sender for b in prefix for tx in b.transactions} | {tx.recipient for b in prefix for tx in b.transactions}
    addresses.discard("0")
    balance_mismatches = [
        (addr, old_style_get_balance(prefix, addr), real_chain_obj.get_balance(addr, chain=prefix))
        for addr in addresses
    ]
    balance_mismatches = [m for m in balance_mismatches if m[1] != m[2]]
    print(f"  checked {len(addresses)} addresses' get_balance(chain=...) against the old hand-rolled scan over the {len(prefix)}-block pre-fork prefix: {len(balance_mismatches)} mismatches")
    assert not balance_mismatches, f"chain= path must match the old OCN-only scan exactly over pre-fork history: {balance_mismatches}"


print("\n=== Scenario 2: op=None transaction signs/verifies exactly as before A2 existed ===")
w1, w2 = Wallet(), Wallet()
tx = Transaction(w1.address, w2.address, 5, timestamp=12345.0)
tx.sign(w1)
assert tx.to_signing_string() == old_style_signing_string(tx)
assert tx.is_valid() is True
print("  plain transfer: signing string matches pre-A2 format, signature verifies")


print("\n=== Scenario 3: activation height gates op-bearing transactions (mempool + block level) ===")
bc = Blockchain()
staker, other = Wallet(), Wallet()
op_tx = Transaction(staker.address, other.address, 1, op="transfer_asset", op_data={"asset_id": "TEST"})
op_tx.sign(staker)
try:
    bc.add_transaction(op_tx)
    raised = False
except ValueError as e:
    raised = True
    print(f"  mempool correctly rejected pre-activation op tx: {e}")
assert raised, "op-bearing tx must be rejected by add_transaction before TX_SCHEMA_ACTIVATION_HEIGHT"

# Simulate a block submitted directly (bypassing add_transaction entirely —
# the "malformed direct block submission attempting to bypass mempool-level
# checks" adversarial case) — accept_block must catch it independently.
bc.balances[(staker.address, "TEST")] = 100  # test-only seed; no mint op exists yet (A4/A5)
reward_amount = bc.reward_at_height(bc.latest_block.index + 1) + op_tx.fee  # must sum correctly or the (unrelated) coinbase-sum check masks the check this scenario actually targets
bad_block = Block(
    index=bc.latest_block.index + 1,
    transactions=[Transaction("0", staker.address, reward_amount), op_tx],
    previous_hash=bc.latest_block.compute_hash(),
    target=bc.current_target,
)
from blockchain import proof_of_work  # noqa: E402
bad_block = proof_of_work(bad_block)
try:
    bc.accept_block(bad_block)
    block_raised = False
except ValueError as e:
    block_raised = True
    print(f"  accept_block correctly rejected a directly-submitted pre-activation op block: {e}")
assert block_raised, "accept_block must independently enforce the activation height, not just trust mempool admission"


print("\n=== Scenario 4: after activation, transfer_asset moves the named asset and OCN fee separately ===")
bc2 = Blockchain()
bc2.TX_SCHEMA_ACTIVATION_HEIGHT = 0  # test-only override — real deployment chooses this deliberately, see blockchain.py's comment
bc2.mine_block(staker.address)  # gives staker some real OCN to pay the fee with
bc2.balances[(staker.address, "TEST")] = 100  # test-only seed
transfer = Transaction(staker.address, other.address, 30, op="transfer_asset", op_data={"asset_id": "TEST"})
transfer.sign(staker)
bc2.add_transaction(transfer)
bc2.mine_block("miner-2")
assert bc2.get_balance(staker.address, asset_id="TEST") == 70, bc2.get_balance(staker.address, asset_id="TEST")
assert bc2.get_balance(other.address, asset_id="TEST") == 30
assert bc2.get_balance(staker.address) == bc2.get_balance(staker.address, chain=bc2.chain), "OCN (fee-debited) balance must still match full scan"
print(f"  staker TEST balance: 100 -> {bc2.get_balance(staker.address, asset_id='TEST')}, other TEST balance: 0 -> {bc2.get_balance(other.address, asset_id='TEST')}")
print(f"  staker's OCN balance correctly debited by the fee alone (not the TEST amount): matches full scan")


print("\n=== Scenario 5: insufficient asset balance is rejected at BOTH mempool and block level ===")
bc3 = Blockchain()
bc3.TX_SCHEMA_ACTIVATION_HEIGHT = 0
bc3.mine_block(staker.address)
bc3.balances[(staker.address, "TEST")] = 10
overspend = Transaction(staker.address, other.address, 9999, op="transfer_asset", op_data={"asset_id": "TEST"})
overspend.sign(staker)
try:
    bc3.add_transaction(overspend)
    mempool_raised = False
except ValueError as e:
    mempool_raised = True
    print(f"  mempool correctly rejected overspend: {e}")
assert mempool_raised

overspend_reward = bc3.reward_at_height(bc3.latest_block.index + 1) + overspend.fee
overspend_block = Block(
    index=bc3.latest_block.index + 1,
    transactions=[Transaction("0", "miner-3", overspend_reward), overspend],
    previous_hash=bc3.latest_block.compute_hash(),
    target=bc3.current_target,
)
overspend_block = proof_of_work(overspend_block)
try:
    bc3.accept_block(overspend_block)
    block_raised2 = False
except ValueError as e:
    block_raised2 = True
    print(f"  accept_block correctly rejected a directly-submitted overspend block: {e}")
assert block_raised2, "a block manufacturing a spend against a balance that was never there must be rejected"
assert bc3.get_balance(staker.address, asset_id="TEST") == 10, "rejected block must not have touched the index"


print("\n=== Scenario 6: reserved asset_id \"OCN\" cannot be moved via transfer_asset ===")
bc4 = Blockchain()
bc4.TX_SCHEMA_ACTIVATION_HEIGHT = 0
sneaky = Transaction(staker.address, other.address, 1, op="transfer_asset", op_data={"asset_id": "OCN"})
sneaky.sign(staker)
try:
    bc4.add_transaction(sneaky)
    sneaky_raised = False
except ValueError as e:
    sneaky_raised = True
    print(f"  correctly rejected transfer_asset targeting OCN: {e}")
assert sneaky_raised


print("\n=== Scenario 7: coinbase transactions can never carry an op ===")
fake_coinbase = Transaction("0", staker.address, 50, op="transfer_asset", op_data={"asset_id": "TEST"})
assert fake_coinbase.is_valid() is False, "sender=0 with an op set must be invalid, regardless of signature"
print("  sender=0 + op set correctly rejected by Transaction.is_valid()")


print("\n=== ALL SCENARIOS PASSED ===")
