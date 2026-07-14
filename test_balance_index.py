"""Verifies Blockchain's incrementally-maintained balance index
(self.balances / _rebuild_balance_index / _apply_transaction_to_balances)
against the pre-existing full-scan get_balance(chain=...) path, which stays
byte-for-byte unchanged and is the ground truth here. No networking, no
Flask — direct Blockchain() instances, same "prove the logic before trusting
it" style as test_bft_consensus.py.

Scenario 1 reads the REAL chain from the production Supabase table
(read-only SELECT, same query load_chain() itself runs) to check the index
against real mined history, not just synthetic blocks — but never writes to
it and never touches the live node process.
"""
import os

from dotenv import load_dotenv

from blockchain import Block, Blockchain

load_dotenv()


def full_scan_balance(blockchain, address):
    """Ground truth: the untouched chain=... path in get_balance."""
    return blockchain.get_balance(address, chain=blockchain.chain)


def assert_index_matches_full_scan(blockchain, label):
    addresses = set()
    for block in blockchain.chain:
        for tx in block.transactions:
            addresses.add(tx.sender)
            addresses.add(tx.recipient)
    addresses.discard("0")  # coinbase sender, not a real address
    mismatches = []
    for addr in addresses:
        indexed = blockchain.get_balance(addr)
        scanned = full_scan_balance(blockchain, addr)
        if indexed != scanned:
            mismatches.append((addr, indexed, scanned))
    print(f"  [{label}] checked {len(addresses)} addresses, {len(mismatches)} mismatches")
    assert not mismatches, f"{label}: index disagrees with full scan for {mismatches}"


print("=== Scenario 1: index vs full-scan against the REAL production chain (read-only) ===")
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
    real_chain = Blockchain()
    loaded_blocks = [Block.from_dict(r[0]) for r in rows]
    candidate = [real_chain.chain[0]] + loaded_blocks
    assert real_chain.is_chain_valid(candidate), "real production chain failed is_chain_valid — cannot proceed"
    real_chain.chain = candidate
    real_chain._rebuild_balance_index()
    print(f"  loaded {len(candidate)} real blocks from ocoin_blocks_10000")
    assert_index_matches_full_scan(real_chain, "real chain after rebuild")

    # Consensus-safety: is_chain_valid must be unaffected by any of this —
    # it only ever reads chain=..., never self.balances.
    assert real_chain.is_chain_valid(real_chain.chain) is True
    print("  is_chain_valid(real chain) still True — consensus path untouched")


print("\n=== Scenario 2: incremental accept_block() keeps the index correct block-by-block ===")
bc = Blockchain()
assert_index_matches_full_scan(bc, "fresh genesis")
for i in range(5):
    bc.mine_block(f"miner-address-{i % 2}")  # two alternating miner addresses
    assert_index_matches_full_scan(bc, f"after mined block {i + 1}")


print("\n=== Scenario 3: reorg (replace_chain) rebuilds the index to match the new tip, not the old one ===")
chain_a = Blockchain()
for _ in range(2):
    chain_a.mine_block("miner-a")
chain_b = Blockchain()
for _ in range(4):  # longer, so it wins
    chain_b.mine_block("miner-b")
pre_reorg_miner_a_balance = chain_a.get_balance("miner-a")
assert pre_reorg_miner_a_balance > 0, "sanity: miner-a should show a balance before the reorg"
replaced = chain_a.replace_chain(chain_b.chain)
assert replaced is True, "longer valid chain should have won"
print(f"  chain_a adopted chain_b's {len(chain_b.chain)}-block chain (was {3} blocks)")
assert chain_a.get_balance("miner-a") == 0, "miner-a's reward should be GONE after the reorg (only mined on the losing chain)"
assert chain_a.get_balance("miner-b") == full_scan_balance(chain_a, "miner-b") == full_scan_balance(chain_b, "miner-b")
assert_index_matches_full_scan(chain_a, "chain_a after adopting chain_b via replace_chain")


print("\n=== Scenario 4: mempool-inclusive balance = indexed confirmed balance + pending delta ===")
bc2 = Blockchain()
bc2.mine_block("payer")
confirmed = bc2.get_balance("payer")
assert confirmed == full_scan_balance(bc2, "payer")
# Directly append a pending tx to the mempool (bypassing add_transaction's
# own balance/signature checks — this test only cares whether
# include_pending correctly layers on top of the indexed confirmed
# balance, not whether add_transaction's admission logic works).
from transaction import Transaction  # noqa: E402
pending_tx = Transaction(sender="payer", recipient="payee", amount=10, fee=0.01, timestamp=0)
bc2.mempool.append(pending_tx)
with_pending = bc2.get_balance("payer", include_pending=True)
assert with_pending == confirmed - pending_tx.total_cost(), (
    f"expected {confirmed - pending_tx.total_cost()}, got {with_pending}"
)
assert bc2.get_balance("payer") == confirmed, "confirmed (non-pending) balance must be unaffected by mempool contents"
print(f"  confirmed={confirmed}, with_pending={with_pending} (delta = -{pending_tx.total_cost()}) — correct")


print("\n=== ALL SCENARIOS PASSED ===")
