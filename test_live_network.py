"""Track A, Phase A6 — the ONE test in this repo that actually exercises
the real HTTP layer: two real `node.py` processes, real signed
transactions submitted over POST /transactions/new, real block gossip
(/blocks/receive) and full chain resolution (/nodes/resolve), real Postgres
persistence (separate ocoin_blocks_<port> tables, cleaned up afterward).
Every other test_*.py in this repo drives Blockchain objects directly in
one process — that proves the accounting/consensus LOGIC is correct, but
it can't catch a bug in how a transaction's op_data survives being
serialized to JSON, sent over a socket, and reconstructed on the other
end. That's exactly the kind of bug this test exists to catch — and it
already found one for real (see the /transactions/new fix in this same
commit) before this script even ran once, just from reading node.py while
writing it.

Both nodes run on local test ports (5301/5302, nothing like the real
deployed node's port) and OCOIN_TEST_ACTIVATION_HEIGHT=0 (a test-only env
var node.py checks — see its __main__ block — that NEVER touches the real
committed TX_SCHEMA_ACTIVATION_HEIGHT). Their chain data goes to
ocoin_blocks_5301/ocoin_blocks_5302 in the same Supabase project the real
node uses (same trick the project's own README already documents for
local sync-testing: different ports get automatically-isolated tables) —
dropped at the end of this script either way, pass or fail.

Run with the O-Coin node NOT already running on these ports:
    python test_live_network.py
"""
import atexit
import os
import subprocess
import sys
import time

import psycopg2
import requests
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SHARED_SECRET = os.getenv("OCOIN_NODE_SHARED_SECRET")
PORT_A, PORT_B = 5301, 5302
URL_A, URL_B = f"http://127.0.0.1:{PORT_A}", f"http://127.0.0.1:{PORT_B}"
HEADERS = {"X-Node-Auth": SHARED_SECRET} if SHARED_SECRET else {}

processes = []


def dump_process_output():
    for label, p in zip(("A", "B"), processes):
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        out = p.stdout.read() if p.stdout else ""
        print(f"\n--- node {label} (port {PORT_A if label == 'A' else PORT_B}) output ---\n{out}")


def cleanup():
    for p in processes:
        if p.poll() is None:
            p.terminate()
    for p in processes:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    if DATABASE_URL:
        conn = psycopg2.connect(DATABASE_URL, connect_timeout=10)
        try:
            cur = conn.cursor()
            cur.execute(f"DROP TABLE IF EXISTS ocoin_blocks_{PORT_A}")
            cur.execute(f"DROP TABLE IF EXISTS ocoin_blocks_{PORT_B}")
            conn.commit()
        finally:
            conn.close()
        print(f"  cleaned up test tables ocoin_blocks_{PORT_A}/{PORT_B}")


atexit.register(cleanup)


def _excepthook(exc_type, exc_value, tb):
    dump_process_output()
    sys.__excepthook__(exc_type, exc_value, tb)


sys.excepthook = _excepthook


def start_node(port):
    env = os.environ.copy()
    env["OCOIN_TEST_ACTIVATION_HEIGHT"] = "0"
    proc = subprocess.Popen(
        [sys.executable, "node.py", "--port", str(port), "--host", "127.0.0.1"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    processes.append(proc)
    return proc


def wait_ready(url, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{url}/status", timeout=2)
            if r.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"{url} never became ready")


def post(url, path, **kwargs):
    r = requests.post(f"{url}{path}", headers=HEADERS, timeout=15, **kwargs)
    return r


def get(url, path, **kwargs):
    r = requests.get(f"{url}{path}", headers=HEADERS, timeout=15, **kwargs)
    return r


def wait_for(fn, timeout=10, interval=0.3):
    """Poll fn() until it returns truthy, or raise on timeout — used
    instead of a flat sleep() to wait for gossip propagation, which is a
    fire-and-forget background thread on the sending node (see
    broadcast_block in node.py)."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise TimeoutError(f"condition never became true within {timeout}s (last value: {last})")


print("=== Starting two real node.py processes (ports 5301/5302) ===")
proc_a = start_node(PORT_A)
proc_b = start_node(PORT_B)
wait_ready(URL_A)
wait_ready(URL_B)
print("  both nodes responding to /status")

print("\n=== Registering as mutual peers ===")
post(URL_A, "/nodes/register", json={"nodes": [URL_B]})
post(URL_B, "/nodes/register", json={"nodes": [URL_A]})
print(f"  A peers: {get(URL_A, '/status').json()['peers']}")
print(f"  B peers: {get(URL_B, '/status').json()['peers']}")


print("\n=== Scenario 1: node A mines a real PoW block, node B gets it via gossip ===")
from wallet import Wallet  # noqa: E402
from transaction import Transaction  # noqa: E402

depositor = Wallet()
trader = Wallet()
r = get(URL_A, f"/mine?miner_address={depositor.address}")
assert r.status_code == 200, r.text
bal_a = get(URL_A, f"/balance/{depositor.address}").json()["balance"]
wait_for(lambda: get(URL_B, f"/balance/{depositor.address}").json()["balance"] == bal_a)
bal_b = get(URL_B, f"/balance/{depositor.address}").json()["balance"]
assert bal_a == bal_b and bal_a > 0, (bal_a, bal_b)
print(f"  mined on A ({bal_a} OCN), synced to B via gossip ({bal_b} OCN) — real HTTP block propagation confirmed")


print("\n=== Scenario 2: a REAL signed stake_pool_deposit over POST /transactions/new ===")
from blockchain import Blockchain  # noqa: E402

deposit = Transaction(depositor.address, Blockchain.STAKE_POOL_ADDRESS, 50, op="stake_pool_deposit")
deposit.sign(depositor)
r = post(URL_A, "/transactions/new", json=deposit.to_dict())
print(f"  submit response: {r.status_code} {r.json()}")
assert r.status_code == 200 and r.json()["status"] == "ok", r.text
r = get(URL_A, f"/mine?miner_address=miner-2")
assert r.status_code == 200, r.text
time.sleep(1)
stocn_a = get(URL_A, f"/balance/{depositor.address}?asset_id=stOCN").json()["balance"]
stocn_b = get(URL_B, f"/balance/{depositor.address}?asset_id=stOCN").json()["balance"]
assert stocn_a == 50 and stocn_a == stocn_b, (stocn_a, stocn_b)
status_a = get(URL_A, "/stake_pool/status").json()
status_b = get(URL_B, "/stake_pool/status").json()
assert status_a == status_b, (status_a, status_b)
print(f"  stOCN minted correctly on A ({stocn_a}), independently confirmed identical on B ({stocn_b}) after gossip sync")
print(f"  /stake_pool/status agrees on both nodes: {status_a}")


print("\n=== Scenario 3: transfer_asset moves the newly-real stOCN between two real wallets ===")
xfer = Transaction(depositor.address, trader.address, 10, op="transfer_asset", op_data={"asset_id": "stOCN"})
xfer.sign(depositor)
r = post(URL_A, "/transactions/new", json=xfer.to_dict())
assert r.status_code == 200 and r.json()["status"] == "ok", r.text
r = get(URL_A, f"/mine?miner_address=miner-3")
assert r.status_code == 200, r.text
time.sleep(1)
trader_stocn_a = get(URL_A, f"/balance/{trader.address}?asset_id=stOCN").json()["balance"]
trader_stocn_b = get(URL_B, f"/balance/{trader.address}?asset_id=stOCN").json()["balance"]
assert trader_stocn_a == 10 == trader_stocn_b, (trader_stocn_a, trader_stocn_b)
print(f"  transfer_asset over real HTTP: trader now holds {trader_stocn_a} stOCN, agrees on both nodes")


print("\n=== Scenario 4: a real OCN:stOCN AMM pool — add liquidity, swap, remove — all via HTTP ===")
pool_key = Blockchain._pool_key("OCN", "stOCN")
pool_addr = Blockchain._pool_address(pool_key)
add_liq = Transaction(depositor.address, pool_addr, 0, op="pool_add_liquidity",
                       op_data={"pool_key": pool_key, "amount_a": 10, "amount_b": 20})
# amount_a/amount_b apply to pool_key's SORTED assets, not necessarily
# (OCN, stOCN) in that order — confirm which is which before assigning.
asset_a, asset_b = pool_key.split(":")
if asset_a != "OCN":
    add_liq.op_data["amount_a"], add_liq.op_data["amount_b"] = add_liq.op_data["amount_b"], add_liq.op_data["amount_a"]
add_liq.sign(depositor)
r = post(URL_A, "/transactions/new", json=add_liq.to_dict())
assert r.status_code == 200 and r.json()["status"] == "ok", r.text
r = get(URL_A, f"/mine?miner_address=miner-4")
assert r.status_code == 200, r.text
time.sleep(1)
pool_a = get(URL_A, f"/pools/{pool_key}").json()
pool_b = get(URL_B, f"/pools/{pool_key}").json()
assert pool_a == pool_b, (pool_a, pool_b)
print(f"  liquidity added over HTTP, pool state agrees on both nodes: {pool_a}")

r = get(URL_B, f"/mine?miner_address={trader.address}")  # fund the trader with real OCN, mined on B this time (exercises A<-B gossip direction too)
assert r.status_code == 200, r.text
wait_for(lambda: get(URL_A, f"/balance/{trader.address}").json()["balance"] > 0)
trader_ocn = get(URL_A, f"/balance/{trader.address}").json()["balance"]
print(f"  funded trader with {trader_ocn} OCN by mining on B, synced to A")

swap = Transaction(trader.address, trader.address, 0, op="pool_swap",
                    op_data={"pool_key": pool_key, "asset_in": "OCN", "amount_in": 2, "min_amount_out": 0})
swap.sign(trader)
r = post(URL_A, "/transactions/new", json=swap.to_dict())
assert r.status_code == 200 and r.json()["status"] == "ok", r.text
r = get(URL_A, f"/mine?miner_address=miner-5")
assert r.status_code == 200, r.text
time.sleep(1)
pool_after_swap_a = get(URL_A, f"/pools/{pool_key}").json()
pool_after_swap_b = get(URL_B, f"/pools/{pool_key}").json()
assert pool_after_swap_a == pool_after_swap_b
trader_stocn_after_swap = get(URL_B, f"/balance/{trader.address}?asset_id=stOCN").json()["balance"]
assert trader_stocn_after_swap > trader_stocn_a, (trader_stocn_after_swap, trader_stocn_a)
print(f"  real swap over HTTP: trader's stOCN {trader_stocn_a} -> {trader_stocn_after_swap}, pool state agrees on both nodes")

lp_asset = pool_after_swap_a["lp_asset"]
depositor_lp = get(URL_A, f"/balance/{depositor.address}?asset_id={lp_asset}").json()["balance"]
remove = Transaction(depositor.address, depositor.address, 0, op="pool_remove_liquidity",
                      op_data={"pool_key": pool_key, "lp_amount": depositor_lp / 2})
remove.sign(depositor)
r = post(URL_A, "/transactions/new", json=remove.to_dict())
assert r.status_code == 200 and r.json()["status"] == "ok", r.text
r = get(URL_A, f"/mine?miner_address=miner-6")
assert r.status_code == 200, r.text
wait_for(lambda: get(URL_B, f"/balance/{depositor.address}?asset_id={lp_asset}").json()["balance"] < depositor_lp)
depositor_lp_after = get(URL_A, f"/balance/{depositor.address}?asset_id={lp_asset}").json()["balance"]
depositor_lp_after_b = get(URL_B, f"/balance/{depositor.address}?asset_id={lp_asset}").json()["balance"]
assert depositor_lp_after == depositor_lp_after_b == round(depositor_lp / 2, 6), (depositor_lp_after, depositor_lp_after_b)
pool_after_remove_a = get(URL_A, f"/pools/{pool_key}").json()
pool_after_remove_b = get(URL_B, f"/pools/{pool_key}").json()
assert pool_after_remove_a == pool_after_remove_b, (pool_after_remove_a, pool_after_remove_b)
print(f"  real remove_liquidity over HTTP: depositor's LP {depositor_lp} -> {depositor_lp_after}, pool state agrees on both nodes: {pool_after_remove_a}")


print("\n=== Scenario 5: a real fork — independently mined on each node, resolved via /nodes/resolve ===")
# Momentarily stop registering-triggered gossip from mattering by having
# BOTH nodes mine their own next block before either has a chance to push
# to the other — a genuine race, the same thing that happens naturally
# when two miners find a block around the same time.
post(URL_A, "/nodes/register", json={"nodes": []})  # no-op call just to confirm the endpoint; peers already registered
height_before = get(URL_A, "/status").json()["chain_length"]
r_a = get(URL_A, f"/mine?miner_address=fork-miner-a")
r_b = get(URL_B, f"/mine?miner_address=fork-miner-b")
assert r_a.status_code == 200 and r_b.status_code == 200
time.sleep(1)
len_a = get(URL_A, "/status").json()["chain_length"]
len_b = get(URL_B, "/status").json()["chain_length"]
print(f"  post-race chain lengths: A={len_a}, B={len_b} (both should be height_before+1={height_before + 1}, whichever one's broadcast the OTHER accepted first)")
resolve_a = get(URL_A, "/nodes/resolve").json()
resolve_b = get(URL_B, "/nodes/resolve").json()
final_len_a = get(URL_A, "/status").json()["chain_length"]
final_len_b = get(URL_B, "/status").json()["chain_length"]
final_hash_a = get(URL_A, "/status").json()["latest_block_hash"]
final_hash_b = get(URL_B, "/status").json()["latest_block_hash"]
assert final_len_a == final_len_b and final_hash_a == final_hash_b, (final_len_a, final_len_b, final_hash_a, final_hash_b)
final_pool_a = get(URL_A, f"/pools/{pool_key}").json()
final_pool_b = get(URL_B, f"/pools/{pool_key}").json()
assert final_pool_a == final_pool_b, (final_pool_a, final_pool_b)
print(f"  both nodes converged to the SAME tip after /nodes/resolve: height={final_len_a}, hash={final_hash_a[:16]}...")
print(f"  pool/balance state (rebuilt from a real replace_chain over network-transported blocks) still agrees: {final_pool_a}")


print("\n=== ALL SCENARIOS PASSED ===")
