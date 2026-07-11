"""Standalone O-Coin miner — mirrors mining/miner.js's pattern from the
Speepcoin side of this project (that one mines an Ethereum smart contract;
this one mines O-Coin's own real chain, but the shape is the same): fetch
a block template from a node, search for a valid nonce locally, submit
the finished block, repeat. Runs as its own separate process, talking to
node.py purely over HTTP — you can run this on a completely different
machine than the node itself, exactly like real mining hardware talking
to a remote pool or your own node.

Run it:
    pip install -r requirements.txt
    python wallet.py                          # generate a wallet first if you don't have one
    python miner.py --node http://localhost:5100 --address <your wallet address>
"""
import argparse
import functools
import os
import time

# Local network security software on this machine intercepts TLS with a
# cert that's in the OS trust store but not Python's bundled CA list — same
# root cause/fix as trading-platform's server.py. This script always runs
# locally (never deployed), so no Render-specific gating needed here.
import truststore
truststore.inject_into_ssl()

import requests

from pow_hash import header_fields_to_hash

# Only needed against a node that has OCOIN_NODE_SHARED_SECRET set (the
# real deployed node does) — read from the environment so this stays
# secret-free source, not hardcoded. Set it in your shell before running:
#   PowerShell:  $env:OCOIN_NODE_SHARED_SECRET = "..."
#   cmd:         set OCOIN_NODE_SHARED_SECRET=...
NODE_SHARED_SECRET = os.environ.get("OCOIN_NODE_SHARED_SECRET", "")
_HEADERS = {"X-Node-Auth": NODE_SHARED_SECRET} if NODE_SHARED_SECRET else {}

# Python fully buffers stdout when it's not a live terminal (piped to a
# log file, redirected, etc.) — without this, every print() below sits in
# memory and only actually appears when the buffer fills or the process
# exits, making `python miner.py > miner.log 2>&1 &` look silently dead
# for minutes even while real mining work is happening underneath.
print = functools.partial(print, flush=True)

REFRESH_INTERVAL_S = 5   # re-check the node's current template this often, in case someone else found the block first
BATCH_SIZE = 2000         # nonces tried between staleness checks — smaller than the old SHA-256 value since Scrypt is deliberately much slower per hash


def header_hash(template, nonce):
    return header_fields_to_hash(
        template["index"], template["timestamp"], template["merkle_root"],
        template["previous_hash"], template["target"], nonce,
    )


def fetch_template(node, address):
    r = requests.get(f"{node}/mining/template", params={"miner_address": address}, headers=_HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()


def submit_block(node, template, nonce):
    body = {**template, "nonce": nonce}
    r = requests.post(f"{node}/mining/submit", json=body, headers=_HEADERS, timeout=30)
    return r.status_code, r.json()


def mine(node, address):
    if not NODE_SHARED_SECRET and node != "http://localhost:5100" and "127.0.0.1" not in node:
        print("Warning: OCOIN_NODE_SHARED_SECRET isn't set in this terminal — a remote node with that env var configured will reject every request with 401.")
    print(f"O-Coin miner starting — node {node}, rewards to {address}")
    while True:
        template = fetch_template(node, address)
        target = int(template["target"])
        print(f"\nMining block #{template['index']} — {len(template['transactions'])} tx(s) included, target {hex(target)[:18]}...")

        nonce = 0
        start = time.time()
        last_fetch = start
        while True:
            for _ in range(BATCH_SIZE):
                if int(header_hash(template, nonce), 16) < target:
                    elapsed = time.time() - start
                    print(f"Found a valid nonce! nonce={nonce}, took {elapsed:.1f}s, {nonce/max(elapsed,0.001):.0f} h/s")
                    status, result = submit_block(node, template, nonce)
                    if status == 200 and result.get("status") == "ok":
                        print(f"Block accepted: #{result['index']}, hash {result['block_hash'][:16]}...")
                    else:
                        print(f"Block rejected (probably someone else found it first): {result.get('reason')}")
                    nonce = None
                    break
                nonce += 1
            if nonce is None:
                break
            # Periodically refresh the template — the previous_hash we're
            # mining against may have changed (someone else found this
            # block already), in which case every attempt from here on
            # would be wasted work against a stale chain tip.
            if time.time() - last_fetch > REFRESH_INTERVAL_S:
                fresh = fetch_template(node, address)
                if fresh["previous_hash"] != template["previous_hash"]:
                    print("Chain tip moved — someone else found this block, restarting on the new one.")
                    template = fresh
                    nonce = 0
                    start = time.time()
                last_fetch = time.time()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", default="http://localhost:5100")
    parser.add_argument("--address", required=True, help="Your wallet address (see wallet.py) — mining rewards go here")
    args = parser.parse_args()
    try:
        mine(args.node, args.address)
    except KeyboardInterrupt:
        print("\nStopped.")
