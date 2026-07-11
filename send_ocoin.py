"""Send O-Coin from your own wallet to another address.

Interactive only — your private key is entered via hidden input (getpass)
and used only in-memory to sign one transaction. It is never written to
disk, printed, or sent anywhere except locally to build the signature.

Run:
    python send_ocoin.py
"""
import getpass
import os

# Same TLS-interception workaround as miner.py/trading-platform's server.py
# — harmless if this machine doesn't actually need it.
import truststore
truststore.inject_into_ssl()

import requests

from wallet import Wallet
from transaction import Transaction

NODE = "https://o-coin.onrender.com"
# Read from the environment rather than hardcoded, so this file (tracked in
# this repo) never contains the actual secret in plaintext. Set it once per
# terminal session before running this script — same value used everywhere
# else (Render's env var, trading-platform's .env):
#   PowerShell:  $env:OCOIN_NODE_SHARED_SECRET = "..."
#   bash:        export OCOIN_NODE_SHARED_SECRET="..."
NODE_SHARED_SECRET = os.environ.get("OCOIN_NODE_SHARED_SECRET", "")

if not NODE_SHARED_SECRET:
    print("Warning: OCOIN_NODE_SHARED_SECRET isn't set in this terminal — the deployed node will reject this with 401 Unauthorized.")

private_key_hex = getpass.getpass("Your private key (hidden as you type): ").strip()
wallet = Wallet(private_key_hex=private_key_hex)
print(f"Sending from address: {wallet.address}")

recipient = input("Recipient address: ").strip()
amount = float(input("Amount to send: ").strip())

tx = Transaction(wallet.address, recipient, amount)
tx.sign(wallet)

headers = {"X-Node-Auth": NODE_SHARED_SECRET} if NODE_SHARED_SECRET else {}
# Render's free tier spins the node down after ~15min idle and can take
# 30-60s to wake back up on the next request — a short timeout here just
# means giving up right as the real response was about to arrive.
print("Submitting (may take up to a minute if the node was asleep)...")
resp = requests.post(f"{NODE}/transactions/new", json=tx.to_dict(), headers=headers, timeout=75)
data = resp.json()
if data.get("status") == "ok":
    print(f"Sent! transaction_hash: {data['transaction_hash']}")
    print("It'll show up once a block confirms it (mining/staking on the node picks it up from the mempool).")
else:
    print(f"Failed: {data.get('reason')}")
