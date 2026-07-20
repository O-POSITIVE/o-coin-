"""Local-only backend for the NEXUS O-Coin Control Deck web window."""
import base64
from collections import deque
import ctypes
from ctypes import wintypes
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import requests
import truststore
from transaction import Transaction
from wallet import Wallet

truststore.inject_into_ssl()
ROOT = os.path.dirname(os.path.abspath(__file__))
NEXUS_SOURCE = r"C:\Users\notbe\Desktop\trading-platform"
VAULT = os.path.join(ROOT, "ocoin_wallet_vault.dat")
PORT = 51842
NODE = "https://o-coin.onrender.com"
state = {"key": None, "address": None, "miner": None, "lines": deque(maxlen=180)}


class Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def blob(data):
    buffer = ctypes.create_string_buffer(data)
    return Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def protect(data):
    source, keep = blob(data); result = Blob()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), "O-Coin Wallet Vault", None, None, None, 1, ctypes.byref(result)):
        raise ctypes.WinError()
    try: return ctypes.string_at(result.pbData, result.cbData)
    finally: ctypes.windll.kernel32.LocalFree(result.pbData)


def unprotect(data):
    source, keep = blob(data); result = Blob()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise ctypes.WinError()
    try: return ctypes.string_at(result.pbData, result.cbData)
    finally: ctypes.windll.kernel32.LocalFree(result.pbData)


def read_vault():
    with open(VAULT, "rb") as handle:
        return json.loads(unprotect(base64.b64decode(handle.read())).decode())


def save_vault(address, key):
    payload = json.dumps({"address": address, "private_key": key}).encode()
    with open(VAULT, "wb") as handle:
        handle.write(base64.b64encode(protect(payload)))


def headers(secret):
    return {"X-Node-Auth": secret} if secret else {}


def miner_reader(process):
    for line in iter(process.stdout.readline, ""):
        state["lines"].append(line.rstrip())
    state["lines"].append("[ miner stopped ]")


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, *_args):
        pass

    def json(self, data, status=200):
        raw = json.dumps(data).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def body(self):
        size = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(size) or b"{}")

    def do_GET(self):
        shader_files = {
            "/_nexus_gr3_shaders.js": "_gr3_test_shaders.js",
            "/_nexus_gr3_harness.js": "_gr3_test_harness.js",
        }
        if self.path in shader_files:
            with open(os.path.join(NEXUS_SOURCE, shader_files[self.path]), encoding="utf-8") as handle:
                raw = handle.read().encode("utf-8")
            self.send_response(200); self.send_header("Content-Type", "application/javascript; charset=utf-8"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
            return
        if self.path == "/ocoin_control_center.html":
            # Keep the deck markup compact while layering visual experiments
            # as separately cache-busted local assets.
            with open(os.path.join(ROOT, "ocoin_control_center.html"), encoding="utf-8") as handle:
                page = handle.read()
            page = page.replace("</head>", '<link rel="stylesheet" href="/ocoin_blackhole.css"></head>')
            page = page.replace("</body>", '<script src="/_nexus_gr3_shaders.js"></script><script src="/_nexus_gr3_harness.js"></script><script src="/ocoin_gr_backdrop.js"></script></body>')
            raw = page.encode("utf-8")
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
            return
        if self.path == "/api/status":
            process = state["miner"]
            self.json({"address": state["address"], "vault": os.path.exists(VAULT), "mining": bool(process and process.poll() is None), "lines": list(state["lines"])})
            return
        if self.path.startswith("/api/balance"):
            from urllib.parse import parse_qs, urlparse
            params = parse_qs(urlparse(self.path).query); address = params.get("address", [""])[0]; node = params.get("node", [NODE])[0]; secret = params.get("secret", [""])[0]
            try:
                result = requests.get(f"{node.rstrip('/')}/balance/{address}", headers=headers(secret), timeout=75); result.raise_for_status(); self.json(result.json())
            except Exception as error: self.json({"error": str(error)}, 502)
            return
        return super().do_GET()

    def do_POST(self):
        try:
            data = self.body()
            if self.path == "/api/wallet/create":
                wallet = Wallet(); key = wallet.private_key_hex(); save_vault(wallet.address, key)
                state.update(key=key, address=wallet.address)
                self.json({"address": wallet.address, "backup_key": key})
            elif self.path == "/api/wallet/unlock":
                vault = read_vault(); wallet = Wallet(private_key_hex=vault["private_key"])
                if wallet.address != vault["address"]: raise ValueError("Vault integrity check failed")
                state.update(key=vault["private_key"], address=wallet.address); self.json({"address": wallet.address})
            elif self.path == "/api/wallet/lock":
                state.update(key=None, address=None); self.json({"ok": True})
            elif self.path == "/api/miner/start":
                address, node, secret = data.get("address", ""), data.get("node", NODE).rstrip("/"), data.get("secret", "")
                if len(address) != 40: raise ValueError("A valid 40-character reward address is required")
                process = state["miner"]
                if process and process.poll() is None: raise ValueError("Miner is already running")
                env = os.environ.copy()
                if secret: env["OCOIN_NODE_SHARED_SECRET"] = secret
                state["lines"].clear(); state["lines"].append("[ NEXUS miner started ]")
                state["miner"] = subprocess.Popen([sys.executable, "-u", os.path.join(ROOT, "miner.py"), "--node", node, "--address", address], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
                threading.Thread(target=miner_reader, args=(state["miner"],), daemon=True).start(); self.json({"ok": True})
            elif self.path == "/api/miner/stop":
                process = state["miner"]
                if process and process.poll() is None: process.terminate()
                self.json({"ok": True})
            elif self.path == "/api/send":
                key = state["key"] or data.get("key", "")
                wallet = Wallet(private_key_hex=key); recipient = data["recipient"].strip(); amount = float(str(data["amount"]).replace(",", "")); node = data.get("node", NODE).rstrip("/")
                if len(recipient) != 40 or amount <= 0: raise ValueError("Recipient address or amount is invalid")
                transaction = Transaction(wallet.address, recipient, amount); transaction.sign(wallet)
                response = requests.post(f"{node}/transactions/new", json=transaction.to_dict(), headers=headers(data.get("secret", "")), timeout=75)
                result = response.json()
                if not response.ok or result.get("status") != "ok": raise ValueError(result.get("reason", "Node rejected transaction"))
                self.json(result)
            else: self.json({"error": "Not found"}, 404)
        except Exception as error:
            self.json({"error": str(error)}, 400)


def open_window():
    url = f"http://127.0.0.1:{PORT}/ocoin_control_center.html"
    candidates = [shutil.which("msedge"), os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Microsoft", "Edge", "Application", "msedge.exe"), os.path.join(os.environ.get("ProgramFiles", ""), "Microsoft", "Edge", "Application", "msedge.exe")]
    edge = next((path for path in candidates if path and os.path.exists(path)), None)
    if edge: subprocess.Popen([edge, f"--app={url}"])
    else: webbrowser.open(url)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Timer(.4, open_window).start()
    server.serve_forever()
