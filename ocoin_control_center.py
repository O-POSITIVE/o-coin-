"""NEXUS-styled local wallet, miner and send console for O-Coin.

The wallet vault uses Windows DPAPI. The encrypted vault is usable only by the
same Windows account that saved it; the private key is never logged, placed on
the command line, or sent to a node. Keep an offline backup of the key: DPAPI
is deliberately not a substitute for a recovery backup.
"""
import base64
import ctypes
from ctypes import wintypes
import json
import math
import os
import queue
import random
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox

import requests
import truststore

from transaction import Transaction
from wallet import Wallet

truststore.inject_into_ssl()

APP_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_PATH = os.path.join(APP_DIR, "ocoin_wallet_vault.dat")
DEFAULT_NODE = "https://o-coin.onrender.com"
ADDRESS_LENGTH = 40

BG = "#00030a"
PANEL = "#0a1323"
PANEL_2 = "#0e1b31"
FIELD = "#050b16"
TEXT = "#edf5ff"
MUTED = "#8da1bc"
CYAN = "#45e6d6"
PURPLE = "#a78bfa"
RED = "#fb7185"
GREEN = "#69e6a0"


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _rounded(canvas, x1, y1, x2, y2, radius, **kwargs):
    """A native-canvas rounded rectangle for the app's custom controls."""
    points = [x1 + radius, y1, x2 - radius, y1, x2, y1, x2, y1 + radius,
              x2, y2 - radius, x2, y2, x2 - radius, y2, x1 + radius, y2,
              x1, y2, x1, y2 - radius, x1, y1 + radius, x1, y1]
    return canvas.create_polygon(points, smooth=True, splinesteps=16, **kwargs)


class GlowButton(tk.Canvas):
    """Compact canvas button with a restrained, soft neon hover bloom."""
    def __init__(self, parent, text, command, accent=CYAN, **kwargs):
        self.text = text
        self.command = command
        self.accent = accent
        self.enabled = kwargs.pop("state", "normal") != "disabled"
        width = max(122, len(text) * 9 + 34)
        super().__init__(parent, width=width, height=44, bg=PANEL, highlightthickness=0, bd=0, cursor="hand2")
        self.hover = False
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<Button-1>", self._click)
        self._render()

    def configure(self, cnf=None, **kwargs):
        if "state" in kwargs:
            self.enabled = kwargs.pop("state") != "disabled"
            self.configure(cursor="hand2" if self.enabled else "arrow")
            self._render()
        return super().configure(cnf, **kwargs)

    config = configure

    def _enter(self, _event):
        if self.enabled:
            self.hover = True
            self._render()

    def _leave(self, _event):
        self.hover = False
        self._render()

    def _click(self, _event):
        if self.enabled:
            self.command()

    def _render(self):
        self.delete("all")
        width, height = int(self["width"]), int(self["height"])
        if self.hover and self.enabled:
            # Concentric outlines make the glow look soft rather than like a
            # dated hard border, while remaining fast in standard Tk.
            for pad, color in ((1, "#203b59"), (3, "#1f3552"), (5, "#172945")):
                _rounded(self, pad, pad, width-pad, height-pad, 12, fill=color, outline="")
        fill = "#172b43" if self.enabled else "#101827"
        if self.hover and self.enabled:
            fill = "#1b3651"
        _rounded(self, 5, 5, width-5, height-5, 10, fill=fill, outline=self.accent if self.hover and self.enabled else "#28405d")
        self.create_rectangle(12, 12, 15, height-12, fill=self.accent if self.enabled else "#40516a", outline="")
        self.create_text(width/2 + 3, height/2, text=self.text, fill=TEXT if self.enabled else "#64758c",
                         font=("Segoe UI Semibold", 9), anchor="center")


class GlassCard(tk.Frame):
    """Dark, low-contrast panel with an illuminated edge and hover lift."""
    def __init__(self, parent):
        super().__init__(parent, bg=PANEL, highlightthickness=1, highlightbackground="#203754", highlightcolor="#2f5880", padx=24, pady=22)
        self.bind("<Enter>", self._lift)
        self.bind("<Leave>", self._rest)

    def _lift(self, _event=None):
        self.configure(highlightbackground="#355b81")

    def _rest(self, _event=None):
        self.configure(highlightbackground="#203754")


def _blob(data):
    buffer = ctypes.create_string_buffer(data)
    return DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def dpapi_protect(data):
    """Encrypt bytes for this Windows account without showing an OS prompt."""
    source, source_buffer = _blob(data)
    encrypted = DataBlob()
    crypt32 = ctypes.windll.crypt32
    if not crypt32.CryptProtectData(ctypes.byref(source), "O-Coin Wallet Vault", None, None, None, 0x1, ctypes.byref(encrypted)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(encrypted.pbData, encrypted.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(encrypted.pbData)


def dpapi_unprotect(data):
    source, source_buffer = _blob(data)
    decrypted = DataBlob()
    crypt32 = ctypes.windll.crypt32
    if not crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(decrypted)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(decrypted.pbData, decrypted.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(decrypted.pbData)


class ControlCenter(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NEXUS // O-COIN")
        self.geometry("920x690")
        self.minsize(780, 590)
        self.configure(bg=BG)
        self.option_add("*Font", ("Segoe UI Variable", 10))
        self.miner_process = None
        self.output_queue = queue.Queue()
        self.current_page = None
        self.backdrop_started = time.monotonic()
        # Fixed positions let the field drift gently without distracting from
        # wallet numbers or miner output.
        self.stars = [(random.random(), random.random(), random.choice((1, 1, 1, 2)), random.random() * math.tau)
                      for _ in range(105)]
        self.hero_stars = [(random.random(), random.random(), random.choice((1, 1, 2)), random.random() * math.tau)
                           for _ in range(68)]

        self.node = tk.StringVar(value=DEFAULT_NODE)
        self.node_secret = tk.StringVar()
        self.wallet_address = tk.StringVar(value="No wallet unlocked")
        self.wallet_key = None
        self.reward_address = tk.StringVar()
        self.send_recipient = tk.StringVar()
        self.send_amount = tk.StringVar()
        self.send_key = tk.StringVar()
        self.status = tk.StringVar(value="Vault locked — create or unlock a wallet to begin.")

        self._build_shell()
        self.show_page("wallet")
        self.after(100, self._drain_output)
        self.after(100, self._animate_backgrounds)

    # ----- visual components -----
    def _label(self, parent, text, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", PANEL), fg=kwargs.pop("fg", TEXT), **kwargs)

    def _button(self, parent, text, command, accent=CYAN, **kwargs):
        return GlowButton(parent, text, command, accent=accent, **kwargs)

    def _entry(self, parent, variable, secret=False, readonly=False):
        entry = tk.Entry(parent, textvariable=variable, bg=FIELD, fg=TEXT, insertbackground=TEXT,
                         relief="flat", bd=0, highlightthickness=1, highlightbackground="#263b59",
                         highlightcolor="#57f0e1", show="•" if secret else "", font=("Cascadia Mono", 10))
        if readonly:
            entry.configure(state="readonly", readonlybackground=FIELD)
        return entry

    def _field(self, parent, row, label, variable, secret=False, readonly=False, hint=None):
        # Pages use pack-based cards; a small nested frame keeps field layout
        # self-contained and avoids mixing Tk geometry managers in one parent.
        field = tk.Frame(parent, bg=PANEL)
        field.pack(fill="x", pady=(12 if row else 0, 0))
        self._label(field, label, fg=MUTED, font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(0, 5))
        entry = self._entry(field, variable, secret, readonly)
        entry.pack(fill="x", ipady=9)
        if hint:
            self._label(field, hint, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(4, 0))
        return entry

    def _card(self, parent):
        return GlassCard(parent)

    def _build_shell(self):
        # This is deliberately a real, visible hero—not a hidden decoration
        # underneath opaque Tk panels. It carries the landing-page look from
        # the first frame the control deck opens.
        self.hero = tk.Canvas(self, height=142, bg=BG, highlightthickness=0)
        self.hero.pack(fill="x")
        self.hero.bind("<Configure>", self._draw_hero)

        nav = tk.Frame(self, bg=PANEL_2, padx=20, pady=10)
        nav.pack(fill="x")
        self.nav_buttons = {}
        for key, label in (("wallet", "WALLET"), ("mine", "MINE"), ("send", "SEND"), ("settings", "NODE")):
            button = tk.Button(nav, text=label, command=lambda page=key: self.show_page(page), bg=PANEL_2, fg=MUTED,
                               activebackground="#192d49", activeforeground=CYAN, relief="flat", bd=0, padx=18,
                               font=("Segoe UI Semibold", 10), cursor="hand2", highlightthickness=0)
            button.bind("<Enter>", lambda _event, item=button: item.configure(bg="#192d49"))
            button.bind("<Leave>", lambda _event, item=button, name=key: item.configure(bg=PANEL_2 if self.current_page != name else "#192d49"))
            button.pack(side="left")
            self.nav_buttons[key] = button

        # Canvas sits behind the page cards. Tk widgets are opaque, so the
        # celestial treatment reads through the intentional breathing room
        # around panels rather than competing with controls.
        self.content = tk.Canvas(self, bg=BG, highlightthickness=0)
        self.content.pack(fill="both", expand=True)
        self.content.bind("<Configure>", self._draw_black_hole)
        footer = tk.Frame(self, bg="#0c1320", padx=25, pady=10)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer, textvariable=self.status, bg="#0c1320", fg=MUTED, anchor="w", font=("Segoe UI", 9)).pack(fill="x")

    def _draw_hero(self, _event=None):
        """Prominent, animated NEXUS landing-page banner."""
        canvas = self.hero
        width, height = canvas.winfo_width(), canvas.winfo_height()
        if width < 2 or height < 2:
            return
        canvas.delete("nexus_hero")
        now = time.monotonic() - self.backdrop_started
        for x, y, size, phase in self.hero_stars:
            glow = int(125 + 110 * (0.5 + 0.5 * math.sin(now * .8 + phase)))
            canvas.create_oval(x*width-size, y*height-size, x*width+size, y*height+size,
                               fill=f"#{glow:02x}{min(255, glow+12):02x}ff", outline="", tags="nexus_hero")
        cx, cy = width * .80, height * .54
        for radius, color, arc_width, start, extent in ((105, "#16375a", 7, 18, 76), (82, "#2ce5dc", 8, 90, 92),
                                                         (64, "#a778ee", 9, 205, 84), (48, "#f05d9e", 5, 306, 55)):
            canvas.create_arc(cx-radius*1.35, cy-radius*.46, cx+radius*1.35, cy+radius*.46,
                              start=start + now*7, extent=extent, style="arc", outline=color, width=arc_width, tags="nexus_hero")
        canvas.create_oval(cx-37, cy-37, cx+37, cy+37, fill="#000000", outline="#172136", width=2, tags="nexus_hero")
        canvas.create_text(27, 48, text="NEXUS", anchor="w", fill=CYAN, font=("Segoe UI Black", 25), tags="nexus_hero")
        canvas.create_text(29, 78, text="//  O-COIN CONTROL DECK", anchor="w", fill="#a9bbd2", font=("Cascadia Mono", 10), tags="nexus_hero")
        canvas.create_text(29, 104, text="LOCAL-FIRST   •   ENCRYPTED VAULT   •   ON-CHAIN", anchor="w", fill=PURPLE, font=("Segoe UI Semibold", 9), tags="nexus_hero")

    def _draw_black_hole(self, _event=None):
        """Landing-page-inspired black hole: stars, horizon and accretion arcs."""
        canvas = self.content
        width, height = canvas.winfo_width(), canvas.winfo_height()
        if width < 2 or height < 2:
            return
        canvas.delete("nexus_space")
        now = time.monotonic() - self.backdrop_started
        cx, cy = width * 0.69, height * 0.48
        scale = max(0.55, min(width, height) / 620)

        # Sparse, independently twinkling star field.
        for x, y, size, phase in self.stars:
            pulse = 0.32 + 0.55 * (0.5 + 0.5 * math.sin(now * 0.75 + phase))
            shade = int(110 + 120 * pulse)
            color = f"#{shade:02x}{min(245, shade + 12):02x}ff"
            px, py = x * width, y * height
            canvas.create_oval(px - size, py - size, px + size, py + size, fill=color, outline="", tags="nexus_space")

        # Broad, diffuse accretion glow: native Tk has no alpha, so layered
        # outlines provide the same cyan/purple/pink landing-page atmosphere.
        for radius, color, line_width in ((300, "#061b35", 3), (265, "#102443", 3), (230, "#132244", 2)):
            r = radius * scale
            canvas.create_oval(cx-r, cy-r*.46, cx+r, cy+r*.46, outline=color, width=line_width, tags="nexus_space")
        rotation = now * 4.0
        for start, extent, color, width_arc in ((8, 70, "#29d9df", 8), (122, 92, "#9e6cf2", 10), (247, 62, "#f05093", 7), (321, 35, "#36b9e7", 5)):
            r = 215 * scale
            canvas.create_arc(cx-r, cy-r*.42, cx+r, cy+r*.42, start=start + rotation, extent=extent,
                              style="arc", outline=color, width=width_arc, tags="nexus_space")
        # Tilted inner disk and the completely black event horizon.
        for radius, color, width_arc in ((160, "#5e3c9b", 5), (142, "#19bfc9", 4), (125, "#e14d8a", 3)):
            r = radius * scale
            canvas.create_arc(cx-r, cy-r*.35, cx+r, cy+r*.35, start=rotation * 1.65, extent=142,
                              style="arc", outline=color, width=width_arc, tags="nexus_space")
        core = 78 * scale * (1 + 0.035 * math.sin(now * 0.42))
        canvas.create_oval(cx-core*1.12, cy-core, cx+core*1.12, cy+core, fill="#000000", outline="#10101b", width=2, tags="nexus_space")
        canvas.create_oval(cx-core*.64, cy-core*.64, cx+core*.64, cy+core*.64, fill="#000000", outline="", tags="nexus_space")
        canvas.tag_lower("nexus_space")
    def _animate_backgrounds(self):
        self._draw_hero()
        self._draw_black_hole()
        self.after(85, self._animate_backgrounds)

    def show_page(self, page):
        for widget in self.content.winfo_children():
            widget.destroy()
        self.current_page = page
        for key, button in self.nav_buttons.items():
            button.configure(fg=CYAN if key == page else MUTED, bg="#192d49" if key == page else PANEL_2)
        getattr(self, f"_page_{page}")()

    # ----- wallet -----
    def _page_wallet(self):
        left = self._card(self.content)
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        right = self._card(self.content)
        right.pack(side="left", fill="both", expand=True)
        self._label(left, "YOUR O-COIN WALLET", fg=CYAN, font=("Segoe UI Semibold", 15)).pack(anchor="w")
        self._label(left, "One local identity for mining and sending.", fg=MUTED).pack(anchor="w", pady=(4, 16))
        self._label(left, "ADDRESS", fg=MUTED, font=("Segoe UI Semibold", 9)).pack(anchor="w")
        address = self._entry(left, self.wallet_address, readonly=True)
        address.pack(fill="x", pady=(5, 15), ipady=10)
        row = tk.Frame(left, bg=PANEL)
        row.pack(fill="x")
        self._button(row, "Create new wallet", self.create_wallet).pack(side="left")
        self._button(row, "Unlock saved wallet", self.unlock_wallet, accent=PURPLE).pack(side="left", padx=(8, 0))
        self._button(left, "Lock wallet", self.lock_wallet, accent="#33445f").pack(anchor="w", pady=(10, 0))

        self._label(right, "VAULT SECURITY", fg=PURPLE, font=("Segoe UI Semibold", 15)).pack(anchor="w")
        self._label(right, "Your private key is encrypted with Windows DPAPI.", fg=MUTED, wraplength=320, justify="left").pack(anchor="w", pady=(5, 16))
        for title, copy in (
            ("ENCRYPTED AT REST", "The saved vault can only be decrypted by this Windows account."),
            ("NOT SENT TO THE NODE", "Transactions are signed locally; the network receives only a signed transaction."),
            ("BACK UP OFFLINE", "A Windows-account vault is convenient, not a replacement for an offline recovery backup."),
        ):
            self._label(right, title, fg=CYAN, font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(8, 0))
            self._label(right, copy, fg=MUTED, wraplength=320, justify="left").pack(anchor="w", pady=(2, 4))

    def create_wallet(self):
        if os.path.exists(VAULT_PATH) and not messagebox.askyesno("Replace saved wallet?", "This will replace the encrypted wallet currently saved on this computer. Continue?"):
            return
        wallet = Wallet()
        key = wallet.private_key_hex()
        self._save_vault(wallet.address, key)
        self.wallet_key = key
        self.wallet_address.set(wallet.address)
        self.reward_address.set(wallet.address)
        self.status.set("New wallet created and encrypted in the local vault. Back up its private key now.")
        self._show_backup(wallet.address, key)

    def _show_backup(self, address, key):
        window = tk.Toplevel(self)
        window.title("Back up your O-Coin private key")
        window.configure(bg=BG)
        window.geometry("680x290")
        window.transient(self)
        frame = tk.Frame(window, bg=PANEL, padx=24, pady=22)
        frame.pack(fill="both", expand=True, padx=14, pady=14)
        self._label(frame, "SAVE THIS PRIVATE KEY OFFLINE", fg=RED, font=("Segoe UI Semibold", 15)).pack(anchor="w")
        self._label(frame, "It is shown only now. Anyone with it can spend your O-Coin.", fg=MUTED).pack(anchor="w", pady=(4, 14))
        value = tk.StringVar(value=key)
        key_entry = self._entry(frame, value, readonly=True)
        key_entry.pack(fill="x", ipady=9)
        self._label(frame, f"Wallet address: {address}", fg=CYAN, font=("Cascadia Mono", 9)).pack(anchor="w", pady=(12, 0))
        self._button(frame, "I saved it safely", window.destroy).pack(anchor="e", pady=(15, 0))

    def _save_vault(self, address, key):
        payload = json.dumps({"address": address, "private_key": key}).encode("utf-8")
        encrypted = dpapi_protect(payload)
        with open(VAULT_PATH, "wb") as file:
            file.write(base64.b64encode(encrypted))

    def unlock_wallet(self):
        if not os.path.exists(VAULT_PATH):
            messagebox.showinfo("No saved wallet", "Create a wallet first. The encrypted vault will be created beside this app.")
            return
        try:
            with open(VAULT_PATH, "rb") as file:
                encrypted = base64.b64decode(file.read())
            vault = json.loads(dpapi_unprotect(encrypted).decode("utf-8"))
            wallet = Wallet(private_key_hex=vault["private_key"])
            if wallet.address != vault["address"]:
                raise ValueError("Vault address does not match its key")
        except Exception:
            messagebox.showerror("Could not unlock wallet", "This vault cannot be opened by this Windows account or is damaged. Restore from your offline private-key backup.")
            return
        self.wallet_key = vault["private_key"]
        self.wallet_address.set(wallet.address)
        self.reward_address.set(wallet.address)
        self.status.set("Saved wallet unlocked. It is ready for mining and sending.")

    def lock_wallet(self):
        self.wallet_key = None
        self.wallet_address.set("No wallet unlocked")
        self.send_key.set("")
        self.status.set("Wallet locked. The encrypted vault remains saved locally.")

    # ----- mining -----
    def _page_mine(self):
        card = self._card(self.content)
        card.pack(fill="both", expand=True)
        self._label(card, "MINING CONSOLE", fg=CYAN, font=("Segoe UI Semibold", 15)).pack(anchor="w")
        self._label(card, "Mine O-Coin from this computer. Rewards go to your unlocked wallet by default.", fg=MUTED).pack(anchor="w", pady=(4, 12))
        self._field(card, 0, "REWARD ADDRESS", self.reward_address, hint="Use a 40-character O-Coin address. Mining stays active until you press Stop.")
        button_row = tk.Frame(card, bg=PANEL)
        button_row.pack(anchor="w", pady=(16, 14))
        self.start_button = self._button(button_row, "START MINING", self.start_mining)
        self.start_button.pack(side="left")
        self.stop_button = self._button(button_row, "STOP", self.stop_mining, accent=RED, state="disabled")
        self.stop_button.pack(side="left", padx=(9, 0))
        self._button(button_row, "CHECK BALANCE", self.check_balance, accent=PURPLE).pack(side="left", padx=(9, 0))
        self.output = tk.Text(card, bg="#060a11", fg="#b9d8f3", insertbackground=TEXT, relief="flat", bd=0,
                              height=17, wrap="word", font=("Cascadia Mono", 9), state="disabled", padx=13, pady=12)
        self.output.pack(fill="both", expand=True)

    def start_mining(self):
        address = self.reward_address.get().strip()
        node = self.node.get().strip().rstrip("/")
        if not self._valid_node(node) or not self._valid_address(address):
            messagebox.showerror("Mining needs a node and address", "Set a valid node URL and a valid 40-character O-Coin reward address.")
            return
        environment = os.environ.copy()
        if self.node_secret.get().strip():
            environment["OCOIN_NODE_SHARED_SECRET"] = self.node_secret.get().strip()
        command = [sys.executable, "-u", os.path.join(APP_DIR, "miner.py"), "--node", node, "--address", address]
        try:
            self.miner_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=environment)
        except OSError as error:
            messagebox.showerror("Could not start miner", str(error))
            return
        threading.Thread(target=self._read_miner, daemon=True).start()
        if hasattr(self, "start_button"):
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
        self.status.set("Mining active — your computer is searching for the next block.")
        self._append("[ NEXUS ] miner process started\n")

    def stop_mining(self):
        if self.miner_process and self.miner_process.poll() is None:
            self.miner_process.terminate()
            self.status.set("Stopping miner…")

    def _read_miner(self):
        for line in iter(self.miner_process.stdout.readline, ""):
            self.output_queue.put(line)
        self.output_queue.put("__MINER_FINISHED__")

    def _drain_output(self):
        try:
            while True:
                line = self.output_queue.get_nowait()
                if line == "__MINER_FINISHED__":
                    if hasattr(self, "start_button"):
                        self.start_button.configure(state="normal")
                        self.stop_button.configure(state="disabled")
                    self.status.set("Miner stopped.")
                else:
                    self._append(line)
        except queue.Empty:
            pass
        self.after(100, self._drain_output)

    def _append(self, text):
        if not hasattr(self, "output"):
            return
        self.output.configure(state="normal")
        self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    # ----- sending -----
    def _page_send(self):
        card = self._card(self.content)
        card.pack(fill="both", expand=True)
        self._label(card, "SEND O-COIN", fg=RED, font=("Segoe UI Semibold", 15)).pack(anchor="w")
        self._label(card, "Transactions are irreversible. Your wallet signs locally; no private key is sent to the node.", fg=MUTED).pack(anchor="w", pady=(4, 12))
        if self.wallet_key:
            self._label(card, f"Sending from unlocked wallet: {self.wallet_address.get()}", fg=GREEN, font=("Cascadia Mono", 9)).pack(anchor="w")
        else:
            self._label(card, "Wallet locked: enter a private key below or unlock your saved wallet.", fg=PURPLE, font=("Segoe UI", 9)).pack(anchor="w")
        self._field(card, 0, "PRIVATE KEY (only needed if wallet is locked)", self.send_key, secret=True)
        self._field(card, 3, "RECIPIENT ADDRESS", self.send_recipient)
        self._field(card, 5, "AMOUNT", self.send_amount, hint="You will see one final confirmation before the transaction is submitted.")
        self._button(card, "REVIEW & SEND", self.review_and_send, accent=RED).pack(anchor="w", pady=(18, 0))

    def review_and_send(self):
        key = self.wallet_key or self.send_key.get().strip()
        recipient = self.send_recipient.get().strip()
        try:
            wallet = Wallet(private_key_hex=key)
            amount = float(self.send_amount.get().replace(",", "").replace("_", "").replace(" ", ""))
        except Exception:
            messagebox.showerror("Invalid send details", "Provide a valid private key and positive numeric amount.")
            return
        if not self._valid_address(recipient) or amount <= 0:
            messagebox.showerror("Invalid send details", "Provide a valid recipient address and positive amount.")
            return
        if not messagebox.askyesno("Final confirmation", f"SEND {amount:,} O-COIN\n\nFrom: {wallet.address}\nTo: {recipient}\n\nThis cannot be reversed.", icon="warning"):
            return
        self.status.set("Signing locally and submitting transaction…")
        threading.Thread(target=self._send, args=(wallet, recipient, amount), daemon=True).start()

    def _send(self, wallet, recipient, amount):
        try:
            transaction = Transaction(wallet.address, recipient, amount)
            transaction.sign(wallet)
            response = requests.post(f"{self.node.get().strip().rstrip('/')}/transactions/new", json=transaction.to_dict(), headers=self._headers(), timeout=75)
            data = response.json()
            if not response.ok or data.get("status") != "ok":
                raise RuntimeError(data.get("reason", f"Node returned HTTP {response.status_code}"))
            self.after(0, lambda: messagebox.showinfo("Transaction submitted", "The transaction is in the mempool and will appear after a block confirms it."))
            self.after(0, lambda: self.status.set("Transaction submitted for confirmation."))
            self.after(0, self.send_key.set, "")
        except Exception as error:
            self.after(0, lambda: messagebox.showerror("Send failed", str(error)))
            self.after(0, lambda: self.status.set("Transaction was not submitted."))

    # ----- node -----
    def _page_settings(self):
        card = self._card(self.content)
        card.pack(fill="both", expand=True)
        self._label(card, "NODE CONNECTION", fg=PURPLE, font=("Segoe UI Semibold", 15)).pack(anchor="w")
        self._label(card, "Configure the O-Coin node used for balance checks, sending, and mining.", fg=MUTED).pack(anchor="w", pady=(4, 12))
        self._field(card, 0, "NODE URL", self.node)
        self._field(card, 3, "NODE SHARED SECRET", self.node_secret, secret=True, hint="Used in memory only. It is never saved in the vault or project files.")
        self._button(card, "TEST CONNECTION", self.test_connection, accent=PURPLE).pack(anchor="w", pady=(18, 0))

    def test_connection(self):
        if not self._valid_node(self.node.get().strip()):
            messagebox.showerror("Invalid node URL", "Use a full URL beginning with http:// or https://.")
            return
        self.status.set("Checking node status…")
        threading.Thread(target=self._test_connection_request, daemon=True).start()

    def _test_connection_request(self):
        try:
            response = requests.get(f"{self.node.get().strip().rstrip('/')}/status", headers=self._headers(), timeout=75)
            response.raise_for_status()
            data = response.json()
            height = data.get("length", data.get("chain_length", "?"))
            self.after(0, lambda: messagebox.showinfo("Node online", f"Connected to O-Coin node.\nReported chain height: {height}"))
            self.after(0, lambda: self.status.set("Node connection confirmed."))
        except Exception as error:
            self.after(0, lambda: messagebox.showerror("Node unavailable", str(error)))
            self.after(0, lambda: self.status.set("Could not reach node."))

    def check_balance(self):
        address = self.reward_address.get().strip()
        if not self._valid_address(address):
            messagebox.showerror("Invalid address", "Enter a valid 40-character O-Coin address first.")
            return
        self.status.set("Checking balance…")
        threading.Thread(target=self._balance_request, args=(address,), daemon=True).start()

    def _balance_request(self, address):
        try:
            response = requests.get(f"{self.node.get().strip().rstrip('/')}/balance/{address}", headers=self._headers(), timeout=75)
            response.raise_for_status()
            data = response.json()
            confirmed = data["balance"]
            pending = data.get("balance_with_pending", confirmed)
            copy = f"Address:\n{address}\n\nConfirmed: {confirmed:,} O-Coin"
            if pending != confirmed:
                copy += f"\nIncluding pending: {pending:,} O-Coin"
            self.after(0, lambda: messagebox.showinfo("O-Coin balance", copy))
            self.after(0, lambda: self.status.set("Balance checked."))
        except Exception as error:
            self.after(0, lambda: messagebox.showerror("Balance check failed", str(error)))
            self.after(0, lambda: self.status.set("Could not check balance."))

    def _headers(self):
        secret = self.node_secret.get().strip()
        return {"X-Node-Auth": secret} if secret else {}

    @staticmethod
    def _valid_address(address):
        return len(address) == ADDRESS_LENGTH and all(character in "0123456789abcdef" for character in address.lower())

    @staticmethod
    def _valid_node(node):
        return node.startswith(("https://", "http://"))


if __name__ == "__main__":
    ControlCenter().mainloop()
