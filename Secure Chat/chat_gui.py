"""
chat_gui.py — Shared Chat GUI Module
=====================================
ECE 4304 Data Security Project

Provides the ChatWindow class used by both server.py and client.py.

Features:
  - Dark-mode Tkinter UI
  - Own messages: right-aligned (cyan bubble)
  - Received messages: left-aligned (dark bubble)
  - Live "Encrypted View" panel — shows the raw hex ciphertext of each message
  - Key fingerprint display for visual verification
  - MitM tamper alert dialog when HMAC fails
  - Connection status indicator
"""

import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, font
import time
import crypto


# ──────────────────────────────────────────────────────────────────────────────
#  Colour Palette  (cyberpunk dark theme)
# ──────────────────────────────────────────────────────────────────────────────

COLORS = {
    "bg":           "#0d0d1a",   # near-black background
    "sidebar":      "#111128",   # slightly lighter sidebar
    "bubble_self":  "#0a2e4a",   # dark blue — own messages
    "bubble_other": "#1a1a2e",   # dark purple — received messages
    "accent":       "#00e5ff",   # cyan accent
    "accent2":      "#7c3aed",   # purple accent
    "text":         "#e0e0e0",   # main text
    "text_dim":     "#6c7a8a",   # dimmed / secondary text
    "border":       "#1e2a3a",   # subtle borders
    "success":      "#00c896",   # green — connected
    "warning":      "#ffb347",   # orange — warning
    "danger":       "#ff4757",   # red — error / tamper
    "input_bg":     "#141428",   # message input background
    "hex_bg":       "#0a0a18",   # encrypted pane background
    "hex_text":     "#00c896",   # hex dump colour
    "status_bar":   "#080815",   # bottom status bar
}

FONT_FAMILY = "Consolas"


class ChatWindow:
    """
    Main chat window widget.

    Parameters
    ----------
    root        : tk.Tk root window
    role        : "Host" or "Guest" — displayed in title
    secret_key  : shared encryption key
    send_fn     : callable(ciphertext: bytes) — called to transmit encrypted bytes
    """

    def __init__(self, root: tk.Tk, role: str, secret_key: str, send_fn):
        self.root       = root
        self.role       = role
        self.secret_key = secret_key
        self.send_fn    = send_fn
        self._show_hex  = tk.BooleanVar(value=False)
        self._connected = False

        self._build_ui()
        self._update_status("Waiting for connection…", "warning")

    # ──────────────────────────────────────────────────────────────────────────
    #  UI Construction
    # ──────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.root.title(f"🔒 SecureChat — {self.role}")
        self.root.configure(bg=COLORS["bg"])
        self.root.geometry("960x680")
        self.root.minsize(700, 500)

        # ── Top header bar ──
        header = tk.Frame(self.root, bg=COLORS["sidebar"], pady=10)
        header.pack(fill="x")

        tk.Label(
            header,
            text="🔒 SecureChat",
            font=(FONT_FAMILY, 18, "bold"),
            bg=COLORS["sidebar"],
            fg=COLORS["accent"],
        ).pack(side="left", padx=18)

        role_badge = tk.Label(
            header,
            text=f"  {self.role}  ",
            font=(FONT_FAMILY, 10, "bold"),
            bg=COLORS["accent2"],
            fg="white",
            padx=6, pady=2,
        )
        role_badge.pack(side="left", padx=6)

        fp = crypto.key_fingerprint(self.secret_key)
        tk.Label(
            header,
            text=f"Key Fingerprint:  {fp}",
            font=(FONT_FAMILY, 9),
            bg=COLORS["sidebar"],
            fg=COLORS["text_dim"],
        ).pack(side="left", padx=20)

        tk.Checkbutton(
            header,
            text="Show Encrypted",
            variable=self._show_hex,
            command=self._toggle_hex_pane,
            bg=COLORS["sidebar"],
            fg=COLORS["text_dim"],
            selectcolor=COLORS["bg"],
            activebackground=COLORS["sidebar"],
            font=(FONT_FAMILY, 9),
        ).pack(side="right", padx=18)

        # ── Status indicator ──
        self._status_var = tk.StringVar(value="")
        self._status_dot = tk.Label(
            header,
            text="●",
            font=(FONT_FAMILY, 14),
            bg=COLORS["sidebar"],
            fg=COLORS["warning"],
        )
        self._status_dot.pack(side="right", padx=4)
        self._status_label = tk.Label(
            header,
            textvariable=self._status_var,
            font=(FONT_FAMILY, 9),
            bg=COLORS["sidebar"],
            fg=COLORS["warning"],
        )
        self._status_label.pack(side="right")

        # ── Main body (chat + optional hex pane) ──
        self._body = tk.PanedWindow(
            self.root,
            orient="horizontal",
            bg=COLORS["border"],
            sashwidth=4,
        )
        self._body.pack(fill="both", expand=True, padx=0, pady=0)

        # Chat frame
        chat_frame = tk.Frame(self._body, bg=COLORS["bg"])
        self._body.add(chat_frame, stretch="always")

        self._chat_canvas = tk.Canvas(
            chat_frame, bg=COLORS["bg"], bd=0, highlightthickness=0
        )
        scrollbar = tk.Scrollbar(chat_frame, command=self._chat_canvas.yview)
        self._chat_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._chat_canvas.pack(side="left", fill="both", expand=True)

        self._msg_frame = tk.Frame(self._chat_canvas, bg=COLORS["bg"])
        self._canvas_window = self._chat_canvas.create_window(
            (0, 0), window=self._msg_frame, anchor="nw"
        )
        self._msg_frame.bind("<Configure>", self._on_frame_configure)
        self._chat_canvas.bind("<Configure>", self._on_canvas_configure)

        # Encrypted hex pane (hidden by default)
        self._hex_frame = tk.Frame(self._body, bg=COLORS["hex_bg"], width=320)
        self._hex_title = tk.Label(
            self._hex_frame,
            text="[ Raw Encrypted Bytes ]",
            font=(FONT_FAMILY, 9, "bold"),
            bg=COLORS["hex_bg"],
            fg=COLORS["accent"],
            pady=6,
        )
        self._hex_title.pack(fill="x")
        self._hex_area = scrolledtext.ScrolledText(
            self._hex_frame,
            bg=COLORS["hex_bg"],
            fg=COLORS["hex_text"],
            font=(FONT_FAMILY, 8),
            state="disabled",
            wrap="char",
            bd=0,
            highlightthickness=0,
        )
        self._hex_area.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Input bar ──
        input_bar = tk.Frame(self.root, bg=COLORS["input_bg"], pady=10)
        input_bar.pack(fill="x", side="bottom")

        self._msg_entry = tk.Entry(
            input_bar,
            font=(FONT_FAMILY, 12),
            bg=COLORS["input_bg"],
            fg=COLORS["text"],
            insertbackground=COLORS["accent"],
            relief="flat",
            bd=0,
        )
        self._msg_entry.pack(side="left", fill="x", expand=True, padx=16, ipady=8)
        self._msg_entry.bind("<Return>", self._on_send)

        send_btn = tk.Button(
            input_bar,
            text="Send  ⟶",
            font=(FONT_FAMILY, 11, "bold"),
            bg=COLORS["accent"],
            fg=COLORS["bg"],
            activebackground="#00b8d9",
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2",
            command=self._on_send,
        )
        send_btn.pack(side="right", padx=16)

        # ── Bottom status bar ──
        status_bar = tk.Frame(self.root, bg=COLORS["status_bar"], pady=4)
        status_bar.pack(fill="x", side="bottom")

        self._bottom_status = tk.Label(
            status_bar,
            text="End-to-end encrypted with SHA-256 Stream Cipher + HMAC-SHA256",
            font=(FONT_FAMILY, 8),
            bg=COLORS["status_bar"],
            fg=COLORS["text_dim"],
        )
        self._bottom_status.pack()

    # ──────────────────────────────────────────────────────────────────────────
    #  Layout helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _on_frame_configure(self, event):
        self._chat_canvas.configure(scrollregion=self._chat_canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self._chat_canvas.itemconfig(self._canvas_window, width=event.width)

    def _toggle_hex_pane(self):
        if self._show_hex.get():
            self._body.add(self._hex_frame, width=320, stretch="never")
        else:
            self._body.remove(self._hex_frame)

    def _scroll_to_bottom(self):
        self._chat_canvas.after(50, lambda: self._chat_canvas.yview_moveto(1.0))

    # ──────────────────────────────────────────────────────────────────────────
    #  Status Updates
    # ──────────────────────────────────────────────────────────────────────────

    def _update_status(self, msg: str, level: str = "success"):
        color_map = {
            "success": COLORS["success"],
            "warning": COLORS["warning"],
            "danger":  COLORS["danger"],
        }
        color = color_map.get(level, COLORS["text"])
        self._status_var.set(msg)
        self._status_label.config(fg=color)
        self._status_dot.config(fg=color)

    def set_connected(self, peer_addr: str):
        self._connected = True
        self._update_status(f"Connected  {peer_addr}", "success")
        self._add_system_message(f"🔗 Secure connection established with {peer_addr}")

    def set_disconnected(self):
        self._connected = False
        self._update_status("Disconnected", "danger")
        self._add_system_message("⚠  Connection lost.")

    # ──────────────────────────────────────────────────────────────────────────
    #  Message Bubbles
    # ──────────────────────────────────────────────────────────────────────────

    def _add_system_message(self, text: str):
        """Centred grey system notification."""
        self.root.after(0, self._render_system, text)

    def _render_system(self, text: str):
        row = tk.Frame(self._msg_frame, bg=COLORS["bg"], pady=4)
        row.pack(fill="x")
        tk.Label(
            row,
            text=text,
            font=(FONT_FAMILY, 9, "italic"),
            bg=COLORS["bg"],
            fg=COLORS["text_dim"],
            wraplength=600,
        ).pack()

    def _render_bubble(self, text: str, timestamp: str, side: str, ciphertext_hex: str = ""):
        """
        side = "right" for own messages, "left" for received.
        """
        is_self = side == "right"
        bubble_bg   = COLORS["bubble_self"] if is_self else COLORS["bubble_other"]
        anchor_side = "e" if is_self else "w"
        label_anchor = "right" if is_self else "left"

        row = tk.Frame(self._msg_frame, bg=COLORS["bg"], pady=3)
        row.pack(fill="x")

        outer = tk.Frame(row, bg=COLORS["bg"])
        if is_self:
            outer.pack(side="right", padx=(60, 12))
        else:
            outer.pack(side="left", padx=(12, 60))

        bubble = tk.Frame(outer, bg=bubble_bg, padx=14, pady=8)
        bubble.pack()

        # Sender label
        sender = "You" if is_self else "Peer"
        tk.Label(
            bubble,
            text=sender,
            font=(FONT_FAMILY, 8, "bold"),
            bg=bubble_bg,
            fg=COLORS["accent"] if is_self else COLORS["accent2"],
            anchor=label_anchor,
        ).pack(fill="x")

        # Message text
        tk.Label(
            bubble,
            text=text,
            font=(FONT_FAMILY, 11),
            bg=bubble_bg,
            fg=COLORS["text"],
            wraplength=380,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(2, 4))

        # Timestamp
        tk.Label(
            bubble,
            text=timestamp,
            font=(FONT_FAMILY, 7),
            bg=bubble_bg,
            fg=COLORS["text_dim"],
            anchor="e",
        ).pack(fill="x")

        # Tiny padlock icon to show encryption
        lock_row = tk.Frame(outer, bg=COLORS["bg"])
        lock_row.pack(fill="x")
        tk.Label(
            lock_row,
            text="🔒 encrypted",
            font=(FONT_FAMILY, 7),
            bg=COLORS["bg"],
            fg=COLORS["text_dim"],
        ).pack(side="right" if is_self else "left")

        self._scroll_to_bottom()

        # Log to encrypted pane
        if ciphertext_hex:
            self._log_hex(sender, ciphertext_hex)

    # ──────────────────────────────────────────────────────────────────────────
    #  Encrypted Hex Pane
    # ──────────────────────────────────────────────────────────────────────────

    def _log_hex(self, sender: str, hex_str: str):
        self._hex_area.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self._hex_area.insert("end", f"\n[{ts}] {sender}:\n")
        # Split into groups of 2 chars (bytes), 16 bytes per line
        chunks = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
        lines  = [" ".join(chunks[i:i+16]) for i in range(0, len(chunks), 16)]
        self._hex_area.insert("end", "\n".join(lines) + "\n")
        self._hex_area.config(state="disabled")
        self._hex_area.see("end")

    # ──────────────────────────────────────────────────────────────────────────
    #  Send / Receive
    # ──────────────────────────────────────────────────────────────────────────

    def _on_send(self, event=None):
        text = self._msg_entry.get().strip()
        if not text or not self._connected:
            if not self._connected:
                self._add_system_message("⚠  Not connected yet. Please wait.")
            return

        try:
            payload    = crypto.encrypt(text, self.secret_key)
            framed     = crypto.framed_packet(payload)
            self.send_fn(framed)

            timestamp     = time.strftime("%H:%M:%S")
            ciphertext_hex = payload.hex()

            self.root.after(0, self._render_bubble,
                            text, timestamp, "right", ciphertext_hex)
            self._msg_entry.delete(0, "end")

        except Exception as e:
            messagebox.showerror("Send Error", str(e), parent=self.root)

    def receive_message(self, payload: bytes):
        """
        Called from the networking thread when an encrypted packet arrives.
        Decrypts and renders in the GUI (thread-safe via root.after).
        """
        try:
            plaintext = crypto.decrypt(payload, self.secret_key)
            
            if plaintext.startswith("[CHK]"):
                parts = plaintext.split("|", 3)
                if len(parts) >= 4:
                    msg_id = parts[0][5:]
                    chunk_idx = int(parts[1])
                    total_chunks = int(parts[2])
                    chunk_data = parts[3]
                    
                    if not hasattr(self, "_chunk_buffers"):
                        self._chunk_buffers = {}
                    if msg_id not in self._chunk_buffers:
                        self._chunk_buffers[msg_id] = [None] * total_chunks
                    self._chunk_buffers[msg_id][chunk_idx] = chunk_data
                    
                    if all(c is not None for c in self._chunk_buffers[msg_id]):
                        full_text = "".join(self._chunk_buffers[msg_id])
                        del self._chunk_buffers[msg_id]
                        timestamp = time.strftime("%H:%M:%S")
                        hex_str = payload.hex()
                        self.root.after(0, self._render_bubble, full_text, timestamp, "left", hex_str)
                return

            timestamp = time.strftime("%H:%M:%S")
            hex_str   = payload.hex()
            self.root.after(0, self._render_bubble,
                            plaintext, timestamp, "left", hex_str)

        except crypto.WrongKeyError as e:
            self.root.after(0, self._show_mitm_alert, str(e))

        except Exception as e:
            self.root.after(0, self._add_system_message,
                            f"⚠  Failed to decode message: {e}")

    def _show_mitm_alert(self, detail: str):
        """Full-screen warning when HMAC fails (MitM or wrong key)."""
        win = tk.Toplevel(self.root)
        win.title("⚠  Security Alert")
        win.configure(bg=COLORS["bg"])
        win.geometry("520x320")
        win.grab_set()

        tk.Label(
            win,
            text="🚨  SECURITY ALERT",
            font=(FONT_FAMILY, 18, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["danger"],
        ).pack(pady=(30, 10))

        tk.Label(
            win,
            text="Message authentication failed!",
            font=(FONT_FAMILY, 12, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["warning"],
        ).pack()

        tk.Label(
            win,
            text=detail,
            font=(FONT_FAMILY, 10),
            bg=COLORS["bg"],
            fg=COLORS["text"],
            wraplength=460,
            justify="left",
        ).pack(padx=30, pady=20)

        tk.Button(
            win,
            text="Dismiss",
            bg=COLORS["danger"],
            fg="white",
            font=(FONT_FAMILY, 10, "bold"),
            relief="flat",
            padx=20, pady=6,
            command=win.destroy,
        ).pack(pady=10)
