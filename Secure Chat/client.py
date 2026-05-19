"""
client.py — SecureChat Guest (Device B)
=========================================
ECE 4304 Data Security Project

Run this on the SECOND device (the guest / client).
It will:
  1. Ask for the Host's IP address
  2. Ask for the shared secret key
  3. Connect to Device A
  4. Open the encrypted chat window

Usage:
    python client.py
"""

import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import sys
import crypto
import chat_gui


PORT = 9999


def start_client():
    # ── 1. Setup dialog ──
    setup_root = tk.Tk()
    setup_root.withdraw()
    setup_root.title("SecureChat Setup")

    host_ip = simpledialog.askstring(
        "SecureChat — Guest Setup",
        "Enter the Host's IP address:\n(shown on Device A when you launched server.py)",
        parent=setup_root,
    )
    if not host_ip:
        messagebox.showinfo("Cancelled", "No IP entered. Exiting.", parent=setup_root)
        setup_root.destroy()
        sys.exit(0)

    host_ip = host_ip.strip()

    key = simpledialog.askstring(
        "SecureChat — Guest Setup",
        "Enter the shared secret key:\n(Must match exactly what Device A entered)",
        show="*",
        parent=setup_root,
    )
    if not key:
        messagebox.showinfo("Cancelled", "No key entered. Exiting.", parent=setup_root)
        setup_root.destroy()
        sys.exit(0)

    setup_root.destroy()

    # ── 2. Connect to server ──
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((host_ip, PORT))
        print(f"[Client] Connected to {host_ip}:{PORT}")
    except Exception as e:
        root_err = tk.Tk()
        root_err.withdraw()
        messagebox.showerror(
            "Connection Failed",
            f"Could not connect to {host_ip}:{PORT}\n\n{e}\n\n"
            "Make sure server.py is running on Device A and the IP is correct.",
            parent=root_err,
        )
        root_err.destroy()
        sys.exit(1)

    # ── 3. Build GUI ──
    root = tk.Tk()

    def send_fn(data: bytes):
        try:
            client_sock.sendall(data)
        except OSError as e:
            window.set_disconnected()
            print(f"[Client] Send error: {e}")

    window = chat_gui.ChatWindow(root, "Guest", key, send_fn)
    window.set_connected(f"{host_ip}:{PORT}")

    # ── 4. Receive loop ──
    def receive_loop():
        try:
            while True:
                payload = crypto.read_packet(client_sock)
                if not payload:
                    break
                window.receive_message(payload)
        except Exception as e:
            print(f"[Client] Receive error: {e}")
        finally:
            client_sock.close()
            root.after(0, window.set_disconnected)
            print("[Client] Disconnected.")

    threading.Thread(target=receive_loop, daemon=True).start()

    # ── 5. Run GUI event loop ──
    def on_close():
        try:
            client_sock.close()
        except Exception:
            pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    start_client()
