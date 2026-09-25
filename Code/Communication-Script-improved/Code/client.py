"""
LAN Secure Chat — client

Wire protocol (must stay in sync with server.pyw and any other
interoperating client): plaintext is Caesar-shifted by 3, converted to
a space-separated binary string, then encrypted with Fernet using a
shared static key. See encrypt_message()/decrypt_message() below.
"""

import socket
import threading
import base64
import time
from tkinter import *
from cryptography.fernet import Fernet, InvalidToken

# ---------- IP Viewer ----------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "Unknown"

# ---------- Chat Encryption ----------
# NOTE: the Caesar shift + binary encoding add no real security on top of
# Fernet (AES-128-CBC) — they're just obfuscation and roughly 8x the
# message size on the wire. Left in place so this stays wire-compatible
# with other clients speaking the same protocol.
KEY = base64.urlsafe_b64encode(b"binArynUmberSARethebestyay^&$%*&")
f = Fernet(KEY)

def caesar_shift(text, shift=3):
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)

def to_binary(text):
    return " ".join(format(ord(c), "08b") for c in text)

def from_binary(binary_text):
    parts = binary_text.split()
    return "".join(chr(int(b, 2)) for b in parts)

def encrypt_message(msg: str) -> bytes:
    shifted = caesar_shift(msg, 3)
    binary = to_binary(shifted)
    return f.encrypt(binary.encode())

def decrypt_message(token: bytes) -> str:
    binary = f.decrypt(token).decode()
    ascii_text = from_binary(binary)
    return caesar_shift(ascii_text, -3)

PORT = 7879
HEADER_LEN = 4  # 4-byte big-endian length prefix for framing (see recv_message)


def send_message(sock, plaintext: str):
    """Encrypt + length-prefix + send. TCP has no message boundaries, so
    every message is framed with a 4-byte length header the receiver
    reads first — this replaces the old bare recv(4096) which could
    silently merge or truncate messages under load."""
    payload = encrypt_message(plaintext)
    sock.sendall(len(payload).to_bytes(HEADER_LEN, "big") + payload)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_message(sock):
    """Read one full framed message, or None if the connection closed."""
    header = recv_exact(sock, HEADER_LEN)
    if header is None:
        return None
    length = int.from_bytes(header, "big")
    payload = recv_exact(sock, length)
    if payload is None:
        return None
    return decrypt_message(payload)


def run_client(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, PORT))
    except OSError as e:
        print(f"Could not connect to {ip}:{PORT} — {e}")
        return

    username = input("Enter username: ").strip() or "User"
    try:
        sock.sendall(username.encode())
    except OSError as e:
        print(f"Failed to send username: {e}")
        sock.close()
        return

    # ---------- Waiting for admin approval ----------
    wait_win = Tk()
    wait_win.title("Connecting...")
    wait_win.geometry("260x80")
    wait_win.attributes("-topmost", True)
    Label(wait_win, text="Waiting for admin approval...").pack(pady=10)

    accepted_flag = {"status": None}

    def wait_receive():
        while True:
            try:
                text = recv_message(sock)
            except (OSError, InvalidToken, ValueError):
                break
            if text is None:
                break
            if text == "SYS|ACCEPT":
                accepted_flag["status"] = True
                break
            elif text == "SYS|REJECT":
                accepted_flag["status"] = False
                break
        wait_win.after(0, wait_win.destroy)

    threading.Thread(target=wait_receive, daemon=True).start()
    wait_win.mainloop()

    if accepted_flag["status"] is not True:
        print("Connection rejected by admin.")
        sock.close()
        return

    # ---------- Main Client Window ----------
    win = Tk()
    win.title(f"Secure Chat – {username}")
    win.geometry("550x500")
    win.attributes("-alpha", 0.95)
    win.attributes("-topmost", True)

    # Show client IP
    Label(win, text=f"Your IP: {get_local_ip()}").pack(anchor="w")

    # ---------- Message Display (full scrollable history, not just last 3) ----------
    msg_frame = Frame(win)
    msg_frame.pack(fill=BOTH, expand=True, padx=4, pady=4)
    msg_scroll = Scrollbar(msg_frame)
    msg_scroll.pack(side=RIGHT, fill=Y)
    msg_box = Text(msg_frame, height=15, wrap="word", state="disabled",
                    yscrollcommand=msg_scroll.set)
    msg_box.pack(side=LEFT, fill=BOTH, expand=True)
    msg_scroll.config(command=msg_box.yview)

    # ---------- Latency Display ----------
    latency_label = Label(win, text="Latency: N/A ms", anchor="w")
    latency_label.pack(fill=X)

    # ---------- Chat Inputs ----------
    Label(win, text="Send to everyone:").pack(anchor="w")
    entry_all = Entry(win)
    entry_all.pack(fill=X)

    Label(win, text="Send private message:").pack(anchor="w")
    entry_pm = Entry(win)
    entry_pm.pack(fill=X)

    # ---------- Dropdown PM target (auto-updating) ----------
    Label(win, text="Select user:").pack(anchor="w")
    pm_target_var = StringVar(win)
    pm_target_var.set("Select user")
    pm_target_menu = OptionMenu(win, pm_target_var, "Select user")
    pm_target_menu.pack()

    # ---------- Update dropdown user list ----------
    def update_pm_dropdown(names):
        menu = pm_target_menu["menu"]
        menu.delete(0, "end")
        menu.add_command(label="Select user", command=lambda: pm_target_var.set("Select user"))
        for name in names:
            menu.add_command(label=name, command=lambda v=name: pm_target_var.set(v))

    # ---------- Send to everyone ----------
    def send_all(event=None):
        msg = entry_all.get().strip()
        if not msg:
            return
        try:
            send_message(sock, f"ALL|{username}: {msg}")
        except OSError as e:
            update_client_display(f"[Send failed: {e}]")
            return
        entry_all.delete(0, END)

    # ---------- Send private message ----------
    def send_pm():
        msg = entry_pm.get().strip()
        target = pm_target_var.get()
        if not msg or target == "Select user":
            return
        try:
            send_message(sock, f"PM|{username} -> {target}: {msg}")
        except OSError as e:
            update_client_display(f"[Send failed: {e}]")
            return
        entry_pm.delete(0, END)

    # ---------- Refresh user list ----------
    def request_refresh():
        try:
            send_message(sock, "SYS|REFRESH")
        except OSError:
            pass

    entry_all.bind("<Return>", send_all)
    Button(win, text="Send to everyone", command=send_all).pack()
    Button(win, text="Send PM", command=send_pm).pack()
    Button(win, text="Refresh Users", command=request_refresh).pack()

    # ---------- Display helper ----------
    def update_client_display(text):
        msg_box.config(state="normal")
        msg_box.insert(END, text + "\n")
        msg_box.see(END)
        msg_box.config(state="disabled")

    # ---------- Receiving messages ----------
    def receive_messages():
        while True:
            try:
                text = recv_message(sock)
            except (OSError, InvalidToken, ValueError):
                break
            if text is None:
                break

            # ---------- User list update ----------
            if text.startswith("SYS|USERS|"):
                names_str = text[len("SYS|USERS|"):]
                names = [n for n in names_str.split(",") if n.strip()]
                win.after(0, lambda ns=names: update_pm_dropdown(ns))
                continue

            # ---------- Ping ----------
            if text.startswith("SYS|PING|"):
                ts = float(text.split("|")[2])
                now = time.time()
                rtt = (now - ts) * 1000
                pong = f"SYS|PONG|{ts}|{rtt}"
                try:
                    send_message(sock, pong)
                except OSError:
                    break
                win.after(0, lambda: latency_label.config(text=f"Latency: {rtt:.1f} ms"))
                continue

            # ---------- Normal chat ----------
            if text.startswith("ALL|"):
                content = text[4:]
            elif text.startswith("PM|"):
                content = text[3:]
            else:
                content = text

            win.after(0, lambda t=content: update_client_display(t))

        win.after(0, lambda: update_client_display("[Disconnected from server]"))
        sock.close()

    # ---------- Start receiver thread ----------
    threading.Thread(target=receive_messages, daemon=True).start()

    # ---------- Mainloop ----------
    win.mainloop()

# ---------- MAIN ----------
if __name__ == "__main__":
    ip = input("Enter server IPv4 (shown on server window): ").strip()
    run_client(ip)
