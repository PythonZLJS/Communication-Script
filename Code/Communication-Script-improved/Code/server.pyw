"""
LAN Secure Chat — server / admin control panel

Wire protocol (must stay in sync with client.py and any other
interoperating client, e.g. a Lua/KOReader port): every message is
length-prefixed (4-byte big-endian header) then Fernet-encrypted
Caesar+binary-encoded text. See encrypt_message()/decrypt_message() and
send_message()/recv_message() below.
"""

import socket
import threading
import base64
import time
from collections import defaultdict
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
HEADER_LEN = 4  # 4-byte big-endian length prefix for framing


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


def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen()

    clients = {}  # sock -> {"username": str, "ip": str, "room": str}
    rooms = defaultdict(set)
    rooms["Lobby"] = set()

    bans_user = set()
    bans_ip = set()
    latencies = {}  # sock -> ms

    # Guards clients/rooms/latencies/bans, which are written both from
    # accept_loop's per-client threads and from Tkinter button callbacks
    # on the main thread.
    state_lock = threading.Lock()

    root = Tk()
    root.title("Admin Control Panel – Admin")
    root.geometry("900x650")

    # Show server IP
    Label(root, text=f"Server IP (connect to this): {get_local_ip()}").pack(anchor="w")

    Label(root, text="Admin inbox (@admin or /admin):").pack(anchor="w")
    inbox_box = Listbox(root, height=6)
    inbox_box.pack(fill=X)

    # ---------- Users list ----------
    user_frame = Frame(root)
    user_frame.pack(fill=X, pady=5)

    Label(user_frame, text="Users:").pack(side=LEFT)
    user_list = Listbox(user_frame, height=10)
    user_list.pack(side=LEFT, fill=X, expand=True)
    user_scroll = Scrollbar(user_frame, command=user_list.yview)
    user_scroll.pack(side=LEFT, fill=Y)
    user_list.config(yscrollcommand=user_scroll.set)

    def refresh_users():
        user_list.delete(0, END)
        with state_lock:
            items = [(info["username"], info["room"], latencies.get(sock, "N/A"))
                     for sock, info in clients.items()]
        for username, room, ping in items:
            user_list.insert(END, f'{username} ({room}) - {ping} ms')

    def broadcast_user_list():
        with state_lock:
            usernames = [info["username"] for info in clients.values()]
            targets = list(clients.keys())
        if "Admin" not in usernames:
            usernames.append("Admin")
        payload = "SYS|USERS|" + ",".join(usernames)
        for sock in targets:
            try:
                send_message(sock, payload)
            except OSError:
                pass

    # ---------- Ping ----------
    def ping_all_clients():
        now = time.time()
        payload = f"SYS|PING|{now}"
        with state_lock:
            targets = list(clients.keys())
        for sock in targets:
            try:
                send_message(sock, payload)
            except OSError:
                pass
        inbox_box.insert(END, "Ping sent to all clients")

    Button(root, text="Ping All Clients", command=ping_all_clients).pack(pady=5)

    # ---------- Latency panel ----------
    latency_win = None
    latency_list = None

    def open_latency_panel():
        nonlocal latency_win, latency_list
        if latency_win is not None:
            return
        latency_win = Toplevel(root)
        latency_win.title("Client Latency Panel")
        latency_win.geometry("300x300")
        latency_win.attributes("-topmost", True)

        Label(latency_win, text="Client Latencies (ms):").pack(anchor="w")
        latency_list = Listbox(latency_win, height=12)
        latency_list.pack(fill=BOTH, expand=True)

        def refresh_latency_panel():
            if latency_list is None:
                return
            with state_lock:
                items = [(info["username"], latencies.get(sock, "N/A"))
                         for sock, info in clients.items()]
            latency_list.delete(0, END)
            for username, ping in items:
                latency_list.insert(END, f'{username}: {ping} ms')
            latency_win.after(1000, refresh_latency_panel)

        latency_win.after(1000, refresh_latency_panel)

        def on_close():
            nonlocal latency_win
            latency_win.destroy()
            latency_win = None

        latency_win.protocol("WM_DELETE_WINDOW", on_close)

    Button(root, text="Open Latency Panel", command=open_latency_panel).pack(pady=5)
    # ---------- Rooms ----------
    room_frame = Frame(root)
    room_frame.pack(fill=X, pady=5)

    Label(room_frame, text="Rooms:").pack(side=LEFT)
    room_list = Listbox(room_frame, height=5)
    room_list.pack(side=LEFT, fill=X, expand=True)
    room_scroll = Scrollbar(room_frame, command=room_list.yview)
    room_scroll.pack(side=LEFT, fill=Y)
    room_list.config(yscrollcommand=room_scroll.set)

    def refresh_rooms():
        room_list.delete(0, END)
        with state_lock:
            names = list(rooms.keys())
        for r in names:
            room_list.insert(END, r)

    refresh_rooms()

    room_ctrl = Frame(root)
    room_ctrl.pack(fill=X)

    new_room_entry = Entry(room_ctrl)
    new_room_entry.pack(side=LEFT)

    def add_room():
        name = new_room_entry.get().strip()
        with state_lock:
            exists = name in rooms
            if name and not exists:
                rooms[name] = set()
        if name and not exists:
            refresh_rooms()
        new_room_entry.delete(0, END)

    def del_room():
        sel = room_list.curselection()
        if not sel:
            return
        room_name = room_list.get(sel[0])
        if room_name == "Lobby":
            return
        with state_lock:
            if room_name not in rooms:
                return
            for sock in list(rooms[room_name]):
                rooms[room_name].remove(sock)
                rooms["Lobby"].add(sock)
                clients[sock]["room"] = "Lobby"
            del rooms[room_name]
        refresh_rooms()
        refresh_users()
        broadcast_user_list()

    Button(room_ctrl, text="Add room", command=add_room).pack(side=LEFT)
    Button(room_ctrl, text="Delete room", command=del_room).pack(side=LEFT)

    # ---------- User controls ----------
    user_ctrl = Frame(root)
    user_ctrl.pack(fill=X, pady=5)

    def move_user_to_room():
        sel_user = user_list.curselection()
        sel_room = room_list.curselection()
        if not sel_user or not sel_room:
            return
        target_room = room_list.get(sel_room[0])
        with state_lock:
            socks = list(clients.keys())
            if sel_user[0] >= len(socks):
                return
            sock = socks[sel_user[0]]
            old_room = clients[sock]["room"]
            rooms[old_room].discard(sock)
            rooms[target_room].add(sock)
            clients[sock]["room"] = target_room
        refresh_users()
        broadcast_user_list()

    def kick_user():
        sel_user = user_list.curselection()
        if not sel_user:
            return
        with state_lock:
            socks = list(clients.keys())
            if sel_user[0] >= len(socks):
                return
            sock = socks[sel_user[0]]
            info = clients[sock]
            rooms[info["room"]].discard(sock)
            del clients[sock]
        try:
            sock.close()
        except OSError:
            pass
        refresh_users()
        broadcast_user_list()

    def ban_user():
        sel_user = user_list.curselection()
        if not sel_user:
            return
        with state_lock:
            socks = list(clients.keys())
            if sel_user[0] >= len(socks):
                return
            sock = socks[sel_user[0]]
            info = clients[sock]
            bans_user.add(info["username"])
            bans_ip.add(info["ip"])
            rooms[info["room"]].discard(sock)
            del clients[sock]
        try:
            sock.close()
        except OSError:
            pass
        refresh_users()
        broadcast_user_list()

    def unban_user():
        win = Toplevel(root)
        win.title("Unban user")
        Label(win, text="Username to unban:").pack()
        e = Entry(win)
        e.pack()

        def do_unban():
            name = e.get().strip()
            with state_lock:
                bans_user.discard(name)
            win.destroy()

        Button(win, text="Unban", command=do_unban).pack()

    Button(user_ctrl, text="Move to room", command=move_user_to_room).pack(side=LEFT)
    Button(user_ctrl, text="Kick", command=kick_user).pack(side=LEFT)
    Button(user_ctrl, text="Ban", command=ban_user).pack(side=LEFT)
    Button(user_ctrl, text="Unban", command=unban_user).pack(side=LEFT)

    # ---------- Admin chat ----------
    admin_chat_win = None
    admin_chat_box = None
    admin_all_entry = None
    admin_pm_entry = None
    admin_target_var = StringVar(root)
    admin_target_var.set("Select user")
    admin_target_menu = None

    def refresh_target_menu():
        if admin_target_menu is None:
            return
        with state_lock:
            names = [info["username"] for info in clients.values()]
        menu = admin_target_menu["menu"]
        menu.delete(0, "end")
        menu.add_command(label="Select user", command=lambda: admin_target_var.set("Select user"))
        for name in names:
            menu.add_command(label=name, command=lambda v=name: admin_target_var.set(v))

    def update_admin_chat_display(text):
        if admin_chat_box is None:
            return
        admin_chat_box.config(state="normal")
        admin_chat_box.insert(END, text + "\n")
        admin_chat_box.see(END)
        admin_chat_box.config(state="disabled")

    def open_admin_chat():
        nonlocal admin_chat_win, admin_chat_box, admin_all_entry, admin_pm_entry, admin_target_menu
        if admin_chat_win is not None:
            return

        admin_chat_win = Toplevel(root)
        admin_chat_win.title("Admin Chat – Admin")
        admin_chat_win.geometry("500x400")
        admin_chat_win.attributes("-topmost", True)

        chat_frame = Frame(admin_chat_win)
        chat_frame.pack(fill=BOTH, expand=True, padx=4, pady=4)
        chat_scroll = Scrollbar(chat_frame)
        chat_scroll.pack(side=RIGHT, fill=Y)
        admin_chat_box = Text(chat_frame, height=12, wrap="word", state="disabled",
                               yscrollcommand=chat_scroll.set)
        admin_chat_box.pack(side=LEFT, fill=BOTH, expand=True)
        chat_scroll.config(command=admin_chat_box.yview)

        Label(admin_chat_win, text="To everyone:").pack(anchor="w")
        admin_all_entry = Entry(admin_chat_win)
        admin_all_entry.pack(fill=X)

        Label(admin_chat_win, text="To specific user:").pack(anchor="w")
        admin_pm_entry = Entry(admin_chat_win)
        admin_pm_entry.pack(fill=X)

        admin_target_menu = OptionMenu(admin_chat_win, admin_target_var, "Select user")
        admin_target_menu.pack()
        refresh_target_menu()

        def send_admin_all(event=None):
            msg = admin_all_entry.get().strip()
            if not msg:
                return
            full = f"Admin: {msg}"
            with state_lock:
                targets = list(clients.keys())
            for sock in targets:
                try:
                    send_message(sock, f"ALL|{full}")
                except OSError:
                    pass
            update_admin_chat_display(full)
            admin_all_entry.delete(0, END)

        def send_admin_pm():
            msg = admin_pm_entry.get().strip()
            target = admin_target_var.get()
            if not msg or target == "Select user":
                return
            full = f"Admin -> {target}: {msg}"
            with state_lock:
                match = next((sock for sock, info in clients.items()
                              if info["username"] == target), None)
            if match is not None:
                try:
                    send_message(match, f"PM|{full}")
                except OSError:
                    pass
            update_admin_chat_display(full)
            admin_pm_entry.delete(0, END)

        def admin_refresh_users():
            refresh_users()
            refresh_target_menu()
            broadcast_user_list()
            update_admin_chat_display("Admin refreshed user list")

        admin_all_entry.bind("<Return>", send_admin_all)
        Button(admin_chat_win, text="Send to everyone", command=send_admin_all).pack()
        Button(admin_chat_win, text="Send to user", command=send_admin_pm).pack()
        Button(admin_chat_win, text="Refresh Users", command=admin_refresh_users).pack()

        def on_close():
            nonlocal admin_chat_win, admin_chat_box
            admin_chat_win.destroy()
            admin_chat_win = None
            admin_chat_box = None

        admin_chat_win.protocol("WM_DELETE_WINDOW", on_close)

    Button(root, text="Open Admin Chat", command=open_admin_chat).pack(pady=5)

    # ---------- Join popup ----------
    def show_join_popup(sock, username, ip):
        win = Toplevel(root)
        win.title("Join request")
        win.attributes("-topmost", True)
        win.geometry("300x120+0+0")

        Label(win, text=f'User "{username}" from {ip} wants to join').pack()

        def accept():
            with state_lock:
                clients[sock] = {"username": username, "ip": ip, "room": "Lobby"}
                rooms["Lobby"].add(sock)
            refresh_users()
            refresh_target_menu()
            broadcast_user_list()
            try:
                send_message(sock, "SYS|ACCEPT")
            except OSError:
                pass
            win.destroy()

        def reject():
            try:
                send_message(sock, "SYS|REJECT")
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
            win.destroy()

        Button(win, text="Accept", command=accept).pack(side=LEFT)
        Button(win, text="Reject", command=reject).pack(side=LEFT)

    # ---------- Networking / Main Handler ----------
    def handle_client(sock, addr):
        ip = addr[0]
        try:
            username = sock.recv(1024).decode().strip()
        except OSError:
            sock.close()
            return
        if not username:
            sock.close()
            return

        # Auto-reject known-banned username/IP without bothering the admin
        with state_lock:
            banned = username in bans_user or ip in bans_ip
        if banned:
            try:
                send_message(sock, "SYS|REJECT")
            except OSError:
                pass
            sock.close()
            return

        # Ask admin to approve join
        root.after(0, lambda: show_join_popup(sock, username, ip))

        while True:
            try:
                text = recv_message(sock)
            except (OSError, InvalidToken, ValueError):
                break
            if text is None:
                break

            # ---------- PING / LATENCY ----------
            if text.startswith("SYS|PONG|"):
                parts = text.split("|")
                if len(parts) >= 4:
                    try:
                        rtt_ms = round(float(parts[3]), 1)
                    except ValueError:
                        rtt_ms = None
                    if rtt_ms is not None:
                        with state_lock:
                            latencies[sock] = rtt_ms
                        root.after(0, lambda u=username, r=rtt_ms: (
                            inbox_box.insert(END, f'Latency {u}: {r} ms'),
                            refresh_users(),
                        ))
                continue

            if text == "SYS|REFRESH":
                broadcast_user_list()
                continue

            # ---------- ADMIN MESSAGES ----------
            # Check the actual message content (after the ALL|/PM| envelope
            # is stripped), not the raw "ALL|user: @admin ..." wrapper —
            # otherwise this branch never fires since normal chat always
            # arrives wrapped in ALL|/PM|.
            if text.startswith("ALL|"):
                content = text[4:]
            elif text.startswith("PM|"):
                content = text[3:]
            else:
                content = text

            body = content.split(":", 1)[1].strip() if ":" in content else content
            if body.lower().startswith("@admin") or body.lower().startswith("/admin"):
                root.after(0, lambda t=content: inbox_box.insert(END, t))
                continue

            # ---------- BROADCAST ----------
            if text.startswith("ALL|"):
                root.after(0, lambda c=content: update_admin_chat_display(c))
                with state_lock:
                    room = clients.get(sock, {}).get("room")
                    targets = [o for o in rooms.get(room, set()) if o != sock] if room else []
                for other in targets:
                    try:
                        send_message(other, text)  # relay the full "ALL|..." message as-is
                    except OSError:
                        pass
                continue

            # ---------- PRIVATE MESSAGE ----------
            if text.startswith("PM|"):
                root.after(0, lambda c=content: update_admin_chat_display(c))

                # Extract target name
                target_name = None
                if "->" in content:
                    try:
                        sender_part, rest = content.split("->", 1)
                        target_part, msg_part = rest.split(":", 1)
                        target_name = target_part.strip()
                    except ValueError:
                        target_name = None

                if target_name:
                    with state_lock:
                        match = next((o for o, info in clients.items()
                                      if info["username"] == target_name), None)
                    if match is not None:
                        try:
                            send_message(match, content)
                        except OSError:
                            pass
                continue

            # ---------- SERVER RECEIVES PING ----------
            if text.startswith("SYS|PING|"):
                ts = float(text.split("|")[2])
                now = time.time()
                rtt = (now - ts) * 1000
                pong = f"SYS|PONG|{ts}|{rtt}"
                try:
                    send_message(sock, pong)
                except OSError:
                    break
                continue

        # ---------- CLEANUP ON DISCONNECT ----------
        with state_lock:
            was_client = sock in clients
            if was_client:
                info = clients[sock]
                rooms[info["room"]].discard(sock)
                del clients[sock]
            latencies.pop(sock, None)
        if was_client:
            root.after(0, lambda: (refresh_users(), refresh_target_menu(), broadcast_user_list()))

        try:
            sock.close()
        except OSError:
            pass

    # ---------- Accept Loop ----------
    def accept_loop():
        while True:
            try:
                client, addr = server.accept()
            except OSError:
                break
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    root.mainloop()

# ---------- MAIN ----------
if __name__ == "__main__":
    run_server()
