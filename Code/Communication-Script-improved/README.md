# 💬 LAN Secure Chat

A small local-network chat app with an admin-controlled server and a
lightweight client GUI. Every message is encrypted before it hits the
network, and it's built to run entirely on your own LAN — no internet,
no accounts, no external servers.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

**Repo:** https://github.com/PythonZLJS/YOUR-REPO-NAME-HERE

---

## 👋 Hey, welcome

I made this as a simple way to chat with people on the same network
without relying on some third-party app or server. One person runs the
server, everyone else connects to it as a client, and the admin approves
who gets in.

A couple of honest heads-ups before you dive in:
- This only works between devices on the **same network**, and it won't
  work if you (or the person connecting to you) are on a **VPN** — the
  VPN will get in the way of the local connection.
- Messages are encrypted in transit, but this was built for fun/personal
  use on a trusted home/school/work LAN, not as a hardened, audited
  security product. In particular, the encryption key is a fixed string
  baked into the source — anyone with the code can read the key, so
  don't rely on this for anything sensitive.
- Alongside the raw source code, I've also attached **pre-compiled
  Windows versions of both the server and the client** in the release —
  worth a look if you'd rather skip installing anything. The compiled
  versions do just take a little longer to start up than running from
  source.
- Also I may add more features in the future as well as some other code
  on my GitHub account that could be useful.
- If you enjoyed this project, feel free to star the repo, and you're
  welcome to fork it and make it your own.
- I've also got a **smaller, separate project** that's just simple
  2-person messaging with lighter encryption, if you want something more
  minimal than this.

Have fun with it, and if something breaks, open an issue — I'd genuinely
like to know.

---

## ✨ Quick feature rundown

- **One admin, many clients** — one person runs the server (`server.pyw`)
  and acts as admin; everyone else runs the client (`client.py`) and
  connects to the admin's IP.
- **Join approval** — every new connection pops up on the admin's screen
  for Accept/Reject before the person can chat. Previously banned
  usernames/IPs are auto-rejected without even bothering the admin.
- **Encrypted, framed messages** — everything sent between client and
  server is length-prefixed and encrypted, so it isn't sitting in plain
  text on the network and can't get corrupted by TCP merging or
  splitting messages under load.
- **Broadcast + private messages** — chat with everyone at once, or send
  a direct message to one specific person.
- **Rooms** — the admin can create/delete chat rooms and move users
  between them.
- **Admin tools** — kick users, ban by username or IP, an admin-only
  inbox for messages sent with `@admin` / `/admin`, and an admin chat
  window to talk to everyone or a specific user.
- **Live latency** — clients ping the server and see their latency in
  real time; the admin has a live latency panel for every connected user.
- **Auto-updating user list** — the client's "select user" dropdown for
  private messages refreshes automatically as people join/leave.
- **Full scrollable chat history** — both the client window and the
  admin chat window keep the whole conversation, not just the last
  couple of lines.
- **Your IP shown for you** — both the server and client windows display
  the local IP so you know what to connect to / share with others.

---

## 🚀 Getting started (running from source)

### 1. Install Python
You need Python 3.9 or newer. Jump to **[Installing Python](#-installing-python)**
at the very bottom of this page if you don't have it yet.

### Important
If you're just running the pre-compiled EXEs, you don't need to install
anything — not Python, not the libraries. Just run it as-is; it's a
portable app.

### 2. Get the code
```bash
git clone https://github.com/PythonZLJS/YOUR-REPO-NAME-HERE.git
cd YOUR-REPO-NAME-HERE
```
Or just hit the green **Code → Download ZIP** button on the repo page if
you'd rather not use git.

### 3. Install the dependencies
Open a terminal in the folder you just downloaded/cloned, then run:
```bash
pip install cryptography
```
This installs:

| Package | What it's for |
|---|---|
| `cryptography` | Encrypts/decrypts every message sent over the network |

`tkinter` (the GUI toolkit both windows use) ships with most standard
Python installs, so there's nothing extra to install for it on Windows
or macOS. On some Linux distros you may need it separately, e.g.
`sudo apt install python3-tk`.

### 4. Run the server (the admin)
Whoever is hosting the chat runs:
```bash
python server.pyw
```
This opens the **Admin Control Panel**. It shows your local IP at the
top — share that with everyone who wants to connect.

### 5. Run the client (everyone else)
```bash
python client.py
```
Each client is asked for the server's IP and a username, then a
"Waiting for admin approval..." window shows up until the admin accepts.

---

## 🖱️ Using it once it's set up

### As a client
1. Enter the server's IP and your username when prompted.
2. Wait for the admin to accept your join request.
3. Type in **"Send to everyone"** to broadcast, or pick a name from the
   **"Select user"** dropdown and use **"Send private message"** for a PM.
4. Hit **Refresh Users** any time if the user list looks out of date.
5. Your live latency to the server shows near the top of the window.
6. Start a message with `@admin` or `/admin` and it lands directly in
   the admin's private inbox, separate from normal chat.

### As the admin
1. New join requests pop up automatically — **Accept** or **Reject**
   each one. Known-banned users/IPs are turned away automatically and
   never show a popup.
2. The **Users** list shows everyone connected, their room, and their
   latency; the **Rooms** list shows all chat rooms.
3. Select a user (and a room) and use the room controls to move people
   between rooms, or add/delete rooms entirely.
4. Select a user and hit **Kick** to disconnect them, or **Ban** to
   block their username and IP from rejoining.
5. **Ping All Clients** refreshes everyone's latency reading; **Open
   Latency Panel** gives you a live-updating view of every user's ping.
6. **Open Admin Chat** gives you your own window to broadcast to
   everyone or message a specific user, separately from the main panel.
7. Messages starting with `@admin`/`/admin` from any client show up in
   the **Admin inbox** list at the top of the panel.

---

## 🧠 How it works

- **Server/client model** — `server.pyw` opens a TCP socket and listens
  for connections on port `7879`. Each connecting client gets its own
  handler thread, so multiple people can chat at once without blocking
  each other.
- **Message framing** — TCP is a byte stream with no built-in message
  boundaries, so every message is sent as a 4-byte length header
  followed by that many bytes of encrypted payload. The receiver reads
  the header first, then reads exactly that many bytes before
  decrypting. **This is a wire-format change** from earlier versions of
  this project that read straight off `recv(4096)` — if you have another
  implementation of this protocol (e.g. a port to another language), it
  needs to speak the same length-prefixed framing to interoperate.
- **Join approval flow** — when a client connects, it sends its username
  to the server, then waits. The server checks it against the ban list
  first; if it's clear, the admin gets an Accept/Reject popup, and only
  after acceptance does the client's chat window open and the client get
  added to the "Lobby" room.
- **Encryption** — every message is transformed with a Caesar cipher,
  converted to a binary string, then encrypted with `Fernet` (from the
  `cryptography` library, which is AES-128-CBC under the hood) before
  being sent over the socket. The receiving side reverses the exact same
  steps. Both sides use the same shared key baked into the code. Note
  that the Caesar/binary steps don't add real security on top of
  Fernet — they're kept only so the wire format stays compatible with
  other implementations of this protocol; the actual security comes
  entirely from Fernet/AES.
- **Rooms & broadcasting** — the server tracks which room each client is
  in. A broadcast message is only relayed to other clients in the same
  room; a private message is looked up by username and sent directly to
  that one client's socket.
- **Latency** — clients periodically get a `PING` message from the
  server with a timestamp, echo it straight back, and the server (or
  client, depending on direction) calculates round-trip time in
  milliseconds from the difference.
- **Live user list** — whenever someone joins, leaves, or gets moved
  between rooms, the server rebroadcasts the full username list to every
  client, which is what keeps each client's PM dropdown up to date
  without needing a manual refresh.
- **Thread safety** — the server's shared state (connected clients,
  rooms, bans, latencies) is guarded by a lock since it's touched both
  by each client's network thread and by the admin's button clicks on
  the main thread; all GUI updates triggered from a network thread are
  marshalled back onto the main thread via `root.after(...)`, since
  Tkinter itself isn't thread-safe.

---

## 📦 Using the pre-compiled version instead

If you'd rather not install Python at all, grab the pre-compiled Windows
executables for both the server and client from the **Releases** section
of the repo. They run standalone with nothing else needed — the only
trade-off is they take a bit longer to start up than running the `.py`/
`.pyw` files directly with Python.

---

## 📁 Project structure
```
YOUR-REPO-NAME-HERE/
├── server.pyw            # admin server + control panel
├── client.py              # client chat window
└── README.md
```

---

## 🐍 Installing Python

If you don't already have Python installed:

1. Go to https://www.python.org/downloads/
2. Download the latest Python 3 installer for your OS.
3. **Windows:** during install, tick **"Add python.exe to PATH"** before
   clicking Install — this is the single most common setup mistake, and
   skipping it is why `python` or `pip` might say "not recognized" later.
4. **macOS:** the installer from python.org works fine, or use
   `brew install python` if you have Homebrew.
5. **Linux:** most distributions include Python already; if not,
   `sudo apt install python3 python3-pip python3-venv` (Debian/Ubuntu) or
   your distribution's equivalent package manager.
6. Confirm it worked:
   ```bash
   python --version      # Windows
   python3 --version     # Linux/macOS
   ```

---

## 📜 License
MIT — do whatever you like with it.
