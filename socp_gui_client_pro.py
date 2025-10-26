
import threading, queue, json, time, uuid, os, sys, tkinter as tk
from tkinter import ttk, messagebox
import config
from ws import client_connect, client_send_text, client_recv_text

# Crypto backend
if config.CRYPTO_BACKEND == "strict":
    import crypto_strict as crypto
else:
    import crypto_demo as crypto

APP_TITLE = "SOCP — Chat"
POLL_MS = 60

def now_ms(): return int(time.time()*1000)
def jdump(o): return json.dumps(o, separators=(",",":"))
def send_json(conn, obj): client_send_text(conn, jdump(obj))

class Toast(tk.Toplevel):
    def __init__(self, master, text, ms=1500):
        super().__init__(master)
        self.overrideredirect(True)
        self.configure(bg="#222")
        lbl = tk.Label(self, text=text, fg="#eee", bg="#222", padx=12, pady=8)
        lbl.pack()
        self.after(ms, self.destroy)
        self.update_idletasks()
        x = master.winfo_rootx() + master.winfo_width() - self.winfo_width() - 24
        y = master.winfo_rooty() + master.winfo_height() - self.winfo_height() - 24
        self.geometry(f"+{x}+{y}")

class ProGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x680")
        self.minsize(800, 560)
        self._apply_dark_theme()

        self.conn = None
        self.user_id = None
        self.priv = None
        self.pub_b64 = None
        self.recvq = queue.Queue()
        self.directory = {}   # user_id -> {"name","pubkey"}
        self.connected = False

        self._build_ui()
        self.after(POLL_MS, self._poll)

    # ----- Theme -----
    def _apply_dark_theme(self):
        bg = "#0f1115"; fg = "#eaeaea"; acc = "#2f81f7"; card = "#151821"
        self.configure(bg=bg)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=bg, foreground=fg, fieldbackground=card)
        style.configure("TFrame", background=bg)
        style.configure("Card.TFrame", background=card, relief="flat")
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Accent.TButton", background=acc, foreground="#fff")
        style.map("Accent.TButton", background=[("active", "#2563eb")])
        style.configure("TButton", background="#1f2330", foreground=fg)
        style.map("TButton", background=[("active", "#252a38")])
        style.configure("TCheckbutton", background=bg, foreground=fg)

    # ----- UI -----
    def _build_ui(self):
        # Top bar
        top = ttk.Frame(self); top.pack(fill="x", padx=14, pady=12)
        self.host_var = tk.StringVar(value=config.SERVER_HOST)
        self.port_var = tk.StringVar(value=str(config.SERVER_PORT))
        self.name_var = tk.StringVar(value="User")

        ttk.Label(top, text="Host").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, width=16, textvariable=self.host_var).grid(row=0, column=1, padx=(6,12))
        ttk.Label(top, text="Port").grid(row=0, column=2, sticky="w")
        ttk.Entry(top, width=7, textvariable=self.port_var).grid(row=0, column=3, padx=(6,12))
        ttk.Label(top, text="Name").grid(row=0, column=4, sticky="w")
        ttk.Entry(top, width=18, textvariable=self.name_var).grid(row=0, column=5, padx=(6,12))

        self.btn_connect = ttk.Button(top, text="Connect", style="Accent.TButton", command=self.on_connect)
        self.btn_connect.grid(row=0, column=6, padx=(6,6))
        self.btn_setname = ttk.Button(top, text="Set name", command=self.on_set_name, state="disabled")
        self.btn_setname.grid(row=0, column=7)

        # Main area
        main = ttk.Frame(self, style="Card.TFrame"); main.pack(fill="both", expand=True, padx=14, pady=(0,12))

        # Left panel
        left = ttk.Frame(main); left.pack(side="left", fill="y", padx=12, pady=12)
        ttk.Label(left, text="Recipients").pack(anchor="w")
        self.search_var = tk.StringVar()
        search = ttk.Entry(left, textvariable=self.search_var)
        search.pack(fill="x", pady=(6,6))
        search.bind("<KeyRelease>", lambda e: self._refresh_user_list())
        self.listbox = tk.Listbox(left, height=18, bg="#0f1115", fg="#eaeaea", selectbackground="#2f81f7", activestyle="none", highlightthickness=0)
        self.listbox.pack(fill="y", expand=True)
        self.chk_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Send to all", variable=self.chk_all).pack(anchor="w", pady=(8,0))

        # Right panel
        right = ttk.Frame(main); right.pack(side="left", fill="both", expand=True, padx=(12,12), pady=12)
        self.chat = tk.Text(right, bg="#0d1017", fg="#eaeaea", insertbackground="#eaeaea", wrap="word", height=20, borderwidth=0, highlightthickness=0)
        self.chat.pack(fill="both", expand=True)
        self.chat.configure(state="disabled")

        # Compose bar
        compose = ttk.Frame(self); compose.pack(fill="x", padx=14, pady=(0,10))
        self.msg_var = tk.StringVar()
        entry = ttk.Entry(compose, textvariable=self.msg_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self.on_send())
        ttk.Button(compose, text="Send", style="Accent.TButton", command=self.on_send).pack(side="left", padx=8)
        ttk.Button(compose, text="Clear", command=self._clear_chat).pack(side="left")
        ttk.Button(compose, text="List", command=self._dump_dir).pack(side="left", padx=(6,0))

        # Status
        self.status = ttk.Label(self, text="Disconnected")
        self.status.pack(fill="x", padx=14, pady=(0,10))

    # ----- Helpers -----
    def _append_chat(self, text):
        self.chat.configure(state="normal")
        self.chat.insert("end", text + "\n")
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def _clear_chat(self):
        self.chat.configure(state="normal")
        self.chat.delete("1.0", "end")
        self.chat.configure(state="disabled")

    def _refresh_user_list(self):
        q = self.search_var.get().strip().lower()
        self.listbox.delete(0, "end")
        for uid, info in sorted(self.directory.items()):
            name = info.get("name","")
            line = f"{uid}  {name}"
            if not q or q in uid.lower() or q in name.lower():
                self.listbox.insert("end", line)

    def _toast(self, text, ms=1400):
        Toast(self, text, ms)

    # ----- Connect / I/O -----
    def on_connect(self):
        if self.connected: 
            self._toast("Already connected"); return
        host = self.host_var.get().strip()
        try: port = int(self.port_var.get().strip())
        except: messagebox.showerror(APP_TITLE, "Invalid port"); return
        label = self.name_var.get().strip() or "User"

        try: uuid.UUID(label); self.user_id = label
        except: self.user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, label))

        self.priv, pub = crypto.ensure_keys(config.KEYS_DIR, f"user_{self.user_id}")
        self.pub_b64 = crypto.public_b64url(pub)

        try:
            self.conn = client_connect(host, port, "/")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Connect failed: {e}"); return

        hello = {"type":"USER_HELLO","from":self.user_id,"to":"server_1","ts":now_ms(),
                 "payload":{"client":"gui-pro","pubkey":self.pub_b64,"enc_pubkey":self.pub_b64,"name":label},"sig":""}
        send_json(self.conn, hello)
        self.connected = True
        self.status.configure(text=f"Connected as {self.user_id}  —  ws://{host}:{port}")
        self.btn_setname.configure(state="normal")
        self._append_chat(f"[system] Connected as {self.user_id}")
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def on_set_name(self):
        if not self.connected: return
        new_name = self.name_var.get().strip()
        send_json(self.conn, {"type":"SET_NAME","from":self.user_id,"to":"server_1","ts":now_ms(),
                              "payload":{"name":new_name},"sig":""})
        self._toast("Name updated")

    def _dump_dir(self):
        if not self.directory:
            self._append_chat("[dir] no users yet")
        else:
            self._append_chat("[dir] known users:")
            for uid, v in self.directory.items():
                nm = v.get("name","")
                self._append_chat(f"  {uid}  {('('+nm+')') if nm else ''}")

    def on_send(self):
        if not self.connected: return
        text = self.msg_var.get().strip()
        if not text: return
        self.msg_var.set("")

        if self.chk_all.get():
            # E2EE fan-out
            n=0
            for rid in list(self.directory.keys()):
                if rid == self.user_id: continue
                n += self._send_dm(rid, text)
            self._toast(f"Sent to {n} recipient(s)")
            return

        sel = self.listbox.curselection()
        if not sel:
            self._toast("Select a recipient or enable 'Send to all'"); return
        rid = self.listbox.get(sel[0]).split()[0]
        if self._send_dm(rid, text):
            self._toast("Sent")

    def _send_dm(self, rid, text):
        info = self.directory.get(rid)
        if not info or not info.get("pubkey"):
            self._append_chat(f"[error] no pubkey for {rid}")
            return 0
        ct = crypto.encrypt_for_recipient(text.encode(), info["pubkey"])
        cts = now_ms()
        obj = {"type":"MSG_DIRECT","from":self.user_id,"to":rid,"ts":cts,
               "payload":{"ciphertext":ct,"sender_pub":self.pub_b64,"cts":cts,
                          "content_sig": crypto.sign_content(ct, self.user_id, rid, cts, self.priv)},"sig":""}
        send_json(self.conn, obj); return 1

    # ----- Receive -----
    def _recv_loop(self):
        while True:
            try:
                msg = client_recv_text(self.conn)
            except Exception as e:
                self.recvq.put(("error", str(e))); break
            if msg is None:
                self.recvq.put(("closed","")); break
            self.recvq.put(("message", msg))

    def _poll(self):
        try:
            while True:
                kind, payload = self.recvq.get_nowait()
                if kind == "message":
                    self._handle_incoming(payload)
                elif kind == "closed":
                    self.connected = False
                    self.status.configure(text="Disconnected")
                    self._append_chat("[system] disconnected")
                elif kind == "error":
                    self._append_chat(f"[error] {payload}")
        except queue.Empty:
            pass
        self.after(POLL_MS, self._poll)

    def _handle_incoming(self, raw):
        try: obj = json.loads(raw)
        except Exception: return
        t = obj.get("type","")
        if t == "USER_DELIVER":
            pay = obj.get("payload",{})
            ct = pay.get("ciphertext",""); sender = pay.get("sender","?")
            sender_pub_b64 = pay.get("sender_pub",""); cts = pay.get("cts", obj.get("ts", 0))
            ok = crypto.verify_content_sig_dm(ct, sender, self.user_id, cts, pay.get("content_sig",""), sender_pub_b64) \
                 or crypto.verify_content_sig_public(ct, sender, cts, pay.get("content_sig",""), sender_pub_b64)
            try: pt = crypto.decrypt_for_recipient(ct, self.priv).decode(errors="ignore")
            except Exception: pt = "<decrypt error>"
            tick = "✓" if ok else "✗"
            self._append_chat(f"<from {sender}> [{tick} sig] {pt}")
        elif t == "USER_DIRECTORY":
            self.directory = {u["user_id"]: {"name":u.get("name",""), "pubkey":u.get("pubkey","")} for u in obj.get("payload",{}).get("users",[])}
            self._refresh_user_list()
            self._toast("Directory updated")

if __name__ == "__main__":
    ProGui().mainloop()
