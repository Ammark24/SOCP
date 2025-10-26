
import threading, queue, json, time, uuid, os, sys, tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import config
from ws import client_connect, client_send_text, client_recv_text

# Crypto backend
if config.CRYPTO_BACKEND == "strict":
    import crypto_strict as crypto
else:
    import crypto_demo as crypto

APP_TITLE = "SOCP GUI Client"
POLL_MS = 100

def now_ms(): return int(time.time()*1000)
def jdump(obj): return json.dumps(obj, separators=(",",":"))
def send_json(conn, obj): client_send_text(conn, jdump(obj))

class SocpGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("920x640")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # State
        self.conn = None
        self.user_id = None
        self.priv = None
        self.pub_b64 = None
        self.recv_queue = queue.Queue()
        self.directory = {}   # user_id -> {"name","pubkey"}
        self.name_index = {}  # lower(name) -> user_id
        self.connected = False

        # UI
        self._build_ui()
        self.after(POLL_MS, self._poll_recv_queue)

    def _build_ui(self):
        top = ttk.Frame(self); top.pack(fill="x", padx=10, pady=8)
        ttk.Label(top, text="Server:").grid(row=0, column=0, sticky="w")
        self.host_var = tk.StringVar(value=config.SERVER_HOST)
        self.port_var = tk.StringVar(value=str(config.SERVER_PORT))
        ttk.Entry(top, width=16, textvariable=self.host_var).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Label(top, text=":").grid(row=0, column=2)
        ttk.Entry(top, width=6, textvariable=self.port_var).grid(row=0, column=3, sticky="w", padx=4)

        ttk.Label(top, text="Your name:").grid(row=0, column=4, sticky="e", padx=(20,2))
        self.name_var = tk.StringVar(value="Alice")
        ttk.Entry(top, width=20, textvariable=self.name_var).grid(row=0, column=5, sticky="w")

        self.btn_connect = ttk.Button(top, text="Connect", command=self.on_connect)
        self.btn_connect.grid(row=0, column=6, padx=8)
        self.btn_setname = ttk.Button(top, text="Set Name", command=self.on_set_name, state="disabled")
        self.btn_setname.grid(row=0, column=7, padx=2)

        # Middle: user list + chat
        middle = ttk.Panedwindow(self, orient="horizontal"); middle.pack(fill="both", expand=True, padx=10, pady=8)

        left = ttk.Frame(middle)
        ttk.Label(left, text="Online users").pack(anchor="w")
        self.users_list = tk.Listbox(left, height=20, exportselection=False)
        self.users_list.pack(fill="both", expand=True)
        self.chk_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Send to all", variable=self.chk_all_var).pack(anchor="w", pady=6)
        middle.add(left, weight=1)

        right = ttk.Frame(middle)
        ttk.Label(right, text="Chat").pack(anchor="w")
        self.chat = scrolledtext.ScrolledText(right, height=24, state="disabled", wrap="word")
        self.chat.pack(fill="both", expand=True)
        middle.add(right, weight=3)

        # Bottom: compose
        bottom = ttk.Frame(self); bottom.pack(fill="x", padx=10, pady=(0,10))
        self.entry_msg = ttk.Entry(bottom)
        self.entry_msg.pack(side="left", fill="x", expand=True)
        self.entry_msg.bind("<Return>", lambda e: self.on_send())
        ttk.Button(bottom, text="Send", command=self.on_send).pack(side="left", padx=6)
        ttk.Button(bottom, text="/list", command=self.on_list).pack(side="left")
        ttk.Button(bottom, text="Clear", command=lambda: self._clear_chat()).pack(side="left", padx=6)

        # Status
        self.status = ttk.Label(self, text="Disconnected", anchor="w")
        self.status.pack(fill="x", padx=10, pady=(0,8))

    def log(self, text):
        self.chat.configure(state="normal")
        self.chat.insert("end", text + "\n")
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def _clear_chat(self):
        self.chat.configure(state="normal")
        self.chat.delete("1.0", "end")
        self.chat.configure(state="disabled")

    # --- Connection & I/O ---
    def on_connect(self):
        if self.connected:
            messagebox.showinfo(APP_TITLE, "Already connected"); return
        host = self.host_var.get().strip()
        try: port = int(self.port_var.get().strip())
        except: messagebox.showerror(APP_TITLE, "Invalid port"); return
        name_label = self.name_var.get().strip() or "User"

        # Stable UUID from label for demo
        try: uuid.UUID(name_label); user_id = name_label
        except: user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, name_label))
        self.user_id = user_id

        # Keys
        self.priv, pub = crypto.ensure_keys(config.KEYS_DIR, f"user_{user_id}")
        self.pub_b64 = crypto.public_b64url(pub)

        # Connect
        try:
            self.conn = client_connect(host, port, "/")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Connect failed: {e}"); return

        # Send USER_HELLO
        hello = {
            "type":"USER_HELLO","from":user_id,"to":"server_1","ts":now_ms(),
            "payload":{"client":"gui-v1","pubkey":self.pub_b64,"enc_pubkey":self.pub_b64,"name":name_label},
            "sig":""
        }
        send_json(self.conn, hello)
        self.connected = True
        self.btn_setname.configure(state="normal")
        self.status.configure(text=f"Connected as {user_id} to ws://{host}:{port}")
        self.log(f"[system] Connected as {user_id}")

        # Start recv thread
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def on_set_name(self):
        if not self.connected: return
        new_name = self.name_var.get().strip()
        send_json(self.conn, {"type":"SET_NAME","from":self.user_id,"to":"server_1","ts":now_ms(),
                              "payload":{"name":new_name},"sig":""})
        self.log(f"[system] Requested name change to {new_name}")

    def on_list(self):
        # Dump known directory
        if not self.directory:
            self.log("[dir] no users yet")
        else:
            self.log("[dir] known users:")
            for uid, v in self.directory.items():
                nm = v.get("name","")
                self.log(f"  {uid} {('('+nm+')') if nm else ''}")

    def on_send(self):
        if not self.connected: return
        text = self.entry_msg.get().strip()
        if not text: return
        self.entry_msg.delete(0, "end")

        if self.chk_all_var.get():
            # client-side fanout
            sent = 0
            for rid in list(self.directory.keys()):
                if rid == self.user_id: continue
                sent += self._send_dm(rid, text)
            self.log(f"[all] sent to {sent} recipient(s)")
            return

        # else, send to selected user
        sel = self.users_list.curselection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a user on the left or check 'Send to all'")
            return
        idx = sel[0]
        rid = self.users_list.get(idx).split()[0]  # first token is UUID
        ok = self._send_dm(rid, text)
        if not ok:
            self.log("[error] couldn't send DM")

    def _send_dm(self, rid, text):
        info = self.directory.get(rid)
        if not info or not info.get("pubkey"):
            self.log(f"[error] no pubkey for {rid}")
            return 0
        ct = crypto.encrypt_for_recipient(text.encode(), info["pubkey"])
        cts = now_ms()
        obj = {
            "type":"MSG_DIRECT","from":self.user_id,"to":rid,"ts":cts,
            "payload":{"ciphertext":ct,"sender_pub":self.pub_b64,"cts":cts,
                       "content_sig": crypto.sign_content(ct, self.user_id, rid, cts, self.priv)},"sig":""
        }
        send_json(self.conn, obj)
        return 1

    def _recv_loop(self):
        # Read from websocket, push to queue for main thread
        while True:
            try:
                msg = client_recv_text(self.conn)
            except Exception as e:
                self.recv_queue.put(("error", str(e)))
                break
            if msg is None:
                self.recv_queue.put(("closed",""))
                break
            self.recv_queue.put(("message", msg))

    def _poll_recv_queue(self):
        try:
            while True:
                kind, payload = self.recv_queue.get_nowait()
                if kind == "message":
                    self._handle_incoming(payload)
                elif kind == "closed":
                    self.log("[system] disconnected")
                    self.status.configure(text="Disconnected")
                    self.connected = False
                elif kind == "error":
                    self.log(f"[error] {payload}")
        except queue.Empty:
            pass
        self.after(POLL_MS, self._poll_recv_queue)

    def _handle_incoming(self, raw):
        try:
            obj = json.loads(raw)
        except Exception:
            return
        t = obj.get("type","")
        if t == "USER_DELIVER":
            pay = obj.get("payload",{})
            ct = pay.get("ciphertext",""); sender = pay.get("sender","?")
            sender_pub_b64 = pay.get("sender_pub","")
            cts = pay.get("cts", obj.get("ts", 0))
            ok = crypto.verify_content_sig_dm(ct, sender, self.user_id, cts, pay.get("content_sig",""), sender_pub_b64) \
                 or crypto.verify_content_sig_public(ct, sender, cts, pay.get("content_sig",""), sender_pub_b64)
            try:
                pt = crypto.decrypt_for_recipient(ct, self.priv).decode(errors="ignore")
            except Exception:
                pt = "<decrypt error>"
            self.log(f"<from {sender}> [{'✓' if ok else '✗'} sig] {pt}")
        elif t == "USER_DIRECTORY":
            self._update_directory(obj.get("payload",{}))

    def _update_directory(self, payload):
        self.directory = {u["user_id"]: {"name":u.get("name",""), "pubkey":u.get("pubkey","")} for u in payload.get("users",[])}
        # Rebuild listbox
        self.users_list.delete(0, "end")
        for uid, v in self.directory.items():
            line = f"{uid}  {v.get('name','')}"
            self.users_list.insert("end", line)
        self.log("[dir] directory updated")

    def on_close(self):
        try:
            if self.conn:
                # just close the socket by closing app; ws close not implemented in minimal ws
                pass
        finally:
            self.destroy()

if __name__ == "__main__":
    app = SocpGui()
    app.mainloop()
