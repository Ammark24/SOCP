
import threading, socket, json, time, os, uuid, base64, queue, hashlib
from ws import handshake_server, recv_frame, send_text
import config

if config.CRYPTO_BACKEND == "strict":
    import crypto_strict as crypto
else:
    import crypto_demo as crypto

local_users = {}       # user_id -> {"conn","sendq","pubkey","name"}
name_index = {}        # lower(name) -> user_id
seen = set()
directory_version = 0

def log(*a): print(time.strftime("[%H:%M:%S]"), *a, flush=True)
def b64url(b): import base64; return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
def now_ms(): return int(time.time()*1000)
def send_json(conn, obj): send_text(conn, json.dumps(obj, separators=(",",":")))

def snapshot_directory():
    return {"version": directory_version,
            "users":[{"user_id": uid, "name": info.get("name",""), "pubkey": info.get("pubkey","")} for uid,info in local_users.items()]}

def broadcast_directory():
    snap = snapshot_directory()
    frame = {"type":"USER_DIRECTORY","from":"server_1","to":"*","ts":now_ms(),"payload":snap,"sig": b64url(b"sd")}
    for uid, info in local_users.items():
        info["sendq"].put(frame)

def set_name(uid, new_name):
    global directory_version
    old = local_users[uid].get("name","")
    if old: name_index.pop(old.lower(), None)
    local_users[uid]["name"] = new_name
    if new_name: name_index[new_name.lower()] = uid
    directory_version += 1
    broadcast_directory()

def handle_user_hello(msg, conn, sendq):
    global directory_version
    uid = msg["from"]
    if uid in local_users:
        err = {"type":"ERROR","from":"server_1","to":uid,"ts":now_ms(),
               "payload":{"code":"NAME_IN_USE","detail":f"{uid} already online"},"sig":b64url(b"sig")}
        send_json(conn, err); return False
    payload = msg.get("payload",{})
    pubkey = payload.get("pubkey","")
    name = payload.get("name","")
    local_users[uid] = {"conn":conn, "sendq":sendq, "pubkey":pubkey, "name":name}
    if name: name_index[name.lower()] = uid
    directory_version += 1
    sendq.put({"type":"USER_DIRECTORY","from":"server_1","to":uid,"ts":now_ms(),
               "payload": snapshot_directory(),"sig": b64url(b"sd")})
    broadcast_directory()
    log("HELLO from", uid, name); return True

def handle_set_name(msg):
    uid = msg["from"]
    if uid not in local_users: return
    set_name(uid, msg["payload"].get("name",""))

def resolve_target(token):
    try:
        uuid.UUID(token); return token
    except: pass
    return name_index.get(token.lower())

def route_user_deliver(recipient_id, payload):
    frame = {"type":"USER_DELIVER","from":"server_1","to":recipient_id,"ts":now_ms(),
             "payload": payload,"sig": b64url(b"server_sig_demo")}
    link = local_users.get(recipient_id)
    if link: link["sendq"].put(frame); return bool(link)
    return False

def handle_msg_direct(msg):
    to_token = msg["to"]
    rid = to_token if to_token in local_users else resolve_target(to_token)
    if not rid:
        route_user_deliver(msg["from"], {"ciphertext": b64url(b"User not found"), "sender":"server","sender_pub":"", "content_sig":""})
        return
    payload = msg["payload"]
    key = (msg["ts"], msg["from"], rid, payload.get("ciphertext","")[:16])
    if key in seen and not config.SKIP_DUP_SUPPRESSION: return
    seen.add(key); 
    if len(seen) > 4096: seen.clear()
    delivered = route_user_deliver(rid, {
        "ciphertext": payload["ciphertext"],
        "sender": msg["from"],
        "sender_pub": payload.get("sender_pub",""),
        "cts": payload.get("cts", msg["ts"]),
        "content_sig": payload.get("content_sig",""),
    })
    if not delivered:
        route_user_deliver(msg["from"], {"ciphertext": b64url(b"User offline"), "sender":"server","sender_pub":"", "content_sig":""})
        log("DM failed; user not found:", rid)

def handle_msg_public(msg):
    payload = msg["payload"]
    for member in list(local_users.keys()):
        if member == msg["from"]: continue
        route_user_deliver(member, {"ciphertext": payload["ciphertext"],"sender": msg["from"],
                                    "sender_pub": payload.get("sender_pub",""),"cts": payload.get("cts", msg["ts"]),
                                    "content_sig": payload.get("content_sig","")})

def client_writer(conn, sendq):
    try:
        while True:
            obj = sendq.get()
            if obj is None: break
            send_json(conn, obj)
    except Exception: pass

def client_reader(conn, addr):
    sendq = queue.Queue()
    threading.Thread(target=client_writer, args=(conn, sendq), daemon=True).start()

    user_id = None
    try:
        while True:
            opcode, payload = recv_frame(conn)
            if opcode is None or opcode == 0x8: break
            if opcode != 0x1: continue
            try: msg = json.loads(payload.decode("utf-8"))
            except Exception: continue
            t = msg.get("type","")
            if t == "USER_HELLO":
                user_id = msg["from"]
                if not handle_user_hello(msg, conn, sendq): break
            elif t == "SET_NAME":
                handle_set_name(msg)
            elif t == "MSG_DIRECT":
                handle_msg_direct(msg)
            elif t == "MSG_PUBLIC_CHANNEL":
                handle_msg_public(msg)
    finally:
        if user_id and user_id in local_users:
            old = local_users[user_id].get("name","")
            if old: name_index.pop(old.lower(), None)
            del local_users[user_id]
            global directory_version
            directory_version += 1
            broadcast_directory()
            log("Disconnected:", user_id)
        try: sendq.put(None)
        except: pass
        try: conn.close()
        except: pass

def serve(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port)); s.listen(100)
    log(f"SOCP server listening on ws://{host}:{port}")
    while True:
        conn, addr = s.accept()
        try: handshake_server(conn)
        except Exception:
            conn.close(); continue
        threading.Thread(target=client_reader, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    serve(config.SERVER_HOST, config.SERVER_PORT)
