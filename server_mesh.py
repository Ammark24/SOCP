
import threading, socket, json, time, os, uuid, base64, queue, pathlib, hashlib, argparse
from ws import handshake_server, recv_frame, send_text, client_connect, client_send_text, client_recv_text
import config

if config.CRYPTO_BACKEND == "strict":
    import crypto_strict as crypto
else:
    import crypto_demo as crypto

servers = {}
server_addrs = {}
local_users = {}
user_locations = {}
public_members = set()
seen = set()

server_priv, server_pub = crypto.ensure_keys(config.KEYS_DIR, "server")
server_pub_b64 = crypto.public_b64url(server_pub)

def log(*a): print(time.strftime("[%H:%M:%S]"), *a, flush=True)
def b64url(b): import base64; return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
def now_ms(): return int(time.time()*1000)
def send_json_ws(conn, obj): send_text(conn, json.dumps(obj, separators=(",",":"), sort_keys=False))

def link_writer(conn, sendq):
    try:
        while True:
            obj = sendq.get()
            if obj is None: break
            send_json_ws(conn, obj)
    except Exception: pass

def connect_to_server(server_id, host, port):
    if server_id in servers: return
    try: conn = client_connect(host, port, "/")
    except Exception as e: log("connect_to_server fail", host, port, e); return
    sendq = queue.Queue()
    threading.Thread(target=link_writer, args=(conn, sendq), daemon=True).start()
    servers[server_id] = {"conn": conn, "sendq": sendq, "host": host, "port": port}
    server_addrs[server_id] = (host, port)
    announce_payload = {"host":args.host, "port":args.port, "pubkey":server_pub_b64}
    announce = {"type":"SERVER_ANNOUNCE","from":args.server_id,"to":server_id,"ts":now_ms(),
                "payload":announce_payload,"sig": crypto.transport_sign_payload(announce_payload, server_priv)}
    sendq.put(announce)

def broadcast(obj):
    for sid, link in list(servers.items()):
        try: link["sendq"].put(obj)
        except Exception: pass

def route_to_user(target_u, payload_for_user_deliver):
    if target_u in local_users:
        frame = {"type":"USER_DELIVER","from":args.server_id,"to":target_u,"ts":now_ms(),
                 "payload":payload_for_user_deliver,"sig": crypto.transport_sign_payload(payload_for_user_deliver, server_priv)}
        local_users[target_u]["sendq"].put(frame); return True
    host_server = user_locations.get(target_u)
    if host_server and host_server in servers:
        frame = {"type":"SERVER_DELIVER","from":args.server_id,"to":host_server,"ts":now_ms(),
                 "payload":payload_for_user_deliver,"sig": crypto.transport_sign_payload(payload_for_user_deliver, server_priv)}
        servers[host_server]["sendq"].put(frame); return True
    return False

def handle_user_hello(msg, conn, sendq):
    uid = msg["from"]
    if uid in local_users:
        err_payload = {"code":"NAME_IN_USE","detail":f"{uid} already online"}
        err = {"type":"ERROR","from":args.server_id,"to":uid,"ts":now_ms(),"payload":err_payload,
               "sig": crypto.transport_sign_payload(err_payload, server_priv)}
        send_json_ws(conn, err); return False
    pubkey = msg["payload"].get("pubkey","")
    local_users[uid] = {"conn":conn, "sendq":sendq, "pubkey":pubkey}
    user_locations[uid] = "local"
    public_members.add(uid)
    payload = {"user_id": uid, "server_id": args.server_id, "meta": {}}
    gossip = {"type":"USER_ADVERTISE","from":args.server_id,"to":"*","ts":now_ms(),
              "payload":payload, "sig": crypto.transport_sign_payload(payload, server_priv)}
    broadcast(gossip)
    log("HELLO", uid); return True

def handle_disconnect(uid):
    if uid in local_users: del local_users[uid]
    public_members.discard(uid)
    payload = {"user_id": uid, "server_id": args.server_id}
    rm = {"type":"USER_REMOVE","from":args.server_id,"to":"*","ts":now_ms(),
          "payload":payload,"sig": crypto.transport_sign_payload(payload, server_priv)}
    broadcast(rm)
    log("Disconnected:", uid)

def handle_msg_direct(msg):
    to = msg["to"]; payload = msg["payload"]
    key = (msg["ts"], msg["from"], to, hashlib.sha256(payload.get("ciphertext","").encode()).hexdigest()[:16])
    if not config.SKIP_DUP_SUPPRESSION:
        if key in seen: return
        if len(seen) > 8192: seen.clear()
        seen.add(key)
    delivered = route_to_user(to, {
        "ciphertext": payload["ciphertext"],
        "sender": msg["from"],
        "sender_pub": payload.get("sender_pub",""),
        "content_sig": payload.get("content_sig",""),
    })
    if not delivered:
        route_to_user(msg["from"], {"ciphertext": b64url(b"User not found"), "sender": args.server_id, "sender_pub": server_pub_b64, "content_sig":""})
        log("DM failed; user not found:", to)

def handle_msg_public(msg):
    payload = msg["payload"]
    for member in list(public_members):
        if member == msg["from"]: continue
        route_to_user(member, {"ciphertext": payload["ciphertext"],"sender": msg["from"],
                               "sender_pub": payload.get("sender_pub",""),"content_sig": payload.get("content_sig","")})
    broadcast(msg)

def handle_file(msg):
    p = msg["payload"]
    fdir = os.path.join("files", msg["to"], p["file_id"])
    os.makedirs(fdir, exist_ok=True)
    if msg["type"] == "FILE_START":
        with open(os.path.join(fdir,"manifest.json"),"w") as fp: json.dump({"name":p["name"],"size":p["size"],"sha256":p["sha256"],"mode":p["mode"]}, fp)
    elif msg["type"] == "FILE_CHUNK":
        with open(os.path.join(fdir, f"chunk_{p['index']:06d}.bin"),"wb") as fp: fp.write(p["ciphertext"].encode("utf-8"))
    elif msg["type"] == "FILE_END": pass
    route_to_user(msg["from"], {"ciphertext": b64url(b"FILE_OK"), "sender": args.server_id, "sender_pub": server_pub_b64, "content_sig":""})

def handle_server_frame(msg):
    mtype = msg.get("type",""); pay = msg.get("payload",{})
    if mtype == "SERVER_ANNOUNCE":
        sid = msg["from"]; host, port = pay["host"], pay["port"]
        server_addrs[sid] = (host, port)
        if sid not in servers and sid != args.server_id:
            connect_to_server(sid, host, port)
    elif mtype == "USER_ADVERTISE":
        u = pay["user_id"]; s = pay["server_id"]
        user_locations[u] = s
    elif mtype == "USER_REMOVE":
        u = pay["user_id"]; s = pay["server_id"]
        if user_locations.get(u) == s: del user_locations[u]
    elif mtype == "SERVER_DELIVER":
        to_user = pay.get("user_id") or msg.get("to")
        if "user_id" not in pay: pay["user_id"] = to_user
        route_to_user(pay["user_id"], {"ciphertext": pay["ciphertext"],"sender": pay.get("sender",""),
                                       "sender_pub": pay.get("sender_pub",""),"content_sig": pay.get("content_sig","")})
    elif mtype == "HEARTBEAT":
        pass
    elif mtype == "MSG_PUBLIC_CHANNEL":
        handle_msg_public(msg)

def client_writer(conn, sendq):
    try:
        while True:
            obj = sendq.get()
            if obj is None: break
            send_json_ws(conn, obj)
    except Exception: pass

def user_client_reader(conn, addr):
    sendq = queue.Queue()
    threading.Thread(target=client_writer, args=(conn, sendq), daemon=True).start()
    user_id = None
    try:
        while True:
            opcode, payload = recv_frame(conn)
            if opcode is None or opcode == 0x8: break
            if opcode != 0x1: continue
            try: msg = json.loads(payload.decode("utf-8"))
            except: continue
            t = msg.get("type","")
            if t == "USER_HELLO":
                user_id = msg["from"]
                if not handle_user_hello(msg, conn, sendq): break
            elif t == "MSG_DIRECT":
                handle_msg_direct(msg)
            elif t == "MSG_PUBLIC_CHANNEL":
                handle_msg_public(msg)
            elif t in ("FILE_START","FILE_CHUNK","FILE_END"):
                handle_file(msg)
    finally:
        if user_id: handle_disconnect(user_id)
        try: sendq.put(None)
        except: pass
        try: conn.close()
        except: pass

def server_peer_reader(conn):
    sendq = queue.Queue()
    threading.Thread(target=link_writer, args=(conn, sendq), daemon=True).start()
    try:
        while True:
            opcode, payload = recv_frame(conn)
            if opcode is None or opcode == 0x8: break
            if opcode != 0x1: continue
            try: msg = json.loads(payload.decode("utf-8"))
            except: continue
            handle_server_frame(msg)
    finally:
        try: sendq.put(None)
        except: pass
        try: conn.close()
        except: pass

def bootstrap_from_introducer(path):
    try:
        data = json.load(open(path,"r"))
    except Exception as e:
        log("bootstrap read error", e); return
    for entry in data.get("bootstrap_servers", []):
        h, p, pinned = entry.get("host"), entry.get("port"), entry.get("pubkey","")
        try: conn = client_connect(h, p, "/")
        except Exception as e: log("introducer connect fail", h, p, e); continue
        payload = {"host": args.host, "port": args.port, "pubkey": server_pub_b64}
        join = {"type":"SERVER_HELLO_JOIN","from":args.server_id,"to":f"{h}:{p}","ts":now_ms(),
                "payload":payload,"sig":""}
        client_send_text(conn, json.dumps(join, separators=(",",":")))
        resp = client_recv_text(conn)
        try: obj = json.loads(resp)
        except Exception: conn.close(); continue
        if obj.get("type") != "SERVER_WELCOME": conn.close(); continue
        assigned_id = obj["payload"].get("assigned_id", args.server_id)
        if assigned_id != args.server_id:
            log(f"Assigned id: {assigned_id}"); args.server_id = assigned_id
        sendq = queue.Queue()
        threading.Thread(target=link_writer, args=(conn, sendq), daemon=True).start()
        sid = f"{h}:{p}"
        servers[sid] = {"conn": conn, "sendq": sendq, "host": h, "port": p}
        server_addrs[sid] = (h, p)
        annp = {"host": args.host, "port": args.port, "pubkey": server_pub_b64}
        announce = {"type":"SERVER_ANNOUNCE","from":args.server_id,"to":"*","ts":now_ms(),
                    "payload":annp,"sig": crypto.transport_sign_payload(annp, server_priv)}
        broadcast(announce)
        break

def heartbeat_loop():
    while True:
        time.sleep(config.HEARTBEAT_INTERVAL)
        hb = {"type":"HEARTBEAT","from":args.server_id,"to":"*","ts":now_ms(),"payload":{},
              "sig": crypto.transport_sign_payload({}, server_priv)}
        broadcast(hb)

def serve(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port)); s.listen(200)
    log(f"SOCP node {args.server_id} listening ws://{host}:{port}")
    while True:
        conn, addr = s.accept()
        try: handshake_server(conn)
        except Exception: conn.close(); continue
        opcode, payload = recv_frame(conn)
        if opcode is None or opcode != 0x1: conn.close(); continue
        try: first = json.loads(payload.decode("utf-8"))
        except Exception: conn.close(); continue
        if args.introducer and first.get("type") == "SERVER_HELLO_JOIN":
            new_id = first["from"]; pay = first["payload"]
            host2, port2, pubkey2 = pay.get("host"), pay.get("port"), pay.get("pubkey")
            assigned_id = new_id; i = 1
            while assigned_id in server_addrs or assigned_id == args.server_id:
                assigned_id = f\"{new_id}_{i}\"; i += 1
            server_addrs[assigned_id] = (host2, port2)
            welcome_payload = {"assigned_id": assigned_id, "clients": []}
            frame = {"type":"SERVER_WELCOME","from":args.server_id,"to":assigned_id,"ts":now_ms(),
                     "payload": welcome_payload, "sig": crypto.transport_sign_payload(welcome_payload, server_priv)}
            send_json_ws(conn, frame)
            connect_to_server(assigned_id, host2, port2)
            announce_payload = {"host": host2, "port": port2, "pubkey": pubkey2}
            announce = {"type":"SERVER_ANNOUNCE","from":assigned_id,"to":"*","ts":now_ms(),
                        "payload":announce_payload,"sig": crypto.transport_sign_payload(announce_payload, server_priv)}
            broadcast(announce)
            threading.Thread(target=server_peer_reader, args=(conn,), daemon=True).start()
            continue
        t = first.get("type","")
        if t == "USER_HELLO":
            sendq = queue.Queue()
            threading.Thread(target=client_writer, args=(conn, sendq), daemon=True).start()
            if not handle_user_hello(first, conn, sendq): 
                try: conn.close()
                except: pass
            else:
                user_client_reader(conn, None)
        else:
            sendq = queue.Queue()
            threading.Thread(target=link_writer, args=(conn, sendq), daemon=True).start()
            handle_server_frame(first)
            threading.Thread(target=server_peer_reader, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    import threading
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-id", default="server_1")
    ap.add_argument("--host", default=config.SERVER_HOST)
    ap.add_argument("--port", type=int, default=config.SERVER_PORT)
    ap.add_argument("--introducer", action="store_true")
    ap.add_argument("--bootstrap", default="bootstrap.json")
    args = ap.parse_args()
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    if not args.introducer and os.path.exists(args.bootstrap):
        bootstrap_from_introducer(args.bootstrap)
    serve(args.host, args.port)
