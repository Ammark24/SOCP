
import argparse, json, time, uuid, os, base64, sys, pathlib
from ws import client_connect, client_send_text, client_recv_text
import config

if config.CRYPTO_BACKEND == "strict":
    import crypto_strict as crypto
else:
    import crypto_demo as crypto

def now_ms(): return int(time.time()*1000)
def send_json(conn, obj): client_send_text(conn, json.dumps(obj, separators=(",",":")))

directory = {}      # user_id -> {"name","pubkey"}
name_index = {}     # lower(name) -> user_id

def update_directory(payload):
    global directory, name_index
    directory = {u["user_id"]: {"name":u.get("name",""), "pubkey":u.get("pubkey","")} for u in payload.get("users",[])}
    name_index = { (v["name"] or "").lower(): k for k,v in directory.items() if v.get("name") }
    print("\n[dir] known users:")
    for uid, v in directory.items():
        nm = v.get("name","")
        print(f"  {uid}  {('('+nm+')') if nm else ''}")
    sys.stdout.write("> "); sys.stdout.flush()

def resolve_target(token):
    try:
        uuid.UUID(token); return token
    except: pass
    return name_index.get(token.lower())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True, help="Preferred display name (UUID is derived for ID)")
    args = ap.parse_args()

    try: uuid.UUID(args.user); user_id = args.user
    except: user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, args.user))

    priv, pub = crypto.ensure_keys(config.KEYS_DIR, f"user_{user_id}")
    pub_b64 = crypto.public_b64url(pub)

    host = os.environ.get("SOCP_HOST", config.SERVER_HOST)
    port = int(os.environ.get("SOCP_PORT", config.SERVER_PORT))
    conn = client_connect(host, port, "/")

    hello = {"type":"USER_HELLO","from":user_id,"to":"server_1","ts":now_ms(),
             "payload":{"client":"cli-v2.1","pubkey":pub_b64,"enc_pubkey":pub_b64,"name":args.user},"sig":""}
    send_json(conn, hello)
    print(f"Connected as {user_id} to ws://{host}:{port}")

    import threading
    def reader():
        while True:
            msg = client_recv_text(conn)
            if msg is None:
                print("Disconnected."); break
            if not msg: continue
            try: obj = json.loads(msg)
            except: continue
            if obj.get("type") == "USER_DELIVER":
                pay = obj.get("payload",{})
                ct = pay.get("ciphertext",""); sender = pay.get("sender","?")
                sender_pub_b64 = pay.get("sender_pub","")
                cts = pay.get("cts", obj.get("ts", 0))
                ok = crypto.verify_content_sig_dm(ct, sender, user_id, cts, pay.get("content_sig",""), sender_pub_b64) \
                     or crypto.verify_content_sig_public(ct, sender, cts, pay.get("content_sig",""), sender_pub_b64)
                try:
                    pt = crypto.decrypt_for_recipient(ct, priv).decode(errors="ignore")
                except Exception:
                    pt = "<decrypt error>"
                print(f"\n<from {sender}> [{'✓' if ok else '✗'} sig] {pt}")
            elif obj.get("type") == "USER_DIRECTORY":
                update_directory(obj.get("payload",{}))
            sys.stdout.write("> "); sys.stdout.flush()
    threading.Thread(target=reader, daemon=True).start()

    def cmd_list():
        if not directory:
            print("No users yet. You'll receive a directory snapshot when someone joins.")
        else:
            print("Online users:")
            for uid, v in directory.items():
                print(f"{uid}  {v.get('name','')}")

    def cmd_name(new_name):
        send_json(conn, {"type":"SET_NAME","from":user_id,"to":"server_1","ts":now_ms(),
                         "payload":{"name":new_name},"sig":""})
        print("Requested name change to", new_name)

    def send_dm(rid, text):
        info = directory.get(rid)
        if not info or not info.get("pubkey"):
            print("No pubkey for", rid); return
        ct = crypto.encrypt_for_recipient(text.encode(), info["pubkey"])
        cts = now_ms()
        obj = {"type":"MSG_DIRECT","from":user_id,"to":rid,"ts":cts,
               "payload":{"ciphertext":ct,"sender_pub":pub_b64,"cts":cts,
                          "content_sig": crypto.sign_content(ct, user_id, rid, cts, priv)},"sig":""}
        send_json(conn, obj)

    def cmd_tell(target_token, text):
        rid = resolve_target(target_token)
        if not rid: print("Unknown user:", target_token); return
        send_dm(rid, text)

    def cmd_all(text):
        # Client-side E2EE fanout
        count = 0
        for rid in list(directory.keys()):
            if rid == user_id: continue
            send_dm(rid, text); count += 1
        print(f"[all] sent to {count} recipient(s)")

    while True:
        try: line = input("> ").strip()
        except EOFError: break
        if not line: continue
        if line == "/list":
            cmd_list()
        elif line.startswith("/name "):
            cmd_name(line.split(" ",1)[1])
        elif line.startswith("/tell "):
            parts = line.split(" ", 2)
            if len(parts) < 3: print("Usage: /tell <name|uuid> <text>"); continue
            cmd_tell(parts[1], parts[2])
        elif line.startswith("/all "):
            cmd_all(line.split(" ",1)[1])
        elif line in ("/help","/h"):
            print("Commands: /list, /name <newname>, /tell <name|uuid> <text>, /all <text>, /quit")
        elif line in ("/quit","/exit"):
            break
        else:
            print("Commands: /list, /name <newname>, /tell <name|uuid> <text>, /all <text>, /quit")

if __name__ == "__main__":
    main()
