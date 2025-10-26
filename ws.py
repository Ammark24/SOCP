
import base64, hashlib, struct, socket

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def _sha1(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha1(data).digest()

def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")

def handshake_server(conn):
    req = b""
    while b"\r\n\r\n" not in req:
        chunk = conn.recv(1024)
        if not chunk: break
        req += chunk
    headers = {}
    for line in req.decode("latin1").split("\r\n")[1:]:
        if not line: break
        if ":" in line:
            k,v = line.split(":",1)
            headers[k.strip().lower()] = v.strip()
    key = headers.get("sec-websocket-key","")
    accept = _b64(_sha1((key + WS_MAGIC).encode("ascii")))
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    ).encode("ascii")
    conn.sendall(resp)

def send_text(conn, text: str):
    data = text.encode("utf-8")
    header = bytearray([0x81])
    n = len(data)
    if n < 126:
        header.append(n)
    elif n < (1<<16):
        header += bytes([126]) + struct.pack("!H", n)
    else:
        header += bytes([127]) + struct.pack("!Q", n)
    conn.sendall(header + data)

def recv_frame(conn):
    b1 = conn.recv(1)
    if not b1: return None, None
    b1 = b1[0]
    opcode = b1 & 0x0F
    b2 = conn.recv(1)[0]
    mask = (b2 >> 7) & 1
    length = (b2 & 0x7F)
    if length == 126:
        length = struct.unpack("!H", conn.recv(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", conn.recv(8))[0]
    mask_key = b""
    if mask:
        mask_key = conn.recv(4)
    payload = b""
    while len(payload) < length:
        chunk = conn.recv(length - len(payload))
        if not chunk: break
        payload += chunk
    if mask:
        payload = bytes(b ^ mask_key[i % 4] for i,b in enumerate(payload))
    return opcode, payload

def client_connect(host, port, path="/"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    key = base64.b64encode(b"clientkey").decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    s.sendall(req)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(1024)
        if not chunk: break
        resp += chunk
    return s

def client_send_text(conn, text: str):
    data = text.encode("utf-8")
    header = bytearray([0x81])
    n = len(data)
    mask_key = b"MASK"
    if n < 126:
        header.append(0x80 | n)
    elif n < (1<<16):
        header += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack("!Q", n)
    masked = bytes(b ^ mask_key[i % 4] for i,b in enumerate(data))
    conn.sendall(header + mask_key + masked)

def client_recv_text(conn):
    opcode, payload = recv_frame(conn)
    if opcode == 0x1:
        return payload.decode("utf-8")
    elif opcode == 0x8:
        return None
    else:
        return ""
