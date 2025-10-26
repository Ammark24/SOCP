
# Demo crypto adapter (non-compliant fallback)
import base64, hashlib, pathlib, json
def b64url(data: bytes) -> str: return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
def ensure_keys(dirpath: str, name: str):
    p = pathlib.Path(dirpath); p.mkdir(parents=True, exist_ok=True)
    class P: pass
    return P(), P()
def public_b64url(pub) -> str: return b64url(b"demo")
def encrypt_for_recipient(pt: bytes, recipient_pub_b64url: str) -> str: return b64url(pt)
def decrypt_for_recipient(ct_b64: str, priv) -> bytes:
    pad = (4 - (len(ct_b64) % 4)) % 4
    return base64.urlsafe_b64decode(ct_b64 + ("=" * pad))
def sign_content(c,f,t,ts,priv): return b64url(b"demo")
def sign_content_public(c,f,ts,priv): return b64url(b"demo")
def verify_content_sig_dm(*a, **k): return True
def verify_content_sig_public(*a, **k): return True
def transport_sign_payload(payload_obj: dict, server_priv): return b64url(b"demo")
