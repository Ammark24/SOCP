
# Strict RSA-4096 OAEP/PSS adapter (PyCA cryptography)
import os, json, base64, hashlib, pathlib
from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def ub64url(s: str) -> bytes:
    pad = (4 - (len(s) % 4)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))

def sha256(data: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256())
    d.update(data)
    return d.finalize()

def ensure_keys(dirpath: str, name: str):
    p = pathlib.Path(dirpath); p.mkdir(parents=True, exist_ok=True)
    priv_pem = p / f"{name}_priv.pem"
    pub_pem = p / f"{name}_pub.pem"
    der_b64 = p / f"{name}_pub.der.b64url"
    if not priv_pem.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        priv_pem.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub_der = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_pem.write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        der_b64.write_text(b64url(pub_der))
    priv = serialization.load_pem_private_key(priv_pem.read_bytes(), password=None, backend=default_backend())
    pub = serialization.load_pem_public_key(pub_pem.read_bytes(), backend=default_backend())
    return priv, pub

def public_b64url(pub) -> str:
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return b64url(der)

def encrypt_for_recipient(plaintext: bytes, recipient_pub_b64url: str) -> str:
    pub = serialization.load_der_public_key(ub64url(recipient_pub_b64url), backend=default_backend())
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return b64url(ct)

def decrypt_for_recipient(ciphertext_b64url: str, recipient_priv) -> bytes:
    ct = ub64url(ciphertext_b64url)
    return recipient_priv.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def sign_content(ciphertext_b64url: str, frm: str, to: str, ts: int, priv) -> str:
    m = hashlib.sha256((ciphertext_b64url + frm + to + str(ts)).encode()).digest()
    sig = priv.sign(
        m,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return b64url(sig)

def sign_content_public(ciphertext_b64url: str, frm: str, ts: int, priv) -> str:
    m = hashlib.sha256((ciphertext_b64url + frm + str(ts)).encode()).digest()
    sig = priv.sign(
        m,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return b64url(sig)

def verify_content_sig_dm(ciphertext_b64url: str, frm: str, to: str, ts: int, sig_b64: str, sender_pub_b64: str) -> bool:
    pub = serialization.load_der_public_key(ub64url(sender_pub_b64), backend=default_backend())
    m = hashlib.sha256((ciphertext_b64url + frm + to + str(ts)).encode()).digest()
    try:
        pub.verify(
            ub64url(sig_b64),
            m,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def verify_content_sig_public(ciphertext_b64url: str, frm: str, ts: int, sig_b64: str, sender_pub_b64: str) -> bool:
    pub = serialization.load_der_public_key(ub64url(sender_pub_b64), backend=default_backend())
    m = hashlib.sha256((ciphertext_b64url + frm + str(ts)).encode()).digest()
    try:
        pub.verify(
            ub64url(sig_b64),
            m,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def transport_sign_payload(payload_obj: dict, server_priv) -> str:
    data = json.dumps(payload_obj, separators=(",",":"), sort_keys=True).encode("utf-8")
    dig = hashlib.sha256(data).digest()
    sig = server_priv.sign(
        dig,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return b64url(sig)
