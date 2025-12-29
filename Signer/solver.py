#!/usr/bin/env python3

import os, sys, time, json, base64, hashlib, secrets
from typing import List, Tuple, Dict, Any
from pwn import remote
from coincurve import PublicKey
from functions import untemper, invertStep, recover_Kj_from_Ii

SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def xonly(pub: PublicKey) -> bytes:
    return pub.format(compressed=False)[1:33]

def recv_line_r(r: remote) -> str:
    data = r.recvline(timeout=10)
    if not data:
        sys.exit(1)
    return data.decode(errors="ignore").rstrip("\r\n")

def send_cmd_r(r: remote, cmd: str) -> Dict[str, Any]:
    r.sendline(cmd)
    return json.loads(recv_line_r(r))

def parse_token(tok: str) -> Tuple[bytes, bytes, int]:
    head_b64, pay_b64, sig_hex = tok.split(".")
    msg = sha256((head_b64 + "." + pay_b64).encode())
    sig = bytes.fromhex(sig_hex)
    rx = sig[:32]
    s = int.from_bytes(sig[32:], "big") % SECP_N
    return msg, rx, s

def collect_rolls_r(r: remote, batches: int) -> List[int]:
    out = []
    for _ in range(batches):
        res = send_cmd_r(r, "ROLL " + " ".join("0" for _ in range(10)))
        if not res.get("ok"):
            sys.exit(1)
        out.extend(int(x) & 0xFFFFFFFF for x in res["nums"])
    return out

def recover_seed_from_mt(outputs: List[int]) -> bytes:
    S = [untemper(x) for x in outputs[:624]]
    I_230_, I_231 = invertStep(S[3], S[230])
    I_231_, I_232 = invertStep(S[4], S[231])
    I_232_, I_233 = invertStep(S[5], S[232])
    I_233_, I_234 = invertStep(S[6], S[233])
    I_231 += I_231_; I_232 += I_232_; I_233 += I_233_
    seed_l = recover_Kj_from_Ii(I_233, I_232, I_231, 233) - 16
    seed_h1 = recover_Kj_from_Ii(I_234, I_233, I_232, 234) - 17
    seed_h2 = recover_Kj_from_Ii((I_234 + 0x80000000) & 0xFFFFFFFF, I_233, I_232, 234) - 17
    c1 = ((seed_h1 & 0xFFFFFFFF) << 32) | (seed_l & 0xFFFFFFFF)
    c2 = ((seed_h2 & 0xFFFFFFFF) << 32) | (seed_l & 0xFFFFFFFF)
    mask56 = (1 << 56) - 1
    b1 = (c1 & mask56).to_bytes(7, "big")
    b2 = (c2 & mask56).to_bytes(7, "big")
    alpha = set(b"abcdefghijklmnopqrstuvwxyz0123456789")
    if all(ch in alpha for ch in b1):
        return b1
    if all(ch in alpha for ch in b2):
        return b2
    return b1

def compute_e(rx: bytes, X_pub: PublicKey, m: bytes, seed: bytes) -> int:
    h = sha256(b"BIP0340/challenge" + rx + xonly(X_pub) + m + seed)
    return int.from_bytes(h, "big") % SECP_N

def sign_bip340_msg(m: bytes, k_raw: int, x_secret: int, X_pub: PublicKey, seed: bytes) -> bytes:
    k = (k_raw % SECP_N) or 1
    R = PublicKey.from_valid_secret(k.to_bytes(32, "big"))
    un = R.format(compressed=False)
    if un[-1] & 1:
        k = (SECP_N - k) % SECP_N
        R = PublicKey.from_valid_secret(k.to_bytes(32, "big"))
        un = R.format(compressed=False)
    rx = un[1:33]
    e = compute_e(rx, X_pub, m, seed)
    s = (k + (e * (x_secret % SECP_N)) % SECP_N) % SECP_N
    return rx + s.to_bytes(32, "big")

def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "55338"))
    r = remote(host, port, timeout=10)

    recv_line_r(r)

    pub = send_cmd_r(r, "PUBKEY")
    X = PublicKey(bytes.fromhex(pub["X_compressed"]))

    user = "u" + str(secrets.randbelow(10**6))
    pwd = "p" + str(secrets.randbelow(10**6))
    send_cmd_r(r, f"REGISTER {user} {pwd}")
    resp = send_cmd_r(r, f"LOGIN {user} {pwd}")
    tok1 = resp["token"]

    rolls = collect_rolls_r(r, 63)
    seed = recover_seed_from_mt(rolls)

    m1, rx1, s1 = parse_token(tok1)

    tok2 = None
    deadline = time.time() + 2.0
    while time.time() < deadline:
        resp = send_cmd_r(r, f"LOGIN {user} {pwd}")
        m2, rx2, s2 = parse_token(resp["token"])
        if rx2 == rx1 and s2 != s1:
            tok2 = resp["token"]
            break

    if tok2 is None:
        resp = send_cmd_r(r, f"LOGIN {user} {pwd}")
        m1, rx1, s1 = parse_token(resp["token"])
        while True:
            resp = send_cmd_r(r, f"LOGIN {user} {pwd}")
            m2, rx2, s2 = parse_token(resp["token"])
            if rx2 == rx1 and s2 != s1:
                tok2 = resp["token"]
                break

    e1 = compute_e(rx1, X, m1, seed)
    e2 = compute_e(rx1, X, m2, seed)
    x = ((s1 - s2) % SECP_N) * pow((e1 - e2) % SECP_N, -1, SECP_N) % SECP_N

    hdr = {"alg": "BIP340", "typ": "JWT"}
    now = int(time.time())
    payload = {"sub": user, "role": "admin", "iat": now, "exp": now + 15*60, "jti": secrets.token_hex(16)}
    head_b64 = base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=")
    pay_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=")
    body = head_b64 + b"." + pay_b64
    sig = sign_bip340_msg(sha256(body), secrets.randbelow(SECP_N - 1) or 1, x, X, seed)
    forged = body.decode() + "." + sig.hex()

    resp = send_cmd_r(r, f"MYNOTES {forged}")
    for it in resp.get("notes", []):
        if it.get("title") == "FLAG":
            print(it.get("body"))
            r.close()
            return

    r.close()

if __name__ == "__main__":
    main()
