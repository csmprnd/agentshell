#!/usr/bin/env python3
# =================================================================
# ЕО-42 · ЕКСПЕРИМЕНТАЛЕН ОБРАЗЕЦ №42
# -----------------------------------------------------------------
# КБ ИСОМ — Конструкторско Бюро за Изчислителни
#           Системи за Обработка на Матрици
#
# ДАТА:     28 Октомври 2026 г.
# АВТОР:    Виктор Желев
# ПРОЕКТ:   https://github.com/csmprnd
# UL-ID:    EO-42
#
# ЛИЦЕНЗ:   UL-1.0
# =================================================================
# agentshell.py — клиент за протокол REV.4 (AEAD, двупосочна свежест):
#   пакет = [L u32 BE][ct L B][tag 16B]; таг = Poly1305(kpoly,
#   dir ‖ p u64LE ‖ L u32BE ‖ 0³ ‖ ct); verify ПРЕДИ decrypt.
#   KDF: KS0 = ChaCha20(PSK, seed_s2c ⊕ seed_c2s) — свежестта е
#   ДВУПОСОЧНА: replay на стар „филм" S→C към клиента умира (§13.2);
#   S→C шифър = PSK. Хендшейкът (64+64 B salt) е непроменен.
#   REV.4 = REV.3 (AEAD + @get) с KDF nonce от двата seed-а — 0 нови байта.
#
# usage: agentshell.py <host> <port> <hexkey64> [--yn] | --selftest
# =================================================================
import os, socket, struct, sys

BASE_C = bytes.fromhex("FF81FFFF3E420818")
BASE_S = bytes.fromhex("007E0000C1BDF7E7")
PKT_MAX = 1024
VEC = bytes.fromhex(
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
POLY_K = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
POLY_M = b"Cryptographic Forum Research Group"
POLY_T = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")  # RFC 8439 §2.5.2

class ProtocolError(Exception):
    pass

def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
def qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff; x[d] ^= x[a]; x[d] = rotl(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff; x[b] ^= x[c]; x[b] = rotl(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff; x[d] ^= x[a]; x[d] = rotl(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff; x[b] ^= x[c]; x[b] = rotl(x[b], 7)
def chacha_xor(key, nonce8, blk64):
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    st += list(struct.unpack("<8I", key)) + [0, 0] + list(struct.unpack("<2I", nonce8))
    w = st[:]
    for _ in range(10):
        qr(w,0,4,8,12); qr(w,1,5,9,13); qr(w,2,6,10,14); qr(w,3,7,11,15)
        qr(w,0,5,10,15); qr(w,1,6,11,12); qr(w,2,7,8,13); qr(w,3,4,9,14)
    ks = struct.pack("<16I", *[(a + b) & 0xffffffff for a, b in zip(w, st)])
    return bytes(a ^ b for a, b in zip(blk64, ks))

_P = (1 << 130) - 5
def poly1305(key, msg):
    """RFC 8439 Poly1305 (чист Python, Horner; ~32 MB/s — за тагове по 1 KB е без значение)"""
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        c = msg[i:i + 16]
        n = int.from_bytes(c, "little") + (1 << (8 * len(c)))
        acc = ((acc + n) * r) % _P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")

class AgentShell:
    def __init__(self, host, port, hexkey):
        self.key = bytes.fromhex(hexkey)
        self.s = socket.create_connection((host, int(port)))
        self.p_tx = 0; self.p_rx = 0; self.last_exit = None
        self.frames = 0  # получени пакети този сеанс (диагностика)
    def _exact(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c: raise ConnectionError("connection closed")
            b += c
        return b
    def connect(self):
        salt = chacha_xor(self.key, BASE_C, os.urandom(64))
        self.seed_tx = salt[56:64]; self.s.sendall(salt)
        self.seed_rx = self._exact(64)[56:64]
        # REV.4 KDF: KS0 = ChaCha20(PSK, seed_s2c ⊕ seed_c2s) → enc_key + kpoly
        # (seed_rx = seed_s2c, seed_tx = seed_c2s; свежестта е двупосочна —
        #  replay на стар S→C „филм" срещу свеж seed_c2s дава фалшив таг)
        nonce = bytes(a ^ b for a, b in zip(self.seed_rx, self.seed_tx))
        ks0 = chacha_xor(self.key, nonce, bytes(64))
        self.enc_key = ks0[:32]         # C→S сесиен ключ (свежест!)
        self.kpoly = ks0[32:64]         # Poly1305 ключ
    def _n(self, seed, p):
        return ((int.from_bytes(seed, "little") + p) & 0xffffffffffffffff).to_bytes(8, "little")
    def _tag(self, direction, p, L, ct):
        hdr = direction + struct.pack("<Q", p) + struct.pack(">I", L) + b"\0\0\0"
        return poly1305(self.kpoly, hdr + ct)
    def _encrypt(self, pt):
        out = b""
        for j in range(len(pt) // 64):
            if j % 16 == 0:
                nonce = self._n(self.seed_tx, self.p_tx); self.p_tx += 1
            else:
                nonce = out[-8:]
            out += chacha_xor(self.enc_key, nonce, pt[j*64:(j+1)*64])
        return out
    def send_msg(self, data):
        pt = struct.pack(">I", len(data)) + data
        pt += b"\0" * (-len(pt) % 64)
        p_start = self.p_tx
        ct = self._encrypt(pt)
        for k in range((len(ct) + PKT_MAX - 1) // PKT_MAX):
            sl = ct[k*PKT_MAX:(k+1)*PKT_MAX]
            L = len(sl)
            tag = self._tag(b"C", p_start + k, L, sl)
            self.s.sendall(struct.pack(">I", L) + sl + tag)
    def _recv_pkt(self):
        L = struct.unpack(">I", self._exact(4))[0]
        if not (64 <= L <= PKT_MAX) or L % 64:
            raise ProtocolError(f"невалиден пакет L={L}")
        ct = self._exact(L)
        tag = self._exact(16)
        if self._tag(b"S", self.p_rx, L, ct) != tag:
            raise ProtocolError("фалшив таг (S→C)")
        return ct
    def recv_msg(self):
        ct = self._recv_pkt(); self.frames += 1
        pt = b""; prev = None; got = 0; ln = 0; total_blk = 1
        while True:
            for jj in range(len(ct) // 64):
                j = got
                if j % 16 == 0:
                    nonce = self._n(self.seed_rx, self.p_rx); self.p_rx += 1
                else:
                    nonce = prev[56:64]
                prev = ct[jj*64:(jj+1)*64]
                pt += chacha_xor(self.key, nonce, prev)
                if j == 0:
                    ln = struct.unpack(">I", pt[:4])[0]
                    total_blk = 1 if ln == 0 else -(-(ln + 4) // 64)
                got += 1
            if got >= total_blk:
                break
            ct = self._recv_pkt()
        return ln, (pt[4:8] if ln == 0 else pt[4:4+ln])

    def run(self, cmd):
        self.send_msg(cmd.encode())
        while True:
            ln, data = self.recv_msg()
            if ln == 0:
                self.last_exit = struct.unpack(">I", data[:4])[0]; return
            yield data

    def upload(self, path, data):
        """@put (REV.3): [00][path_len BE16][path][size BE64][data]"""
        p = path.encode() if isinstance(path, str) else path
        d = data if isinstance(data, (bytes, bytearray)) else data.encode()
        if not 1 <= len(p) <= 4096:
            raise ValueError("пътят трябва да е 1..4096 байта")
        payload = b"\x00" + len(p).to_bytes(2, "big") + p + len(d).to_bytes(8, "big") + d
        self.send_msg(payload)
        text = b""
        while True:
            ln, chunk = self.recv_msg()
            if ln == 0:
                return struct.unpack(">I", chunk[:4])[0], text.decode("utf-8", "replace")
            text += chunk

    def download(self, rpath, local):
        """@get (Вълна 3): [01][path_len BE16][път] → DATA chunkове + END.
        END 0 = ОК; 126 = отказан от оператора (--yn); друго = грешка.
        Частичен файл при неуспех се трие (без половинати изтегляния)."""
        p = rpath.encode() if isinstance(rpath, str) else rpath
        if not 1 <= len(p) <= 4096:
            raise ValueError("пътят трябва да е 1..4096 байта")
        self.send_msg(b"\x01" + len(p).to_bytes(2, "big") + p)
        total = 0
        ok = False
        try:
            with open(local, "wb") as f:
                while True:
                    ln, chunk = self.recv_msg()
                    if ln == 0:
                        st = struct.unpack(">I", chunk[:4])[0]
                        if st == 0:
                            ok = True
                        return st, total
                    f.write(chunk)
                    total += len(chunk)
        finally:
            if not ok:
                try:
                    os.unlink(local)          # половинати файлове не остават
                except OSError:
                    pass

USAGE = """\
ЕО-42 · agentshell клиент (протокол REV.4 — AEAD, двупосочна свежест)
употреба:
  agentshell.py <host> <port> <hex_key_64> [--yn] | --selftest | --help

  чете команди от stdin, по една на ред, и стрийма отговора

флагове:
  --yn        преди всяка команда пита на конзолата (y/yes/д/да → изпрати)
  --selftest  ChaCha20 + Poly1305 векторни тестове
  --help      този текст

синтаксис на команда (без shell, без quoting):
  ENV1=val ENV2=val CWD=/path /bin/program arg1 arg2

специални редове:
  @put <локален_файл> <дистанционен_път>   качва файла
  @get <дистанционен_път> [локален_файл]   сваля файла (редовни файлове,
                                           ≤1GB; без локален → basename)

REV.4: всеки пакет носи Poly1305 таг (verify преди decrypt), а сесийните
  ключове се извеждат от ДВАТА seed-а (сървърски ⊕ клиентски) — replay
  на стари сесии И стар „филм" S→C към клиента умира с „фалшив таг".
  Грешен ключ = фалшив таг при ПЪРВАТА команда (мълчалив close).
"""

def conn_fail(c, e):
    if isinstance(e, ProtocolError):
        sys.stderr.write(f"[!] нарушение на протокола: {e}\n"
                         "[!] най-вероятна причина: НЕВЕРЕН КЛЮЧ (фалшив таг),\n"
                         "[!]   подправени данни по пътя или несинхронна верига.\n")
        sys.exit(2)
    if c.frames == 0:
        sys.stderr.write(
            "[!] връзката затворена от сървъра още преди първия отговор (без END)\n"
            "[!] най-вероятна причина: НЕВЕРЕН КЛЮЧ или несинхронна верига. (" + str(e) + ")\n")
        sys.exit(2)
    sys.stderr.write(
        "[!] връзката прекъсна по средата на сесията — веригата е развързана;\n"
        "[!]   свържи се наново. (" + str(e) + ")\n")
    sys.exit(3)

YES = ("y", "yes", "д", "да")

def ask_yn(cmd):
    try:
        a = input(f"агентът се опитва да изпълни команда: {cmd}\n"
                  f"да се изпълни ли? y/n: ")
    except EOFError:
        print("[agentshell] EOF → отказ")
        return False
    return a.strip().lower() in YES

if __name__ == "__main__":
    flags = [a for a in sys.argv[1:] if a.startswith("-")]
    pos = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "--selftest" in flags:
        assert chacha_xor(bytes(32), bytes(8), bytes(64)) == VEC, "ChaCha20 FAIL"
        assert poly1305(POLY_K, POLY_M) == POLY_T, "Poly1305 FAIL"
        print("client selftest OK (ChaCha20 + Poly1305)"); sys.exit(0)
    if "--help" in flags or "-h" in flags:
        print(USAGE); sys.exit(0)
    if len(pos) < 3:
        sys.stderr.write(USAGE); sys.exit(1)
    yn = "--yn" in flags
    try:
        c = AgentShell(*pos[:3]); c.connect()
    except OSError as e:
        sys.stderr.write(f"[!] не мога да се свържа с {pos[0]}:{pos[1]} — {e}\n")
        sys.exit(2)
    for line in sys.stdin:
        cmd = line.rstrip("\n")
        if not cmd: continue
        if cmd.startswith("@put "):
            parts = cmd.split(None, 2)
            if len(parts) < 3 or not parts[1] or not parts[2]:
                print("употреба: @put <локален_файл> <дистанционен_път>"); continue
            try:
                data = open(parts[1], "rb").read()
            except OSError as e:
                print(f"[грешка] {e}"); continue
            try:
                st, msg = c.upload(parts[2], data)
            except (ConnectionError, ProtocolError) as e:
                conn_fail(c, e)
            print(f"{msg}\n[exit {st}]")
            continue
        if cmd.startswith("@get "):
            parts = cmd.split(None, 2)
            if len(parts) < 2 or not parts[1]:
                print("употреба: @get <дистанционен_път> [локален_файл]"); continue
            rpath = parts[1]
            local = parts[2] if len(parts) > 2 and parts[2] else \
                os.path.basename(rpath.rstrip("/")) or "get.out"
            try:
                st, n = c.download(rpath, local)
            except (ConnectionError, ProtocolError) as e:
                conn_fail(c, e)
            except OSError as e:
                print(f"[грешка] {e}"); continue
            if st == 0:
                print(f"[get OK] {n} B → {local}")
            elif st == 126:
                print("[@get] отказано от оператора (y/n)")
            else:
                print(f"[@get] грешка: статус {st} (файлът не е взет)")
            continue
        if yn and not ask_yn(cmd):
            print(f"[пропусната] {cmd}")
            continue
        try:
            for chunk in c.run(cmd):
                sys.stdout.write(chunk.decode("utf-8", "replace"))
        except (ConnectionError, ProtocolError) as e:
            conn_fail(c, e)
        print(f"\n[exit {c.last_exit}]")

