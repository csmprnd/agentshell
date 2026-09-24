#!/usr/bin/env python3
# =================================================================
# ЕО-42 · ЕКСПЕРИМЕНТАЛЕН ОБРАЗЕЦ №42
# -----------------------------------------------------------------
# КБ ИСОМ
# Конструкторско Бюро за Изчислителни
# Системи за Обработка на Матрици
#
# ДАТА:     17 Септември 2026 г.
# АВТОР:    Виктор Желев
# ПРОЕКТ:   https://github.com/csmprnd
# UL-ID:    EO-42
#
# ЛИЦЕНЗ:   UL-1.0
#           https://cyber-bulgaria.eu/license_ul1.txt
#           в сила към 2026-08-05
# =================================================================
# client.py — usage: client.py <host> <port> <hexkey64> | --selftest
import os, socket, struct, sys

BASE_C = bytes.fromhex("FF81FFFF3E420818")
BASE_S = bytes.fromhex("007E0000C1BDF7E7")
VEC = bytes.fromhex(
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")

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

class AgentShell:
    def __init__(self, host, port, hexkey):
        self.key = bytes.fromhex(hexkey)
        self.s = socket.create_connection((host, int(port)))
        self.p_tx = 0; self.p_rx = 0; self.last_exit = None
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
    def _n(self, seed, p):
        return ((int.from_bytes(seed, "little") + p) & 0xffffffffffffffff).to_bytes(8, "little")
    def send_msg(self, data):
        pt = struct.pack(">I", len(data)) + data
        pt += b"\0" * (-len(pt) % 64)
        out = b""
        for j in range(len(pt) // 64):
            if j % 16 == 0:
                nonce = self._n(self.seed_tx, self.p_tx); self.p_tx += 1
            else:
                nonce = out[-8:]
            out += chacha_xor(self.key, nonce, pt[j*64:(j+1)*64])
        self.s.sendall(out)
    def recv_msg(self):
        ct = self._exact(64)
        pt = chacha_xor(self.key, self._n(self.seed_rx, self.p_rx), ct); self.p_rx += 1
        ln = struct.unpack(">I", pt[:4])[0]
        for j in range(1, 1 if ln == 0 else -(-(ln + 4) // 64)):
            b = self._exact(64)
            if j % 16 == 0:
                nonce = self._n(self.seed_rx, self.p_rx); self.p_rx += 1
            else:
                nonce = ct[-8:]
            ct = b; pt += chacha_xor(self.key, nonce, b)
        return ln, (pt[4:8] if ln == 0 else pt[4:4+ln])

    def run(self, cmd):
        self.send_msg(cmd.encode())
        while True:
            ln, data = self.recv_msg()
            if ln == 0:
                self.last_exit = struct.unpack(">I", data[:4])[0]; return
            yield data

    def upload(self, path, data):
        """Качване на файл (протокол v2): [00][path_len BE16][path][size BE64][data]
        връща (status, текст) — status 0 = записано; сървърът отговаря
        'upload: OK <size> B -> <path>' или 'upload: FAIL …' (+END 126 при отказ)"""
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

USAGE = """\
ЕО-42 · agentshell клиент
употреба:
  agentshell.py <host> <port> <hex_key_64> [--yn] | --selftest | --help

  чете команди от stdin, по една на ред, и стрийма отговора

флагове:
  --yn        преди всяка команда пита на конзолата:
                агентът се опитва да изпълни команда: <cmd>
                да се изпълни ли? y/n
              y/yes/д/да → изпрати; n/н → пропусни; EOF → отказ
  --selftest  вътрешен тест на ChaCha20
  --help      този текст

синтаксис на команда (без shell, без quoting):
  ENV1=val ENV2=val CWD=/path /bin/program arg1 arg2

специални редове:
  @put <локален_файл> <дистанционен_път>   качва файла (v2 upload)
"""

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
        assert chacha_xor(bytes(32), bytes(8), bytes(64)) == VEC
        print("client selftest OK"); sys.exit(0)
    if "--help" in flags or "-h" in flags:
        print(USAGE); sys.exit(0)
    if len(pos) < 3:
        sys.stderr.write(USAGE); sys.exit(1)
    yn = "--yn" in flags
    c = AgentShell(*pos[:3]); c.connect()
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
            st, msg = c.upload(parts[2], data)
            print(f"{msg}\n[exit {st}]")
            continue
        if yn and not ask_yn(cmd):
            print(f"[пропусната] {cmd}")
            continue
        for chunk in c.run(cmd):
            sys.stdout.write(chunk.decode("utf-8", "replace"))
