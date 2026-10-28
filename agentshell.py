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
# agentshell.py — клиент за протокол REV.5 (AEAD, еднократен MAC ключ/пакет):
#   пакет = [L u32 BE][ct L B][tag 16B]; verify ПРЕДИ decrypt.
#   OTK (REV.5): otk = ChaCha20(kpoly_dir, LE64(p))[0:32) — ЕДНОКРАТЕН
#   Poly1305 ключ на пакет (Wegman-Carter, RFC 8439 маниер); таг =
#   Poly1305(otk, dir ‖ p u64LE ‖ L u32BE ‖ 0³ ‖ ct). Корени: kpoly =
#   KS0[32:64) (C→S), kpoly_s2c = ChaCha20(kpoly, 2^64−1)[0:32) (S→C) —
#   преизползването на MAC ключ (GCD атака) става невъзможно.
#   KDF REV.4 (KS0 от двата seed-а) е непроменен; S→C шифър = PSK;
#   хендшейкът (64+64 B salt) е непроменен — 0 нови байта по кабела.
#   REV.5b: send_msg е СТРИЙМ — блоковете се шифроват и се пращат пакет по
#   пакет (1024 B), щом са готови; по кабела е БАЙТ-ИДЕНТИЧНО с буферния
#   еталон (_encrypt — selftest доказва). Първият пакет тръгва мигновено →
#   3 s пре-auth дедлайнът на сървъра е безпредметен за @put на всякакъв
#   размер; @put тече директно от диска (O(1) RAM, upload_file).
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
        self.kpoly = ks0[32:64]         # REV.5: корен за C→S OTK
        # REV.5: корен за S→C OTK — производен с РЕЗЕРВИРАН нонс 2^64−1
        # (OTK нонсовете са LE64(p), p ∈ [0, 2^64−1) — никога не го стига)
        self.kpoly_s2c = chacha_xor(self.kpoly, b"\xff" * 8, bytes(64))[:32]
    def _n(self, seed, p):
        return ((int.from_bytes(seed, "little") + p) & 0xffffffffffffffff).to_bytes(8, "little")
    def _tag(self, direction, p, L, ct):
        # REV.5: еднократен Poly1305 ключ на пакет (Wegman-Carter):
        #   otk = ChaCha20(kpoly_dir, LE64(p))[0:32); всеки таг под нов ключ
        #   → преизползване/GCD атака върху MAC ключа е невъзможна
        root = self.kpoly if direction == b"C" else self.kpoly_s2c
        otk = chacha_xor(root, struct.pack("<Q", p), bytes(64))[:32]
        hdr = direction + struct.pack("<Q", p) + struct.pack(">I", L) + b"\0\0\0"
        return poly1305(otk, hdr + ct)
    def _encrypt(self, pt):
        """ЕТАЛОН: буферен шифър на цялото съобщение наведнъж (мутира p_tx).
        send_msg върви по стрийм пътя (_packets); тази функция стои като
        еталон — selftest сравнява двата пътя байт-по-байт (REV.5b)."""
        out = b""
        for j in range(len(pt) // 64):
            if j % 16 == 0:
                nonce = self._n(self.seed_tx, self.p_tx); self.p_tx += 1
            else:
                nonce = out[-8:]
            out += chacha_xor(self.enc_key, nonce, pt[j*64:(j+1)*64])
        return out
    def _packets(self, pieces, total_plain):
        """REV.5b: стрийм пакетиране — връща (p, ct_пакет) щом се съберат
        PKT_MAX байта ct, без да чака цялото съобщение. pt = [L u32 BE] +
        pieces + падинг до 64; веригата: лидер на всеки 16-ти блок (nonce =
        _n(seed_tx, p_start + j//16)), иначе nonce = опашката на предишния
        ct блок. БАЙТ-ИДЕНТИЧНО с буферния еталон (selftest). Контракт:
        sum(len(x) for x in pieces) == 4 + total_plain (виканият дава и
        4-байтовия хедър като ПЪРВО piece)."""
        total = 4 + total_plain
        total_ct = total + (-total % 64)
        p_start = self.p_tx
        npkt = (total_ct + PKT_MAX - 1) // PKT_MAX
        self.p_tx = p_start + npkt       # броячът се резервира EAGER — изоставен
                                         # generator не развързва сесията (таговете
                                         # носят p изрично, не четат p_tx)
        blk = bytearray()                # текущ pt блок (до 64 B)
        out = bytearray()                # ct на текущия пакет (до PKT_MAX)
        tail = b""                       # последните 8 B от предишния ct блок
        j = 0                            # глобален блоков индекс в съобщението
        k = 0                            # индекс на пакета в съобщението
        for piece in pieces:
            i = 0
            while i < len(piece):
                take = min(64 - len(blk), len(piece) - i)
                blk += piece[i:i + take]
                i += take
                if len(blk) < 64:
                    continue
                nonce = self._n(self.seed_tx, p_start + (j >> 4)) if j % 16 == 0 else tail
                c = chacha_xor(self.enc_key, nonce, bytes(blk))
                tail = c[56:64]
                out += c
                blk.clear()
                j += 1
                if len(out) == PKT_MAX:
                    yield p_start + k, bytes(out)
                    k += 1
                    out.clear()
        if blk:                          # последен непълен блок + падинг
            blk += b"\0" * (64 - len(blk))
            nonce = self._n(self.seed_tx, p_start + (j >> 4)) if j % 16 == 0 else tail
            c = chacha_xor(self.enc_key, nonce, bytes(blk))
            tail = c[56:64]
            out += c
            blk.clear()
        if out:                          # последен пакет (кратък или пълен)
            yield p_start + k, bytes(out)
            k += 1
            out.clear()
        assert k == npkt and not blk and not out, "стрийм пакетиране: броене?"
    def _send(self, pkts):
        for p, pkt in pkts:
            tag = self._tag(b"C", p, len(pkt), pkt)
            self.s.sendall(struct.pack(">I", len(pkt)) + pkt + tag)
    def send_msg(self, data):
        # REV.5b: стрийм — първият пакет тръгва по кабела щом е готов,
        # без да чака цялото съобщение да се шифрова (байт-идентично)
        self._send(self._packets([struct.pack(">I", len(data)), data], len(data)))
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
        """@put (REV.3): [00][path_len BE16][path][size BE64][data]
        (data в RAM; за файлове ползвай upload_file — стрийм от диска)"""
        p = path.encode() if isinstance(path, str) else path
        d = data if isinstance(data, (bytes, bytearray)) else data.encode()
        if not 1 <= len(p) <= 4096:
            raise ValueError("пътят трябва да е 1..4096 байта")
        head = b"\x00" + len(p).to_bytes(2, "big") + p + len(d).to_bytes(8, "big")
        payload = head + d
        self._send(self._packets([struct.pack(">I", len(payload)), payload], len(payload)))
        text = b""
        while True:
            ln, chunk = self.recv_msg()
            if ln == 0:
                return struct.unpack(">I", chunk[:4])[0], text.decode("utf-8", "replace")
            text += chunk

    def upload_file(self, lpath, rpath, chunk=65536):
        """@put директно от диска (REV.5b): файлът НИКОГА не е цял в RAM
        (O(1) памет) и първият пакет тръгва мигновено — 3 s пре-auth
        дедлайнът на сървъра е безпредметен за всякакъв размер."""
        p = rpath.encode() if isinstance(rpath, str) else rpath
        if not 1 <= len(p) <= 4096:
            raise ValueError("пътят трябва да е 1..4096 байта")
        f = open(lpath, "rb")
        try:
            size = os.fstat(f.fileno()).st_size
            head = b"\x00" + len(p).to_bytes(2, "big") + p + size.to_bytes(8, "big")
            total = len(head) + size
            def pieces():
                yield struct.pack(">I", total)   # 4B length header — ПЪРВО piece!
                yield head
                while True:
                    c = f.read(chunk)
                    if not c:
                        break
                    yield c
            self._send(self._packets(pieces(), total))
        finally:
            f.close()
        text = b""
        while True:
            ln, ch = self.recv_msg()
            if ln == 0:
                return struct.unpack(">I", ch[:4])[0], text.decode("utf-8", "replace")
            text += ch

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
ЕО-42 · agentshell клиент (протокол REV.5 — AEAD, еднократен MAC ключ/пакет)
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

REV.5b: @put тече директно от диска (O(1) RAM) и стриймва шифровани пакети
  от мига на командата — първият кадър тръгва мигновено, без целия файл в
  паметта и без мълчание преди трансфера (3 s пре-auth дедлайн: безпредметен).
REV.5: всеки таг се изчислява под ЕДНОКРАТЕН ключ (otk = f(kpoly_dir, p))
  — преизползването на Poly1305 ключа (GCD атака) е невъзможно. KDF REV.4
  (двата seed-а) е непроменен: replay на стари сесии И стар „филм" S→C
  към клиента умира с „фалшив таг". Грешен ключ = фалшив таг при ПЪРВАТА
  команда (мълчалив close).
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
        # REV.5: OTK дисциплина — различни за различни p и за различен корен
        _r = bytes(range(32))
        _ots = {chacha_xor(_r, struct.pack("<Q", p), bytes(64))[:32] for p in range(8)}
        assert len(_ots) == 8, "OTK колизия по p?!"
        assert chacha_xor(_r, b"\xff" * 8, bytes(64))[:32] not in _ots,             "OTK колизия с резервирания нонс?!"
        # REV.5b: стрийм пътят (_packets/send_msg) е БАЙТ-ИДЕНТИЧЕН с буферния
        # еталон (_encrypt) — по кабелния формат, вкл. тагове и брояч p
        _c = AgentShell.__new__(AgentShell)          # без socket
        _c.enc_key = bytes(range(32))
        _c.seed_tx = b"\x10\x32\x54\x76\x98\xba\xdc\xfe"
        _c.kpoly = bytes(range(32, 64))
        _sizes = ([0, 1, 60, 64, 1019, 1020, 1021, 2044, 2045, 3068, 4095,
                   4096, 8188, 8189, 16380, 16381] +                 # гранични
                  [(i * 7919) % 9000 + 1 for i in range(1, 25)] +    # разхвърляни
                  [100_000, 262_144])                                # големи
        _n_chk = 0
        for _sz in _sizes:
            _d = os.urandom(_sz)
            _pt = struct.pack(">I", len(_d)) + _d + b"\0" * (-(4 + len(_d)) % 64)
            _c.p_tx = 0
            _whole = _c._encrypt(_pt)                                # еталон
            _ref = b""
            for _k in range((len(_whole) + PKT_MAX - 1) // PKT_MAX):
                _sl = _whole[_k * PKT_MAX:(_k + 1) * PKT_MAX]
                _ref += struct.pack(">I", len(_sl)) + _sl + _c._tag(b"C", _k, len(_sl), _sl)
            _c.p_tx = 0
            _strm = b""; _ps = []
            for _p, _pkt in _c._packets([struct.pack(">I", len(_d)), _d], len(_d)):
                _ps.append(_p)
                _strm += struct.pack(">I", len(_pkt)) + _pkt + _c._tag(b"C", _p, len(_pkt), _pkt)
            assert _ref == _strm, f"стрийм ≠ цяло при n={_sz}!"
            assert _ps == list(range(len(_ps))), f"p не е решетъчно последователен при n={_sz}!"
            assert _c.p_tx == len(_ps), f"p_tx счетен грешно при n={_sz}!"
            _n_chk += 1
        # разкъсани pieces (груби файлови четения) → същите байтове
        _d = os.urandom(5000)
        _w1 = b""; _c.p_tx = 0
        for _p, _pkt in _c._packets([struct.pack(">I", len(_d))] + [_d[i:i+7] for i in range(0, len(_d), 7)], len(_d)):
            _w1 += struct.pack(">I", len(_pkt)) + _pkt + _c._tag(b"C", _p, len(_pkt), _pkt)
        _w2 = b""; _c.p_tx = 0
        for _p, _pkt in _c._packets([struct.pack(">I", len(_d)), _d], len(_d)):
            _w2 += struct.pack(">I", len(_pkt)) + _pkt + _c._tag(b"C", _p, len(_pkt), _pkt)
        assert _w1 == _w2, "стрийм зависи от разкъсването на pieces?!"
        # броячът продължава НАД съобщенията (решетъчна инварианта на сесията)
        _c.p_tx = 0
        for _p, _ in _c._packets([struct.pack(">I", 3000), b"A" * 3000], 3000):
            _last = _p
        assert _last == 2 and _c.p_tx == 3, "броене на пакети над съобщение?!"
        assert next(iter(_c._packets([struct.pack(">I", 0)], 0)))[0] == 3, \
            "броячът не продължава над съобщения?!"
        print(f"client selftest OK (ChaCha20 + Poly1305 + OTK + стрийм≡цяло ×{_n_chk} размера)"); sys.exit(0)
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
                st, msg = c.upload_file(parts[1], parts[2])   # REV.5b: стрийм от диска
            except OSError as e:
                print(f"[грешка] {e}"); continue
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

