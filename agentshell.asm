; ================================================================
; ЕО-42 · ЕКСПЕРИМЕНТАЛЕН ОБРАЗЕЦ №42
; ------------------------------------------------
; КБ ИСОМ
; Конструкторско Бюро за Изчислителни
; Системи за Обработка на Матрици
;
; ДАТА:     17 Септември 2026 г.
; АВТОР:    Виктор Желев
; ПРОЕКТ:   https://github.com/csmprnd
; UL-ID:    EO-42
;
; ЛИЦЕНЗ:   UL-1.0
;           https://cyber-bulgaria.eu/license_ul1.txt
;           в сила към 2026-08-05
; ================================================================

; ============================================================
; agentshell.asm — x86-64 Linux / NASM
;
;   nasm -f elf64 agentshell.asm -o agentshell.o
;   ld -o agentshell agentshell.o
;
;   ВАЖНО: ISOM.ANSI (банерът) трябва да е в същата директория
;   като agentshell.asm по време на компилация (incbin).
;
;   ./agentshell <port> <hex_key_64>
;   ./agentshell --selftest
;
; Протокол ЕО-42 (wire REV.4 — AEAD; детайли: README REV. 4, §3–§7, §13):
;   salt 64B (ChaCha20(key, BASE_dir) XOR random64; seed = ct[56..63])
;   KDF (без нови wire байтове): KS0 = ChaCha20(key, seed_s2c ⊕ seed_c2s)
;        enc_key_c2s = KS0[0..32)  — сесиен ключ C→S (двупосочна свежест!);
;        kpoly       = KS0[32..64) — Poly1305 ключ (общ, dir байт в MAC входа)
;   пакет = [L u32 BE][ct L B][tag 16B]; 64 ≤ L ≤ 1024, L%64 == 0;
;        tag = Poly1305(kpoly, 'C'|'S' ‖ p u64LE ‖ L u32BE ‖ 0³ ‖ ct)
;        verify ПРЕДИ decrypt (V1 replay / V2+V3 bit-flip / филмът §13.2 умират)
;   съобщение = [len u32 BE][data] zero-pad до %64 (вътре в ct — както REV.2)
;   шифър: C→S = enc_key_c2s (сесиен); S→C = key (PSK)
;   nonce: j%16==0 → seed_dir + p (p = брояч пакети, uint64, не се
;          нулира между съобщения); иначе → ct предходен блок [56..64)
;   p ≡ брояч пакети ≡ лидъри (16-блокови пакети) — и двете страни
;          го броят имплицитно; таг и лидър ползват ЕДНО и също p!
;   len==0 от client → drop; len==0 от server → END (status в data)
;   @put = [00][plen BE16 ≤4096][път][size BE64][данни] — запис, ≤1GB
;   @get = [01][plen BE16 ≤4096][път] — четене; S_ISREG; ≤1GB (Вълна 3)
;
; Регистров контракт (вътрешен):
;   chacha_block : caller-save rax,rcx,rdx ; пази rbx,rbp,r12-r15,rdi,rsi
;   read_full/send_all : clobber rax,rcx,rdx,rdi,rsi,r8-r11
; ============================================================

bits 64
default rel

; ---------- syscalls ----------
%define SYS_read          0
%define SYS_write         1
%define SYS_open          2
%define SYS_close         3
%define SYS_mmap          9
%define SYS_rt_sigaction  13
%define SYS_rt_sigreturn  15
%define SYS_dup2          33
%define SYS_socket        41
%define SYS_sendto        44
%define SYS_setsockopt    54
%define SYS_bind          49
%define SYS_listen        50
%define SYS_clone         56
%define SYS_wait4         61
%define SYS_kill          62
%define SYS_fcntl         72
%define SYS_chdir         80
%define SYS_exit          60
%define SYS_exit_group    231
%define SYS_getrandom     318
%define SYS_memfd_create  319
%define SYS_execveat      322
%define SYS_pipe2         293
%define SYS_accept4       288
%define SYS_getpeername   52
%define SYS_clock_gettime 228
%define SYS_fstat         5
%define SYS_umask         95
; ---------- константи ----------
%define AF_INET        2
%define SOCK_STREAM    1
%define SOCK_CLOEXEC   0x80000
%define MSG_NOSIGNAL   0x4000
%define SOL_SOCKET     1
%define SO_REUSEADDR   2
%define SO_RCVTIMEO    20
%define O_RDONLY       0
%define O_CLOEXEC      0x80000
%define O_CREAT        0x40
%define O_TRUNC        0x200
%define O_APPEND       0x400
%define CLOCK_REALTIME 0
%define TZ_OFFSET      (3*3600)     ; EEST (UTC+3) — !!! зиме смени на (2*3600) :D
%define MFD_CLOEXEC    0x01
%define MFD_EXEC       0x10
%define F_ADD_SEALS    1033
%define F_SEAL_SHRINK  2
%define F_SEAL_GROW    4
%define F_SEAL_WRITE   8
%define AT_EMPTY_PATH  0x1000
%define CLONE_VM       0x100
%define CLONE_VFORK    0x4000
%define SIGHUP         1
%define SIGINT         2
%define SIGQUIT        3
%define SIGTERM        15
%define SIGCHLD        17
%define SIGKILL        9
%define SA_RESTORER    0x04000000    ; x86-64: БЕЗ него ядрото не доставя сигнала
%define SA_RESTART     0x10000000    ; QA FIX (Luna/DeepSeek): auto-restart на прекъснати blocking syscalls

%define MAX_CMD        8192        ; по-дълга команда → drop
; --- Вълна 1 (Task 34): sanitize/ротация/rule9/memfd кап ---
%define ESC_CAP        4*MAX_CMD   ; esc_buf: най-лошият случай — всеки байт → \xHH
%ifndef ROT_SIZE
%define ROT_SIZE       250*1024*1024   ; ротация на журнала: месец ИЛИ 250 MB
%endif
%define JUNK63         63          ; RULE 9: 63 junk четива → мълчалив close
; --- Вълна 2 (REV.3): AEAD рамкиране ---
%define PKT_MAX        1024        ; макс ct байтове на пакет (16 блока)
%define TAG_LEN        16          ; Poly1305 таг
%ifndef MEMFD_CAP
%define MEMFD_CAP      980*1024*1024   ; V4: кап на memfd (lab билдът го сваля)
%endif
%define UP_MAX         1073741824  ; max размер на качен файл (1GB)
%define CHUNK          4096        ; четене от pipe-а / io_buf flush
%define STACK_SIZE     65536       ; стек на child-а

; ============================================================
section .rodata
; ============================================================
base_s:       db 00h,7Eh,00h,00h,0C1h,0BDh,0F7h,0E7h   ; ~BASE_C

; ---------- банер ИСОМ (вграждане при компилация) ----------
; Отпечатва се като ПЪРВОТО нещо при всяко стартиране (вкл. --help/--selftest)
isom_ansi:    db 10                        ; празен ред преди арта
              incbin "ISOM.ANSI"           ; самият арт (UTF-8, завършва с \n)
              db 10                        ; празен ред след арта
isom_ansi_len equ $ - isom_ansi
devnull:      db "/dev/null",0
empty:        db 0
memfd_name:   db "payload",0
str_selftest: db "--selftest",0
str_openfail: db "cannot open binary",10
str_openfail_len equ $ - str_openfail
st_ok:        db "selftest OK",10
st_ok_len     equ $ - st_ok
st_fail:      db "selftest FAIL",10
st_fail_len   equ $ - st_fail
usage_msg:    db "usage: agentshell <port> <hex_key_64> [--yn] | --selftest | --help",10
usage_len     equ $ - usage_msg
str_help:     db "--help",0
str_h:        db "-h",0
str_yn:       db "--yn",0
help_msg:     db 10
              db "ЕО-42 · agentshell — криптиран remote-exec сървър (x86-64, без libc)",10,10
              db "употреба:",10
              db "  agentshell <port> <hex_key_64> [--yn]",10
              db "  agentshell --selftest | --help",10,10
              db "аргументи:",10
              db "  <port>        TCP порт (1-65535)",10
              db "  <hex_key_64>  64 hex символа = 32B pre-shared ключ (openssl rand -hex 32)",10,10
              db "флагове:",10
              db "  --yn        преди всяка команда пита в конзолата (stderr):",10
              db "                агентът се опитва да изпълни команда: <cmd>",10
              db "                да се изпълни ли? y/n",10
              db "              y/Y/д/Д = изпълни;  n/N/н/Н = отказ (клиентът получава",10
              db "              exit 126);  EOF от stdin = отказ (безопасно)",10
              db "  --selftest  ChaCha20 векторен тест и изход",10
              db "  --help      този текст",10,10
              db "лог: при всяко пускане се създава DD-MM-YYYY_HH-MM-SS.txt",10
              db "              в текущата директория — пълен одит (връзки, команди,",10
              db "              y/n решения, изход, статуси, изключване)",10,10
              db "upload: съобщение, започващо с нулев байт = запис на файл:",10
              db "        [00][дълж.на пътя BE16 ≤4096][път][размер BE64][данни]",10
              db "        директорията трябва да съществува; съществуващ файл се",10
              db "        презаписва (O_TRUNC); размер ≤1GB; --yn пита и за това",10
              db "get: съобщение, започващо с байт 01 = четене на файл:",10
              db "        [01][дълж.на пътя BE16 ≤4096][път]",10
              db "        само редовни файлове (S_ISREG); размер ≤1GB;",10
              db "        съдържанието НЕ се журналира; --yn пита и за това",10,10
              db "клиент:  agentshell.py <host> <port> <hex_key_64> [--yn]",10
              db "протокол: ЕО-42 — виж README.md",10
help_len      equ $ - help_msg
yn_hdr1:      db 10,"[agentshell] агентът се опитва да изпълни команда:",10,"  "
yn_hdr1_len   equ $ - yn_hdr1
yn_hdr2:      db 10,"да се изпълни ли? y/n: "
yn_hdr2_len   equ $ - yn_hdr2
yn_more:      db "отговори y или n: "
yn_more_len   equ $ - yn_more
yn_yes_log:   db "[agentshell] позволено от оператора",10
yn_yes_len    equ $ - yn_yes_log
yn_no_log:    db "[agentshell] отказано от оператора",10
yn_no_len     equ $ - yn_no_log
yn_deny:      db "[agentshell] отказано от оператора (y/n)",10
yn_deny_len   equ $ - yn_deny

; ---------- качване (съобщение, започващо с нулев байт) ----------
lg_up:        db "upload: "
lg_up_len     equ $ - lg_up
lg_up2:       db " ("
lg_up2_len    equ $ - lg_up2
lg_up3:       db " B)"
lg_up3_len    equ $ - lg_up3
lg_up_ok:     db "upload: OK "
lg_up_ok_len  equ $ - lg_up_ok
lg_up_ok2:    db " B"
lg_up_ok2_len equ $ - lg_up_ok2
lg_up_fail:   db "upload: FAIL — грешка при запис"
lg_up_fail_len equ $ - lg_up_fail
lg_up_open:   db "upload: FAIL — файлът не се отваря"
lg_up_open_len equ $ - lg_up_open
lg_up_bad:    db "upload: невалидно съобщение — прекъсвам"
lg_up_bad_len equ $ - lg_up_bad
up_rep_ok:    db "upload: OK "
up_rep_ok_len equ $ - up_rep_ok
up_rep_mid:   db " B -> "
up_rep_mid_len equ $ - up_rep_mid
yn_up1:       db 10,"[agentshell] агентът иска да запише файл:",10,"  "
yn_up1_len    equ $ - yn_up1
yn_up2:       db 10,"да се запише ли? y/n: "
yn_up2_len    equ $ - yn_up2

; ---------- @get (съобщение, започващо с байт 0x01) — Вълна 3 ----------
lg_get:        db "get: "
lg_get_len     equ $ - lg_get
lg_get_ok:     db "get: OK "
lg_get_ok_len  equ $ - lg_get_ok
lg_get_ok2:    db " B"
lg_get_ok2_len equ $ - lg_get_ok2
lg_get_open:   db "get: FAIL — файлът не се отваря"
lg_get_open_len equ $ - lg_get_open
lg_get_irr:    db "get: FAIL — не е редовен файл"
lg_get_irr_len equ $ - lg_get_irr
lg_get_big:    db "get: FAIL — над капа (1 GB)"
lg_get_big_len equ $ - lg_get_big
lg_get_rf:     db "get: FAIL — грешка при четене"
lg_get_rf_len  equ $ - lg_get_rf
lg_get_bad:    db "get: невалидно съобщение — прекъсвам"
lg_get_bad_len equ $ - lg_get_bad
lg_getsan2:    db " B екейпнати в get: реда)"
lg_getsan2_len equ $ - lg_getsan2
yn_get1:       db 10,"[agentshell] агентът иска да прочете файл:",10,"  "
yn_get1_len    equ $ - yn_get1
yn_get2:       db 10,"да се изпрати ли? y/n: "
yn_get2_len    equ $ - yn_get2

; ---------- лог ----------
log_suffix:   db ".txt",0
hexd:         db "0123456789abcdef"
log_openfail: db "[agentshell] лог-файл не се създаде — продължавам без лог",10
log_openfail_len equ $ - log_openfail
lg_start:     db "=== agentshell стартира — порт "
lg_start_len  equ $ - lg_start
lg_key:       db ", ключ "
lg_key_len    equ $ - lg_key
lg_yn1:       db ", --yn: вкл, TZ=UTC+"
lg_yn1_len    equ $ - lg_yn1
lg_yn0:       db ", --yn: изкл, TZ=UTC+"
lg_yn0_len    equ $ - lg_yn0
lg_end:       db " ==="
lg_end_len    equ $ - lg_end
lg_conn:      db "+ връзка от "
lg_conn_len   equ $ - lg_conn
lg_hs:        db "handshake OK (ЕО-42)"
lg_hs_len     equ $ - lg_hs
lg_cmd:       db "cmd: "
lg_cmd_len    equ $ - lg_cmd
lg_yn_ok:     db "yn: позволено от оператора"
lg_yn_ok_len  equ $ - lg_yn_ok
lg_yn_no:     db "yn: отказано от оператора"
lg_yn_no_len  equ $ - lg_yn_no
lg_exit:      db "exit: "
lg_exit_len   equ $ - lg_exit
lg_sig:       db "убит от сигнал "
lg_sig_len    equ $ - lg_sig
lg_close:     db "- връзката затворена"
lg_close_len  equ $ - lg_close
lg_down1:     db "=== изключване (сигнал "
lg_down1_len  equ $ - lg_down1
lg_down2:     db ") ==="
lg_down2_len  equ $ - lg_down2
lg_childkill: db "   child: SIGKILL при изключване"
lg_childkill_len equ $ - lg_childkill
lg_fatal:     db "=== FATAL: syscall грешка, exit 1 ==="
lg_fatal_len  equ $ - lg_fatal
lg_blfail:    db "FATAL: портът не се закача — bind/listen errno="
lg_blfail_len equ $ - lg_blfail
lg_blhint:    db " (порт зает от друг процес?)"
lg_blhint_len equ $ - lg_blhint
lg_junk:      db "джънк ("
lg_junk_len   equ $ - lg_junk
lg_junk2:     db " B): "
lg_junk2_len  equ $ - lg_junk2
lg_jtot:      db "джънк общо ("
lg_jtot_len   equ $ - lg_jtot
lg_jtot2:     db " B; дъмпнати първите "
lg_jtot2_len  equ $ - lg_jtot2
lg_jend:      db " B)"
lg_jend_len   equ $ - lg_jend
lg_san:       db "✂ САНИТ ("
lg_san_len    equ $ - lg_san
lg_san2:      db " B екейпнати в cmd: реда)"
lg_san2_len   equ $ - lg_san2
lg_san3:      db "; дъмпът отрязан на буфера"
lg_san3_len   equ $ - lg_san3
lg_over:      db "✂ ОТРЯЗ (argv/envp >1023) — мълчалив close"
lg_over_len   equ $ - lg_over
lg_ovcmd:     db "✂ ОТРЯЗ (команда "
lg_ovcmd_len  equ $ - lg_ovcmd
lg_ovcmd2:    db " B > 8192) — мълчалив close"
lg_ovcmd2_len equ $ - lg_ovcmd2
lg_jcut:      db "✂ ОТРЯЗ (63 джънък-четива — мълчалив close)"
lg_jcut_len   equ $ - lg_jcut
lg_cap:       db "✂ ОТРЯЗ (binary надхвърля капа memfd — източникът е в cmd: реда)"
lg_cap_len    equ $ - lg_cap
lg_rot:       db "=== ротация от "
lg_rot_len    equ $ - lg_rot
lg_rot2:      db " ==="
lg_rot2_len   equ $ - lg_rot2
lg_timeout:   db "timeout: пиър без валидни данни (преди auth) — отказана"
lg_timeout_len equ $ - lg_timeout
; ---------- REV.3/4 (AEAD) ----------
lg_tagf:      db "✂ ОТРЯЗ (фалшив таг — пакет "
lg_tagf_len   equ $ - lg_tagf
lg_tagf2:     db "); получен: "
lg_tagf2_len  equ $ - lg_tagf2
lg_tagf3:     db " | ct0: "
lg_tagf3_len  equ $ - lg_tagf3
lg_tagf4:     db " (първите 16 B)"
lg_tagf4_len  equ $ - lg_tagf4
lg_lsan:      db "✂ ОТРЯЗ (невалиден пакет, L="
lg_lsan_len   equ $ - lg_lsan
lg_lsan2:     db " B) — мълчалив close | сурови: "
lg_lsan2_len  equ $ - lg_lsan2
; Poly1305 selftest: RFC 8439 2.5.2 (тагът сверен с openssl mac Poly1305)
poly_kvec:    db 085h,0D6h,0BEh,078h,057h,055h,06Dh,033h,07Fh,044h,052h,0FEh,042h,0D5h,006h,0A8h
              db 001h,003h,080h,08Ah,0FBh,00Dh,0B2h,0FDh,04Ah,0BFh,0F6h,0AFh,041h,049h,0F5h,01Bh
poly_mvec:    db "Cryptographic Forum Research Group"
poly_mvec_len equ $ - poly_mvec
poly_tvec:    db 0A8h,006h,01Dh,0C1h,030h,051h,036h,0C6h,0C2h,02Bh,08Bh,0AFh,00Ch,001h,027h,0A9h
str_execfail: db "execveat failed errno="
str_execfail_len equ $ - str_execfail
; ChaCha20: key=0^32, nonce=0^8, ctr=0 → каноничният вектор
; (валиден и за djb, и за IETF варианта — state-ът съвпада)
st_vec:       db 076h,0B8h,0E0h,0ADh,0A0h,0F1h,3Dh,90h,40h,5Dh,6Ah,0E5h,53h,86h,0BDh,28h
              db 0BDh,0D2h,19h,0B8h,0A0h,8Dh,0EDh,1Ah,0A8h,36h,0EFh,0CCh,8Bh,77h,0Dh,0C7h
              db 0DAh,41h,59h,7Ch,51h,57h,48h,8Dh,77h,24h,0E0h,3Fh,0B8h,0D8h,4Ah,37h
              db 6Ah,43h,0B8h,0F4h,15h,18h,0A1h,1Ch,0C3h,87h,0B6h,69h,0B2h,0EEh,65h,86h

; ============================================================
section .data
; ============================================================
align 8
one:    dd 1
tv_to:  dq 3                       ; SO_RCVTIMEO: 3 s на четене (пре-auth; клиентът е ИИ агент)
        dq 0
tv_off: dq 0                       ; изключване на SO_RCVTIMEO (след auth)
        dq 0
sigact: dq sig_handler           ; handler
        dq SA_RESTORER | SA_RESTART ; flags — ЗАДЪЛЖИТЕЛНО на x86-64!
        dq sig_restore           ; restorer (sig_handler не се връща, но ядрото
                                 ; иска валиден restorer още при доставката)
        dq 0                      ; mask

; ============================================================
section .bss
; ============================================================
key:        resb 32
port:       resd 1
listen_fd:  resd 1
sock_fd:    resd 1
pipe_r:     resd 1
pipe_w:     resd 1
memfd:      resd 1
child_pid:  resd 1
wstatus:    resd 1
seed_s2c:   resq 1                ; нашият TX seed (от нашия salt ct)
seed_c2s:   resq 1                ; RX seed (от client salt ct)
p_s2c:      resq 1                ; TX брояч пакети
p_c2s:      resq 1                ; RX брояч пакети (огледало)
stack_top:  resq 1
bin_path:   resq 1
cwd_ptr:    resq 1
argv_cnt:   resq 1
envp_cnt:   resq 1
argv_arr:   resq 1024
envp_arr:   resq 1024
sockaddr:   resb 16
pt_buf:     resb 16384            ; plaintext (команда / TX съобщение)
ct_buf:     resb 16384            ; ciphertext
salt_tx:    resb 64
salt_rx:    resb 64
io_buf:     resb CHUNK
status_buf: resb 8
zeros64:    resb 64
errno_msg:  resb 64
yn_flag:    resd 1                ; --yn активиран
arg_pos:    resq 2                ; позиционни аргументи (порт, ключ)
yn_ans:     resb 64               ; отговорът на оператора
log_fd:     resd 1                ; лог-файлът (DD-MM-YYYY_HH-MM-SS.txt)
log_name:   resb 32               ; име на лог-файла
log_buf:    resb 16384            ; сглобяване на лог-редове
; --- качване (upload) ---
up_path:    resb 4097             ; пътят на файла (с NUL накрая)
up_blk:     resb 64               ; дешифриран стрийм-блок
up_fb:      resb 8                ; feedback: ct[56..64) на предходния блок
up_reply:   resb 4352             ; сглобяване на лог-ред/отговор
up_msglen:  resd 1
up_blocks:  resd 1                ; общ брой 64B блокове на съобщението
up_js:      resd 1                ; първият блок с данни (след хедъра)
up_j:       resd 1                ; текущ блок
up_hneed:   resd 1                ; 15+path_len — край на хедъра
up_pathlen: resd 1
up_mode:    resd 1                ; 0 = запис / 1 = дрениране
up_ion:     resd 1                ; байтове в io_buf
up_fd:      resd 1
up_size:    resq 1                ; деклариран размер на файла
up_dstart:  resd 1                ; msg-офсет на първия байт с данни
up_dend:    resd 1                ; msg-офсет след последния байт с данни
up_written: resq 1                ; реално записани байтове
; --- @get (Вълна 3) ---
get_fd:     resd 1                ; четеният файл (V6-дисциплина: -1 когато е затворен)
get_total:  resq 1                ; общо изпратени байтове (капът важи и по време на стрийма)
get_msglen: resd 1                ; msg_len (записан от recv_msg)
get_pathlen: resd 1
get_path:   resb 4097             ; пътят за четене (+NUL) — собствен, не up_path
get_stat:   resb 144              ; struct stat scratch за fstat
yn_h1:      resq 1                ; динамични заглавки за yn_prompt
yn_h1l:     resd 1
yn_h2:      resq 1
yn_h2l:     resd 1
peer_len:   resd 1                ; за getpeername
tmp32:      resb 256              ; буфер за сглобяване на съобщения (стартовият ред е ~102B)
authed:     resd 1                ; 0 = пре-auth (дедлайнът върви) / 1 = след първата валидна команда
deadline:   resq 1                ; монотонен дедлайн за пре-auth (секунди)
mono_ts:    resq 2                ; timespec scratch за CLOCK_MONOTONIC
rf_got:     resd 1                ; байтове, приети в последното read_full (за дъмпа на джънка)
rf_err:     resd 1                ; -1 (EOF/нарушение) или -errno от последното read_full
junk_buf:   resb 64               ; drain_junk: chunk буфер (четене на 64 B стъпки)
junk_total: resq 1                ; drain_junk: общо байтове, изсмукани след провала
junk_dmpd:  resq 1                ; drain_junk: от тях hex-нати (до JUNK_CAP)
junk_chunks: resd 1               ; drain_junk: брой последователни junk четива (rule 9)
lb_total:    resq 1               ; load_binary: общо записани в memfd (за капа V4)
esc_buf:     resb 32768           ; ескейпнат текст за yn_prompt (4×MAX_CMD)
log_mo:      resd 1               ; месецът на текущия журнал (ротация)
log_prev:    resb 32              ; име на предишния журнал при ротация
rot_msg:     resb 96              ; маркерът при ротация (директен write, без log_line)
; --- Вълна 2 (REV.3): AEAD ---
enc_key:    resb 32               ; сесиен ключ C→S (KDF: KS0[0..32))
kpoly:      resb 32               ; Poly1305 ключ (KS0[32..64); общ, dir байт в MAC)
ks0:        resb 64               ; KDF scratch (keystroke блок)
kdf_nonce:  resq 1                ; seed_s2c ⊕ seed_c2s
pkt_hdr:    resb 16               ; MAC вход: [dir 1][p 8 LE][L 4 BE][pad 3]
tag_rx:     resb 16               ; получен таг
tag_calc:   resb 16               ; изчислен таг
pkt_len_be: resb 4                ; L по жицата (сурови BE байтове)
pkt_L:      resd 1                ; L (хост ред) за TX пакетирането
pkt_buf:    resb 1044             ; TX пакет: [L 4][ct ≤1024][tag 16]
p_start_tx: resq 1                ; p_s2c в началото на TX съобщение (таг: p_start + k)
up_u0:      resd 1                ; блокове в единица 0 (min(16, N)) — готови в pt_buf
rmsg_n:     resd 1                ; общо блокове на приемащо cmd съобщение
poly_r:     resd 5                ; Poly1305 r (clamped, 5×26-bit)
poly_h:     resd 5                ; Poly1305 accumulator
poly_s:     resd 4                ; s = le128(key[16..32))
ts_y:       resd 1                ; компонентите на локалното време
ts_mo:      resd 1
ts_d:       resd 1
ts_hh:      resd 1
ts_mm:      resd 1
ts_ss:      resd 1

; ============================================================
section .text
; ============================================================
global _start

; ---------- ChaCha20 quarter round (state в [rsp]) ----------
%macro QR 4
    mov     eax, [rsp + 4*%1]
    add     eax, [rsp + 4*%2]
    mov     [rsp + 4*%1], eax
    mov     edx, [rsp + 4*%4]
    xor     edx, eax
    rol     edx, 16
    mov     [rsp + 4*%4], edx
    mov     ecx, [rsp + 4*%3]
    add     ecx, edx
    mov     [rsp + 4*%3], ecx
    mov     eax, [rsp + 4*%2]
    xor     eax, ecx
    rol     eax, 12
    mov     [rsp + 4*%2], eax
    add     eax, [rsp + 4*%1]
    mov     [rsp + 4*%1], eax
    mov     edx, [rsp + 4*%4]
    xor     edx, eax
    rol     edx, 8
    mov     [rsp + 4*%4], edx
    mov     ecx, [rsp + 4*%3]
    add     ecx, edx
    mov     [rsp + 4*%3], ecx
    mov     eax, [rsp + 4*%2]
    xor     eax, ecx
    rol     eax, 7
    mov     [rsp + 4*%2], eax
%endmacro

; SIGACT %1 — инсталира sigact за сигнал %1
%macro SIGACT 1
    mov     eax, SYS_rt_sigaction
    mov     edi, %1
    lea     rsi, [sigact]
    xor     edx, edx
    mov     r10d, 8
    syscall
%endmacro

; ============================================================
; _start
; ============================================================
_start:
    call    print_isom                     ; банерът ИСОМ — първо нещо на екрана
    mov     rax, [rsp]
    cmp     rax, 2
    jl      usage                          ; никакви аргументи

    ; --selftest? — ПРЕДИ изискването за 3 аргумента
    mov     rdi, [rsp + 16]               ; argv[1]
    lea     rsi, [str_selftest]
    mov     ecx, 11
    repe    cmpsb
    jne     .no_selftest
    call    do_selftest                    ; не се връща
.no_selftest:

    ; сканиране на argv: --help/-h/--yn + позиционни (порт, ключ)
    xor     r12d, r12d                     ; брой позиционни
    mov     ebx, 1                         ; argv индекс
.scan_args:
    cmp     rbx, [rsp]                     ; argc
    jae     .args_done
    mov     r13, [rsp + rbx*8 + 8]         ; argv[i]
    mov     rdi, r13
    lea     rsi, [str_help]
    call    streq
    test    eax, eax
    jnz     do_help
    mov     rdi, r13
    lea     rsi, [str_h]
    call    streq
    test    eax, eax
    jnz     do_help
    mov     rdi, r13
    lea     rsi, [str_yn]
    call    streq
    test    eax, eax
    jz      .not_flag
    mov     dword [yn_flag], 1             ; --yn
    jmp     .next
.not_flag:
    cmp     r12d, 2                        ; позиционен (порт/ключ)?
    jae     .next                          ; излишен → игнорирай
    mov     [arg_pos + r12*8], r13
    inc     r12d
.next:
    inc     rbx
    jmp     .scan_args
.args_done:
    cmp     r12d, 2
    jl      usage                          ; липсват порт и/или ключ

    ; порт
    mov     rdi, [arg_pos]
    call    atoi
    cmp     rax, 1
    jb      usage
    cmp     rax, 65535
    ja      usage
    mov     [port], eax

    ; ключ (64 hex → 32B)
    mov     rdi, [arg_pos + 8]             ; позиционен #2
    lea     rsi, [key]
    call    parse_hex64
    test    rax, rax
    js      usage

    ; fd слотовете тръгват "затворени" — иначе при паднала връзка
    ; преди първата команда conn_close би затворил fd 0 (stdin!)
    mov     dword [pipe_r], -1
    mov     dword [pipe_w], -1
    mov     dword [memfd], -1
    mov     dword [up_fd], -1
    mov     dword [get_fd], -1
    mov     dword [log_fd], -1

    ; V8: журнали/качвания — 0644 & ~umask(077) = 0600, само за оператора
    mov     eax, SYS_umask
    mov     edi, 077o
    syscall

    ; лог-файл DD-MM-YYYY_HH-MM-SS.txt в работната директория
    call    log_open

    ; лог: стартов ред — порт, отпечатък на ключа, --yn, TZ
    lea     r14, [tmp32]
    lea     rsi, [lg_start]
    mov     edx, lg_start_len
    call    cp_log
    mov     rdi, r14
    mov     eax, [port]
    call    fmt_dec
    add     r14, rcx
    ; V8: отпечатъкът на ключа си ОТИВА от журнала — излишен отпечатък
    cmp     dword [yn_flag], 0
    lea     rsi, [lg_yn0]
    mov     edx, lg_yn0_len
    jz      .yn_off
    lea     rsi, [lg_yn1]
    mov     edx, lg_yn1_len
.yn_off:
    call    cp_log
    mov     rdi, r14
    mov     eax, TZ_OFFSET / 3600
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_end]
    mov     edx, lg_end_len
    call    cp_log
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line

    ; стек за child-а (mmap, преизползва се)
    mov     eax, SYS_mmap
    xor     edi, edi
    mov     esi, STACK_SIZE
    mov     edx, 3                         ; PROT_READ|PROT_WRITE
    mov     r10d, 0x22 | 0x20000           ; PRIVATE|ANON|STACK
    mov     r8, -1
    xor     r9d, r9d
    syscall
    cmp     rax, -4096
    ja      fatal
    add     rax, STACK_SIZE
    mov     [stack_top], rax

    ; SIGINT/SIGTERM/SIGHUP/SIGQUIT → sig_handler
    ; (SIGPIPE не е нужен: MSG_NOSIGNAL; SIGCHLD се прибира с wait4)
    SIGACT SIGINT
    SIGACT SIGTERM
    SIGACT SIGHUP
    SIGACT SIGQUIT

    ; listener
    mov     eax, SYS_socket
    mov     edi, AF_INET
    mov     esi, SOCK_STREAM | SOCK_CLOEXEC
    xor     edx, edx
    syscall
    test    eax, eax
    js      fatal
    mov     [listen_fd], eax

    mov     eax, SYS_setsockopt
    mov     edi, [listen_fd]
    mov     esi, SOL_SOCKET
    mov     edx, SO_REUSEADDR
    lea     r10, [one]
    mov     r8d, 4
    syscall

    ; sockaddr_in (в .bss = нули): family=2, port BE, addr=ANY
    mov     word [sockaddr], AF_INET
    mov     eax, [port]
    mov     ecx, eax
    and     ecx, 0xff
    shl     ecx, 8                         ; htons ръчно
    shr     eax, 8
    or      ecx, eax
    mov     [sockaddr + 2], cx

    mov     eax, SYS_bind
    mov     edi, [listen_fd]
    lea     rsi, [sockaddr]
    mov     edx, 16
    syscall
    test    eax, eax
    js      fatal_bl                       ; errno=98 (EADDRINUSE) и т.н. — явен съобщение

    mov     eax, SYS_listen
    mov     edi, [listen_fd]
    mov     esi, 1
    syscall
    test    eax, eax
    js      fatal_bl

; ============================================================
; accept_loop — 1 връзка в даден момент
; ============================================================
accept_loop:
    mov     eax, SYS_accept4
    mov     edi, [listen_fd]
    xor     esi, esi
    xor     edx, edx
    mov     r10d, SOCK_CLOEXEC
    syscall
    test    eax, eax
    js      fatal
    mov     [sock_fd], eax

    ; --- пре-auth дедлайн: 3 s общо за salt + първия валиден кадър ---
    ; (клиентът е ИИ агент — човешка латентност не се търпи; мълчалив/дръпващ
    ;  скенер не държи единствения слот; след auth — без лимит)
    mov     dword [authed], 0
    mov     eax, SYS_setsockopt
    mov     edi, [sock_fd]
    mov     esi, SOL_SOCKET
    mov     edx, SO_RCVTIMEO
    lea     r10, [tv_to]
    mov     r8d, 16
    syscall
    mov     eax, SYS_clock_gettime
    mov     edi, 1                         ; CLOCK_MONOTONIC
    lea     rsi, [mono_ts]
    syscall
    mov     rax, [mono_ts]
    add     rax, 3
    mov     [deadline], rax

    ; ЛОГ: от кой IP идва връзката
    mov     dword [peer_len], 16
    mov     eax, SYS_getpeername
    mov     edi, [sock_fd]
    lea     rsi, [sockaddr]
    lea     rdx, [peer_len]
    syscall
    test    eax, eax
    jnz     .no_peer_log
    lea     r14, [tmp32]
    lea     rsi, [lg_conn]
    mov     edx, lg_conn_len
    call    cp_log
    lea     rsi, [sockaddr + 4]             ; sin_addr (4 октета)
    mov     r12d, 4
.ip_oct:
    movzx   eax, byte [rsi]
    mov     rdi, r14
    call    fmt_dec
    add     r14, rcx
    mov     byte [r14], '.'
    inc     r14
    inc     rsi
    dec     r12d
    jnz     .ip_oct
    dec     r14                             ; последната точка → ':'
    mov     byte [r14], ':'
    inc     r14
    movzx   eax, byte [sockaddr + 2]        ; sin_port BE: hi
    shl     eax, 8
    movzx   edx, byte [sockaddr + 3]        ; lo
    or      eax, edx
    movzx   eax, ax
    mov     rdi, r14
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
.no_peer_log:

    ; ---- нашият salt ---- ...не че му имам доверие де...
    mov     eax, SYS_getrandom
    lea     rdi, [salt_tx]
    mov     esi, 64
    xor     edx, edx
    syscall
    cmp     rax, 64
    jne     conn_close

    lea     rdi, [salt_tx]                 ; in-place: src = dst
    mov     rsi, rdi
    lea     rdx, [key]
    mov     rcx, [base_s]
    call    chacha_block

    mov     rax, [salt_tx + 56]            ; seed = последните 8B от ct
    mov     [seed_s2c], rax

    lea     rdi, [salt_tx]
    mov     esi, 64
    call    send_all
    test    rax, rax
    js      conn_close

    ; ---- client salt ----
    lea     rdi, [salt_rx]
    mov     esi, 64
    call    read_full
    test    rax, rax
    jns     .salt_ok
    ; пре-auth провалено: timeout / джънк — логни и двете възможности
    cmp     rax, -110
    jne     .salt_junk
    lea     rsi, [lg_timeout]              ; замълчи 3 s — скенер/полуотворен socket
    mov     edx, lg_timeout_len
    call    log_line
    jmp     conn_close
.salt_junk:
    cmp     dword [rf_got], 0
    jle     .salt_drain
    lea     rdi, [salt_rx]
    mov     esi, [rf_got]
    call    log_junk
.salt_drain:
    call    drain_junk                 ; ВСИЧКИ останали байтове от пиъра (не само 64 B)
.salt_close:
    jmp     conn_close
.salt_ok:
    mov     rax, [salt_rx + 56]
    mov     [seed_c2s], rax

    ; REV.4 KDF: KS0 = ChaCha20(PSK, seed_s2c ⊕ seed_c2s) → enc_key_c2s = KS0[0..32),
    ; kpoly = KS0[32..64). Свежестта става ДВУПОСОЧНА: replay на стари C→S кадри
    ; срещу нова сесия И replay на стар "филм" S→C към клиента (MITM пуска записан
    ; salt_s + стари кадри към жертва със СВЕЖ seed_c2s) носят таг под СТАР kpoly
    ; → пада (V1 + резидуалът §13.2 умират).
    ; (Колизии: seed_s2c = seed_c2s → nonce = 0 — ~2^-64, KS0 си остава тайна;
    ;  KDF-keystream срещу S→C данните (също PSK): seed_s2c⊕seed_c2s = seed_s2c+p
    ;  само при p = (seed_s2c⊕seed_c2s)−seed_s2c ~ uniform 2^64 — недостижимо.)
    mov     rax, [seed_s2c]
    xor     rax, [seed_c2s]
    mov     [kdf_nonce], rax
    lea     rdi, [zeros64]                 ; src (контракт: rdi=src, rsi=dst!)
    lea     rsi, [ks0]                     ; dst → ks0 = keystream ⊕ 0
    lea     rdx, [key]
    mov     rcx, [kdf_nonce]
    call    chacha_block
    xor     ecx, ecx
.kdf_cp:
    mov     al, [ks0 + rcx]
    mov     [enc_key + rcx], al
    mov     al, [ks0 + 32 + rcx]
    mov     [kpoly + rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      .kdf_cp

    ; ЛОГ: ръкостискането мина - "в кавички"
    lea     rsi, [lg_hs]
    mov     edx, lg_hs_len
    call    log_line

    xor     eax, eax
    mov     [p_s2c], rax
    mov     [p_c2s], rax

; ============================================================
; cmd_loop
; ============================================================
cmd_loop:
    call    recv_msg
    test    rax, rax
    js      .recv_fail
    cmp     dword [authed], 0
    jnz     .authed                        ; вече удостоен — без нови syscall-и
    call    auth_now                       ; първата ВАЛИДНА команда = ключът е верен
.authed:
    ; ЛОГ: всяка получена команда (и отказаните!) — преди yn
    lea     rdi, [pt_buf + 4]
    mov     rsi, rax
    call    log_cmd2                       ; → rax = дължината (за yn_prompt)

    ; --yn: потвърждение от оператора преди всяка команда
    cmp     dword [yn_flag], 0
    jz      .no_yn
    lea     rcx, [yn_hdr1]                 ; (rcx е свободен — rax е дължината)
    mov     [yn_h1], rcx
    mov     dword [yn_h1l], yn_hdr1_len
    lea     rcx, [yn_hdr2]
    mov     [yn_h2], rcx
    mov     dword [yn_h2l], yn_hdr2_len
    lea     rdi, [pt_buf + 4]              ; командата (още непокътната)
    mov     rsi, rax                       ; дължина от log_cmd2
    call    yn_prompt
    test    rax, rax
    jns     .yn_allow                      ; y → логни и продължи
    ; ЛОГ: отказано
    lea     rsi, [lg_yn_no]
    mov     edx, lg_yn_no_len
    call    log_line
    mov     edi, 126
    call    log_exit
    ; отказано → съобщение към клиента + END 126; връзката остава жива
    lea     rdi, [yn_deny]
    mov     esi, yn_deny_len
    call    send_msg
    mov     edi, 126
    call    send_end
    jmp     cmd_loop
.yn_allow:
    lea     rsi, [lg_yn_ok]
    mov     edx, lg_yn_ok_len
    call    log_line
    ; продължава към изпълнението
.no_yn:
    lea     rsi, [pt_buf + 4]              ; NUL-terminated команда
    call    parse_cmd
    test    rax, rax
    js      conn_close                     ; няма binary (невалидни данни) → drop

    call    load_binary
    test    rax, rax
    jns     .loaded
    ; грешка при отваряне → DATA + END 127, после следваща команда
    mov     edi, 127
    call    log_exit
    lea     rdi, [str_openfail]
    mov     esi, str_openfail_len
    call    send_msg
    mov     edi, 127
    call    send_end
    jmp     cmd_loop
.loaded:
    call    spawn                           ; връща се след exec на child-а
    test    rax, rax
    js      conn_close

    ; ---- stream: pipe → DATA съобщения ----
.stream:
    xor     eax, eax                       ; SYS_read
    mov     edi, [pipe_r]
    lea     rsi, [io_buf]
    mov     edx, CHUNK
    syscall
    test    rax, rax
    jle     .pipe_eof
    mov     rsi, rax
    lea     rdi, [io_buf]
    call    log_out                        ; ЛОГ: изходът (пази rdi/rsi)
    call    send_msg
    test    rax, rax
    js      conn_close                     ; клиентът си тръгна → cleanup
    jmp     .stream

.pipe_eof:
    mov     eax, SYS_wait4
    mov     edi, [child_pid]
    lea     rsi, [wstatus]
    xor     edx, edx
    xor     r10d, r10d
    syscall
    mov     eax, [wstatus]
    mov     ecx, eax
    and     ecx, 0x7f
    jz      .wexit
    add     ecx, 1000                      ; убит от сигнал
    jmp     .whave
.wexit:
    mov     ecx, eax
    shr     ecx, 8
    and     ecx, 0xff
.whave:
    mov     dword [child_pid], 0
    mov     r12d, ecx                       ; статусът оцелява през syscall
    mov     edi, r12d
    call    log_exit                        ; ЛОГ: exit статус / сигнал
    mov     eax, SYS_close                  ; (syscall прехвърля rcx/r11!)
    mov     edi, [pipe_r]
    syscall
    mov     edi, r12d
    call    send_end
    jmp     cmd_loop

.recv_fail:
    ; пре-auth: логни причината + raw джънка; post-auth: старият път
    cmp     dword [authed], 0
    jne     conn_close
    cmp     rax, -110
    jne     .no_to
    lea     rsi, [lg_timeout]
    mov     edx, lg_timeout_len
    call    log_line
.no_to:
    cmp     dword [rf_got], 0
    jle     .rf_drain
    lea     rdi, [ct_buf]
    mov     esi, [rf_got]
    call    log_junk                       ; каквото пиърът е пратил (hex, ≤64 B)
.rf_drain:
    cmp     dword [rf_err], -110
    je      conn_close                     ; timeout → дупката е празна, няма какво да дреним
    call    drain_junk                     ; ОСТАНАЛИЯТ payload — всички байтове
    jmp     conn_close

; ============================================================
; conn_close — убий/събери ако трябва, затвори всичко, пак accept
; (слотовете с -1 не се пипат — fd 0/1/2 са извън опасност;
;  EBADF при вече затворени е безвреден)
; ============================================================
conn_close:
    ; ЛОГ: краят на връзката (и при грешка по време на handshake)
    lea     rsi, [lg_close]
    mov     edx, lg_close_len
    call    log_line
    mov     edi, [child_pid]
    test    edi, edi
    jz      .nochild
    mov     eax, SYS_kill
    mov     esi, SIGKILL
    syscall
    mov     eax, SYS_wait4
    mov     edi, [child_pid]
    lea     rsi, [wstatus]
    xor     edx, edx
    xor     r10d, r10d
    syscall
    mov     dword [child_pid], 0
.nochild:
    cmp     dword [pipe_r], -1
    je      .no_pipe_r
    mov     eax, SYS_close
    mov     edi, [pipe_r]
    syscall
    mov     dword [pipe_r], -1
.no_pipe_r:
    cmp     dword [pipe_w], -1
    je      .no_pipe_w
    mov     eax, SYS_close
    mov     edi, [pipe_w]
    syscall
    mov     dword [pipe_w], -1
.no_pipe_w:
    cmp     dword [memfd], -1
    je      .no_memfd
    mov     eax, SYS_close
    mov     edi, [memfd]
    syscall
    mov     dword [memfd], -1
.no_memfd:
    ; V6: прекъснато качване НЕ изтича fd (зомби-режимът умира тук)
    cmp     dword [up_fd], -1
    je      .no_upfd
    mov     eax, SYS_close
    mov     edi, [up_fd]
    syscall
    mov     dword [up_fd], -1
.no_upfd:
    cmp     dword [get_fd], -1
    je      .no_getfd
    mov     eax, SYS_close
    mov     edi, [get_fd]
    syscall
    mov     dword [get_fd], -1
.no_getfd:
    mov     eax, SYS_close
    mov     edi, [sock_fd]
    syscall
    jmp     accept_loop

; ============================================================
; do_selftest — ChaCha20(key=0, nonce=0) срещу вектора
; ============================================================
do_selftest:
    lea     rdi, [zeros64]
    lea     rsi, [ct_buf]
    lea     rdx, [zeros64]                 ; ключ = първите 32 нули
    xor     ecx, ecx
    call    chacha_block
    lea     rdi, [ct_buf]
    lea     rsi, [st_vec]
    mov     ecx, 8
.cmp:
    mov     rax, [rdi]
    cmp     rax, [rsi]
    jne     .fail
    add     rdi, 8
    add     rsi, 8
    dec     ecx
    jnz     .cmp
    ; REV.3: Poly1305 (RFC 8439 §2.5.2 — тагът потвърден с `openssl mac`)
    lea     rdi, [poly_kvec]
    lea     rsi, [poly_mvec]
    mov     edx, poly_mvec_len
    lea     rcx, [tag_calc]
    call    poly1305_mac
    lea     rdi, [tag_calc]
    lea     rsi, [poly_tvec]
    mov     ecx, 2
.pcmp:
    mov     rax, [rdi]
    cmp     rax, [rsi]
    jne     .fail
    add     rdi, 8
    add     rsi, 8
    dec     ecx
    jnz     .pcmp
    mov     eax, SYS_write
    mov     edi, 1
    lea     rsi, [st_ok]
    mov     edx, st_ok_len
    syscall
    mov     eax, SYS_exit
    xor     edi, edi
    syscall
.fail:
    mov     eax, SYS_write
    mov     edi, 1
    lea     rsi, [st_fail]
    mov     edx, st_fail_len
    syscall
    mov     eax, SYS_exit
    mov     edi, 1
    syscall

; ============================================================
; print_isom — банерът ИСОМ на stdout (едно write, нищо не пази)
; ============================================================
print_isom:
    mov     eax, SYS_write
    mov     edi, 1
    lea     rsi, [isom_ansi]
    mov     edx, isom_ansi_len
    syscall
    ret

; ============================================================
; do_help — пълната помощ на stdout, exit 0
; ============================================================
do_help:
    mov     eax, SYS_write
    mov     edi, 1
    lea     rsi, [help_msg]
    mov     edx, help_len
    syscall
    mov     eax, SYS_exit
    xor     edi, edi
    syscall

; ============================================================
; streq(rdi, rsi) → eax = 1 равни / 0 различни
; ============================================================
streq:
.l:
    mov     al, [rdi]
    cmp     al, [rsi]
    jne     .no
    test    al, al
    jz      .yes
    inc     rdi
    inc     rsi
    jmp     .l
.yes:
    mov     eax, 1
    ret
.no:
    xor     eax, eax
    ret

; ============================================================
; yn_prompt(rdi = команда, rsi = дължина) → rax = 0 изпълни / -1 откажи
;   Пита оператора на stderr (fd 2), отговора чете от stdin (fd 0).
;   y/Y/д/Д → 0;  n/N/н/Н → -1;  EOF/грешка → -1 (безопасно);  друго → пак пита.
; ============================================================
yn_prompt:
    push    rbx
    push    rbp
    mov     rbx, rdi
    mov     rbp, rsi
    mov     rsi, [yn_h1]
    mov     edx, [yn_h1l]
    call    yn_write
    ; V10: ESC/ctl байтове НЕ стигат сурови до терминала на оператора —
    ; същият рендер като в журнала (\xHH/\n/\t/\r/\e/\0)
    lea     rdi, [esc_buf]
    mov     rcx, ESC_CAP
    call    esc_copy                        ; → r9 = написани (rbx/rbp се пазят)
    lea     rsi, [esc_buf]
    mov     rdx, r9
    call    yn_write
    mov     rsi, [yn_h2]
    mov     edx, [yn_h2l]
    call    yn_write
.read:
    xor     eax, eax                        ; SYS_read
    xor     edi, edi                        ; stdin
    lea     rsi, [yn_ans]
    mov     edx, 63
    syscall
    test    rax, rax
    jle     .deny                           ; EOF/грешка → отказ
    movzx   eax, byte [yn_ans]
    cmp     al, 'y'
    je      .yes
    cmp     al, 'Y'
    je      .yes
    cmp     al, 'n'
    je      .deny
    cmp     al, 'N'
    je      .deny
    cmp     al, 0xD0                        ; кирилица: д/Д/н/Н = D0 xx
    jne     .bad
    movzx   eax, byte [yn_ans + 1]
    cmp     al, 0xB4                        ; д
    je      .yes
    cmp     al, 0x94                        ; Д
    je      .yes
    cmp     al, 0xBD                        ; н
    je      .deny
    cmp     al, 0x9D                        ; Н
    je      .deny
.bad:
    lea     rsi, [yn_more]
    mov     edx, yn_more_len
    call    yn_write
    jmp     .read
.yes:
    lea     rsi, [yn_yes_log]
    mov     edx, yn_yes_len
    call    yn_write
    xor     eax, eax
    jmp     .out
.deny:
    lea     rsi, [yn_no_log]
    mov     edx, yn_no_len
    call    yn_write
    mov     rax, -1
.out:
    pop     rbp
    pop     rbx
    ret

; ------------------------------------------------------------
; yn_write(rsi = buf, rdx = len) — write към stderr
; ------------------------------------------------------------
yn_write:
    mov     eax, SYS_write
    mov     edi, 2
    syscall
    ret

; ============================================================
; chacha_block(rdi=src64, rsi=dst64, rdx=key32, rcx=nonce_qword)
;   dst = ChaCha20(key, nonce, ctr=0) XOR src  (in-place ОК)
;   Първоначален djb вариант: state[12..13]=0, state[14..15]=nonce
; ============================================================
chacha_block:
    push    rbx
    sub     rsp, 128
    ; state в [rsp+0..63], оригинал в [rsp+64..127]
    mov     dword [rsp+0],  0x61707865     ; "expa"
    mov     dword [rsp+4],  0x3320646e     ; "nd 3"
    mov     dword [rsp+8],  0x79622d32     ; "2-by"
    mov     dword [rsp+12], 0x6b206574     ; "te k"
    mov     rax, [rdx]
    mov     [rsp+16], rax
    mov     rax, [rdx+8]
    mov     [rsp+24], rax
    mov     rax, [rdx+16]
    mov     [rsp+32], rax
    mov     rax, [rdx+24]
    mov     [rsp+40], rax
    mov     qword [rsp+48], 0              ; брояч на блоковете = 0
    mov     [rsp+56], rcx                  ; nonce
    ; копие
    mov     rax, [rsp]
    mov     [rsp+64], rax
    mov     rax, [rsp+8]
    mov     [rsp+72], rax
    mov     rax, [rsp+16]
    mov     [rsp+80], rax
    mov     rax, [rsp+24]
    mov     [rsp+88], rax
    mov     rax, [rsp+32]
    mov     [rsp+96], rax
    mov     rax, [rsp+40]
    mov     [rsp+104], rax
    mov     rax, [rsp+48]
    mov     [rsp+112], rax
    mov     rax, [rsp+56]
    mov     [rsp+120], rax
    ; 10 double rounds
    mov     ebx, 10
.rounds:
    QR 0, 4, 8, 12
    QR 1, 5, 9, 13
    QR 2, 6, 10, 14
    QR 3, 7, 11, 15
    QR 0, 5, 10, 15
    QR 1, 6, 11, 12
    QR 2, 7, 8, 13
    QR 3, 4, 9, 14
    dec     ebx
    jnz     .rounds
    ; x[i] += orig[i];  dst[i] = x[i] ^ src[i]   (32-bit — без пренос!)
%assign i 0
%rep 16
    mov     eax, [rsp + 4*i]
    add     eax, [rsp + 64 + 4*i]
    xor     eax, [rdi + 4*i]
    mov     [rsi + 4*i], eax
%assign i i+1
%endrep
    add     rsp, 128
    pop     rbx
    ret


; ============================================================
; REV.3 · Poly1305 (RFC 8439; donna-32, 5×26-bit limbs)
;   Състояние в .bss: poly_r (clamped), poly_s, poly_h.
;   init(rdi = key32) / update(rsi = msg, rdx = len %16==0) /
;   final(rcx = out16) / mac(rdi=key, rsi=msg, rdx=len било какво,
;   rcx=out) — one-shot с падинг на последния непълен chunk.
;   Пази rbx,rbp,r12-r15; цапа rax,rcx,rdx,rsi,rdi,r8-r11.
; ============================================================
poly1305_init:
    ; --- r = le128(key[0..16)) & 0ffffffc0ffffffc0ffffffc0fffffff ---
    mov     eax, [rdi]
    and     eax, 0x03ffffff
    mov     [poly_r], eax
    mov     eax, [rdi]
    shr     eax, 26
    mov     ecx, [rdi + 4]
    shl     ecx, 6
    or      eax, ecx
    and     eax, 0x03ffff03
    mov     [poly_r + 4], eax
    mov     eax, [rdi + 4]
    shr     eax, 20
    mov     ecx, [rdi + 8]
    shl     ecx, 12
    or      eax, ecx
    and     eax, 0x03ffc0ff
    mov     [poly_r + 8], eax
    mov     eax, [rdi + 8]
    shr     eax, 14
    mov     ecx, [rdi + 12]
    shl     ecx, 18
    or      eax, ecx
    and     eax, 0x03f03fff
    mov     [poly_r + 12], eax
    mov     eax, [rdi + 12]
    shr     eax, 8
    and     eax, 0x000fffff                ; кламп: bits 124-127 = 0 (r4 < 2^20)
    mov     [poly_r + 16], eax
    ; --- s = le128(key[16..32)) ---
    mov     eax, [rdi + 16]
    mov     [poly_s], eax
    mov     eax, [rdi + 20]
    mov     [poly_s + 4], eax
    mov     eax, [rdi + 24]
    mov     [poly_s + 8], eax
    mov     eax, [rdi + 28]
    mov     [poly_s + 12], eax
    ; --- h = 0 ---
    mov     dword [poly_h], 0
    mov     dword [poly_h + 4], 0
    mov     dword [poly_h + 8], 0
    mov     dword [poly_h + 12], 0
    mov     dword [poly_h + 16], 0
    ret

; ------------------------------------------------------------
; poly_chunk(rsi = 16B източник, r11d = хайбит 0x01000000 или 0)
;   h += (chunk ‖ 2^128); h *= r   (вътрешна — цапа почти всичко)
; ------------------------------------------------------------
poly_chunk:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 72                        ; d[0..4] u64 @0..39, s1..s4 @40..55, pad buf @56..71
    ; --- h += le-групите на chunk-а ---
    mov     eax, [rsi]
    mov     r8d, eax
    and     r8d, 0x03ffffff
    add     [poly_h], r8d                  ; h0 += t0 & M
    mov     r8d, eax
    shr     r8d, 26
    mov     r12d, [rsi + 4]
    mov     r9d, r12d
    shl     r9d, 6
    or      r8d, r9d
    and     r8d, 0x03ffffff
    add     [poly_h + 4], r8d              ; h1
    mov     r8d, r12d
    shr     r8d, 20
    mov     r13d, [rsi + 8]
    mov     r9d, r13d
    shl     r9d, 12
    or      r8d, r9d
    and     r8d, 0x03ffffff
    add     [poly_h + 8], r8d              ; h2
    mov     r8d, r13d
    shr     r8d, 14
    mov     r14d, [rsi + 12]
    mov     r9d, r14d
    shl     r9d, 18
    or      r8d, r9d
    and     r8d, 0x03ffffff
    add     [poly_h + 12], r8d             ; h3
    mov     r8d, r14d
    shr     r8d, 8
    and     r8d, 0x00ffffff
    or      r8d, r11d                      ; хайбит (пълен chunk) или 0 (падинг)
    add     [poly_h + 16], r8d             ; h4
    ; --- s1..s4 = 5·r1..5·r4 ---
    mov     eax, [poly_r + 4]
    imul    eax, eax, 5
    mov     [rsp + 40], eax
    mov     eax, [poly_r + 8]
    imul    eax, eax, 5
    mov     [rsp + 44], eax
    mov     eax, [poly_r + 12]
    imul    eax, eax, 5
    mov     [rsp + 48], eax
    mov     eax, [poly_r + 16]
    imul    eax, eax, 5
    mov     [rsp + 52], eax
    ; --- d = h × r (25 произведения; h,r < 2^27 → произведения < 2^54) ---
    ; d0 = h0·r0 + h1·s4 + h2·s3 + h3·s2 + h4·s1
    mov     qword [rsp], 0
    mov     eax, [poly_h]
    mov     ecx, [poly_r]
    imul    rcx, rax
    add     [rsp], rcx
    mov     eax, [poly_h + 4]
    mov     ecx, [rsp + 52]
    imul    rcx, rax
    add     [rsp], rcx
    mov     eax, [poly_h + 8]
    mov     ecx, [rsp + 48]
    imul    rcx, rax
    add     [rsp], rcx
    mov     eax, [poly_h + 12]
    mov     ecx, [rsp + 44]
    imul    rcx, rax
    add     [rsp], rcx
    mov     eax, [poly_h + 16]
    mov     ecx, [rsp + 40]
    imul    rcx, rax
    add     [rsp], rcx
    ; d1 = h0·r1 + h1·r0 + h2·s4 + h3·s3 + h4·s2
    mov     qword [rsp + 8], 0
    mov     eax, [poly_h]
    mov     ecx, [poly_r + 4]
    imul    rcx, rax
    add     [rsp + 8], rcx
    mov     eax, [poly_h + 4]
    mov     ecx, [poly_r]
    imul    rcx, rax
    add     [rsp + 8], rcx
    mov     eax, [poly_h + 8]
    mov     ecx, [rsp + 52]
    imul    rcx, rax
    add     [rsp + 8], rcx
    mov     eax, [poly_h + 12]
    mov     ecx, [rsp + 48]
    imul    rcx, rax
    add     [rsp + 8], rcx
    mov     eax, [poly_h + 16]
    mov     ecx, [rsp + 44]
    imul    rcx, rax
    add     [rsp + 8], rcx
    ; d2 = h0·r2 + h1·r1 + h2·r0 + h3·s4 + h4·s3
    mov     qword [rsp + 16], 0
    mov     eax, [poly_h]
    mov     ecx, [poly_r + 8]
    imul    rcx, rax
    add     [rsp + 16], rcx
    mov     eax, [poly_h + 4]
    mov     ecx, [poly_r + 4]
    imul    rcx, rax
    add     [rsp + 16], rcx
    mov     eax, [poly_h + 8]
    mov     ecx, [poly_r]
    imul    rcx, rax
    add     [rsp + 16], rcx
    mov     eax, [poly_h + 12]
    mov     ecx, [rsp + 52]
    imul    rcx, rax
    add     [rsp + 16], rcx
    mov     eax, [poly_h + 16]
    mov     ecx, [rsp + 48]
    imul    rcx, rax
    add     [rsp + 16], rcx
    ; d3 = h0·r3 + h1·r2 + h2·r1 + h3·r0 + h4·s4
    mov     qword [rsp + 24], 0
    mov     eax, [poly_h]
    mov     ecx, [poly_r + 12]
    imul    rcx, rax
    add     [rsp + 24], rcx
    mov     eax, [poly_h + 4]
    mov     ecx, [poly_r + 8]
    imul    rcx, rax
    add     [rsp + 24], rcx
    mov     eax, [poly_h + 8]
    mov     ecx, [poly_r + 4]
    imul    rcx, rax
    add     [rsp + 24], rcx
    mov     eax, [poly_h + 12]
    mov     ecx, [poly_r]
    imul    rcx, rax
    add     [rsp + 24], rcx
    mov     eax, [poly_h + 16]
    mov     ecx, [rsp + 52]
    imul    rcx, rax
    add     [rsp + 24], rcx
    ; d4 = h0·r4 + h1·r3 + h2·r2 + h3·r1 + h4·r0
    mov     qword [rsp + 32], 0
    mov     eax, [poly_h]
    mov     ecx, [poly_r + 16]
    imul    rcx, rax
    add     [rsp + 32], rcx
    mov     eax, [poly_h + 4]
    mov     ecx, [poly_r + 12]
    imul    rcx, rax
    add     [rsp + 32], rcx
    mov     eax, [poly_h + 8]
    mov     ecx, [poly_r + 8]
    imul    rcx, rax
    add     [rsp + 32], rcx
    mov     eax, [poly_h + 12]
    mov     ecx, [poly_r + 4]
    imul    rcx, rax
    add     [rsp + 32], rcx
    mov     eax, [poly_h + 16]
    mov     ecx, [poly_r]
    imul    rcx, rax
    add     [rsp + 32], rcx
    ; --- преноси (donna: d0→d1→d2→d3→d4→(×5)→h0→h1) ---
    mov     r8, [rsp]
    mov     rax, r8
    shr     rax, 26
    and     r8d, 0x03ffffff
    mov     [poly_h], r8d
    add     [rsp + 8], rax
    mov     r8, [rsp + 8]
    mov     rax, r8
    shr     rax, 26
    and     r8d, 0x03ffffff
    mov     [poly_h + 4], r8d
    add     [rsp + 16], rax
    mov     r8, [rsp + 16]
    mov     rax, r8
    shr     rax, 26
    and     r8d, 0x03ffffff
    mov     [poly_h + 8], r8d
    add     [rsp + 24], rax
    mov     r8, [rsp + 24]
    mov     rax, r8
    shr     rax, 26
    and     r8d, 0x03ffffff
    mov     [poly_h + 12], r8d
    add     [rsp + 32], rax
    mov     r8, [rsp + 32]
    mov     rax, r8
    shr     rax, 26
    and     r8d, 0x03ffffff
    mov     [poly_h + 16], r8d
    imul    rax, rax, 5
    add     [poly_h], eax                  ; h0 += 5c
    mov     eax, [poly_h]
    shr     eax, 26
    and     dword [poly_h], 0x03ffffff
    add     [poly_h + 4], eax              ; h1 += c
    add     rsp, 72
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

poly1305_update:
    ; rsi = msg, rdx = len (ЗАДЪЛЖИТЕЛНО %16==0); хайбит = 2^24
    push    r12
    mov     r12, rdx
.u:
    test    r12, r12
    jz      .ud
    mov     r11d, 0x01000000
    call    poly_chunk
    add     rsi, 16
    sub     r12, 16
    jmp     .u
.ud:
    pop     r12
    ret

poly1305_final:
    ; rcx = out16: пълен пренос, -p при h ≥ 2^130-5, +s mod 2^128
    push    r14
    mov     r14, rcx
    ; --- пълен пренос ---
    mov     eax, [poly_h]
    shr     eax, 26
    and     dword [poly_h], 0x03ffffff
    add     [poly_h + 4], eax
    mov     eax, [poly_h + 4]
    shr     eax, 26
    and     dword [poly_h + 4], 0x03ffffff
    add     [poly_h + 8], eax
    mov     eax, [poly_h + 8]
    shr     eax, 26
    and     dword [poly_h + 8], 0x03ffffff
    add     [poly_h + 12], eax
    mov     eax, [poly_h + 12]
    shr     eax, 26
    and     dword [poly_h + 12], 0x03ffffff
    add     [poly_h + 16], eax
    mov     eax, [poly_h + 16]
    shr     eax, 26
    and     dword [poly_h + 16], 0x03ffffff
    imul    eax, eax, 5
    add     [poly_h], eax
    mov     eax, [poly_h]
    shr     eax, 26
    and     dword [poly_h], 0x03ffffff
    add     [poly_h + 4], eax
    ; --- g = h + 5 (сравнение с 2^130-5); стек: g0..g4 @0..19, f0..f4 @20..39 ---
    sub     rsp, 48
    mov     eax, [poly_h]
    add     eax, 5
    mov     r8d, eax
    shr     r8d, 26
    and     eax, 0x03ffffff
    mov     [rsp], eax                     ; g0
    mov     eax, [poly_h + 4]
    add     eax, r8d
    mov     r8d, eax
    shr     r8d, 26
    and     eax, 0x03ffffff
    mov     [rsp + 4], eax                 ; g1
    mov     eax, [poly_h + 8]
    add     eax, r8d
    mov     r8d, eax
    shr     r8d, 26
    and     eax, 0x03ffffff
    mov     [rsp + 8], eax                 ; g2
    mov     eax, [poly_h + 12]
    add     eax, r8d
    mov     r8d, eax
    shr     r8d, 26
    and     eax, 0x03ffffff
    mov     [rsp + 12], eax                ; g3
    mov     eax, [poly_h + 16]
    add     eax, r8d
    sub     eax, 0x04000000                ; g4 = h4 + c - 2^26
    mov     r10d, eax                      ; r10d = g4 (оцелява през f-изчисленията)
    ; mask = (g4 >>u 31) - 1: h < p → g4 < 0 → mask = 0 → избери h
    mov     r8d, eax
    shr     r8d, 31
    sub     r8d, 1                         ; r8d = mask
    mov     r9d, r8d
    not     r9d                            ; ~mask
    mov     eax, [poly_h]
    and     eax, r9d
    mov     ecx, [rsp]
    and     ecx, r8d
    or      eax, ecx
    mov     [rsp + 20], eax                ; f0
    mov     eax, [poly_h + 4]
    and     eax, r9d
    mov     ecx, [rsp + 4]
    and     ecx, r8d
    or      eax, ecx
    mov     [rsp + 24], eax                ; f1
    mov     eax, [poly_h + 8]
    and     eax, r9d
    mov     ecx, [rsp + 8]
    and     ecx, r8d
    or      eax, ecx
    mov     [rsp + 28], eax                ; f2
    mov     eax, [poly_h + 12]
    and     eax, r9d
    mov     ecx, [rsp + 12]
    and     ecx, r8d
    or      eax, ecx
    mov     [rsp + 32], eax                ; f3
    mov     eax, r10d                      ; g4
    and     eax, r8d
    mov     ecx, [poly_h + 16]
    and     ecx, r9d
    or      eax, ecx
    mov     [rsp + 36], eax                ; f4
    ; --- ре-комбинация: h0..h3 = 128-битовият резултат ---
    mov     eax, [rsp + 20]
    mov     ecx, [rsp + 24]
    shl     ecx, 26
    or      eax, ecx                       ; h0
    mov     edx, [rsp + 24]
    shr     edx, 6
    mov     ecx, [rsp + 28]
    shl     ecx, 20
    or      edx, ecx                       ; h1
    mov     ecx, [rsp + 28]
    shr     ecx, 12
    mov     r10d, [rsp + 32]
    shl     r10d, 14
    or      ecx, r10d                      ; h2
    mov     r10d, [rsp + 32]
    shr     r10d, 18
    mov     r11d, [rsp + 36]
    shl     r11d, 8
    or      r10d, r11d                     ; h3
    ; --- + s mod 2^128 (adc верига; преносът отвън се губи) ---
    add     eax, [poly_s]
    adc     edx, [poly_s + 4]
    adc     ecx, [poly_s + 8]
    adc     r10d, [poly_s + 12]
    mov     [r14], eax
    mov     [r14 + 4], edx
    mov     [r14 + 8], ecx
    mov     [r14 + 12], r10d
    add     rsp, 48
    pop     r14
    ret

; ------------------------------------------------------------
; poly1305_mac(rdi = key32, rsi = msg, rdx = len (било какво), rcx = out16)
;   one-shot: init + update (пълните chunk-ове) + падинг на остатъка
;   (n байта ‖ 0x01 ‖ нули — терминът 2^(8n); хайбитът е в него)
; ------------------------------------------------------------
poly1305_mac:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    mov     rbx, rdx                       ; len
    mov     r12, rsi                       ; msg
    mov     r14, rcx                       ; out
    call    poly1305_init
    mov     r13, rbx
    and     r13, -16                       ; пълните байтове
    mov     rsi, r12
    mov     rdx, r13
    call    poly1305_update
    and     rbx, 15                        ; остатък
    jz      .fin
    sub     rsp, 24                        ; 16 B падинг-буфер (+8)
    xor     ecx, ecx
.l:
    cmp     rcx, rbx
    jae     .one
    mov     rax, r12
    add     rax, r13                       ; msg + пълните
    mov     al, [rax + rcx]
    mov     [rsp + rcx], al
    inc     rcx
    jmp     .l
.one:
    mov     byte [rsp + rcx], 1            ; 2^(8·n)
    inc     rcx
.z:
    cmp     rcx, 16
    jae     .pd
    mov     byte [rsp + rcx], 0
    inc     rcx
    jmp     .z
.pd:
    mov     rsi, rsp
    xor     r11d, r11d                     ; без явен хайбит — 0x01 го носи
    call    poly_chunk
    add     rsp, 24
.fin:
    mov     rcx, r14
    call    poly1305_final
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret


; ============================================================
; REV.3 · read_pkt(rdi = dst) → rax = 0/-1, r15d = L (ct байтове)
;   Чете [L u32 BE][ct L B][tag 16B]; санити на L; ИЗЧИСЛЯВА тага
;   (dir='C', p=[p_c2s]) и го сверява ПРЕДИ каквото и да е decrypt.
;   НЕ пипа p_c2s (лидърът в decrypt прави единствения increment).
;   Цапа rax,rcx,rdx,rsi,rdi,r8-r11,r15d; пази rbx,rbp,r12-r14.
; ============================================================
read_pkt:
    push    rbx
    push    rbp
    mov     rbx, rdi                       ; dst
    ; --- L (4 B, явен) ---
    lea     rdi, [pkt_len_be]
    mov     esi, 4
    call    read_full
    test    rax, rax
    js      .fail
    mov     eax, [pkt_len_be]
    bswap   eax
    mov     r15d, eax
    ; --- санити: 64 ≤ L ≤ 1024, L%64 == 0 ---
    cmp     r15d, 64
    jb      .lsan
    cmp     r15d, PKT_MAX
    ja      .lsan
    test    r15d, 63
    jnz     .lsan
    ; --- ct ---
    mov     rdi, rbx
    mov     esi, r15d
    call    read_full
    test    rax, rax
    js      .fail
    ; --- таг ---
    lea     rdi, [tag_rx]
    mov     esi, TAG_LEN
    call    read_full
    test    rax, rax
    js      .fail
    ; --- MAC вход: [dir 'C'][p u64 LE][L u32 BE][pad 3] ---
    lea     rdi, [pkt_hdr]
    mov     byte [rdi], 'C'
    mov     rax, [p_c2s]
    mov     [rdi + 1], rax
    mov     eax, r15d
    bswap   eax
    mov     [rdi + 9], eax
    mov     word [rdi + 13], 0
    mov     byte [rdi + 15], 0
    ; --- очакван таг: split API (hdr и ct са в различни буфери!) ---
    lea     rdi, [kpoly]
    call    poly1305_init
    lea     rsi, [pkt_hdr]
    mov     edx, 16
    call    poly1305_update
    mov     rsi, rbx                       ; ct (dst буферът)
    mov     edx, r15d
    call    poly1305_update
    lea     rcx, [tag_calc]
    call    poly1305_final
    ; --- constant-time сравнение ---
    xor     eax, eax
    xor     ecx, ecx
.cmp:
    mov     dl, [tag_calc + rcx]
    xor     dl, [tag_rx + rcx]
    or      al, dl
    inc     ecx
    cmp     ecx, TAG_LEN
    jb      .cmp
    test    al, al
    jnz     .badtag
    pop     rbp
    pop     rbx
    xor     eax, eax
    ret
.badtag:
    call    log_badtag
    jmp     .fail
.lsan:
    call    log_lsan
.fail:
    mov     rax, -1
    pop     rbp
    pop     rbx
    ret

; ------------------------------------------------------------
; REV.3 · dec_c2s_blk(r12d = j) — дешифровка на блок j:
;   ct_buf+64j → pt_buf+64j с enc_key (сесиен C→S ключ).
;   j%16==0 → leader: nonce = seed_c2s + [p_c2s], p_c2s++ —
;   СЪЩОТО pre-increment p ползва и тагът на пакета (read_pkt).
;   Цапа rax,rcx,rdx,rdi,rsi; пази rbx,rbp,r12-r15.
; ------------------------------------------------------------
dec_c2s_blk:
    mov     rax, r12
    test    al, 15
    jnz     .fb
    mov     rcx, [seed_c2s]                ; leader
    add     rcx, [p_c2s]
    inc     qword [p_c2s]
    jmp     .n
.fb:
    mov     rax, r12
    dec     rax
    shl     rax, 6
    add     rax, 56
    mov     rcx, [ct_buf + rax]            ; feedback: ct[56..64) на предходния блок
.n:
    mov     rax, r12
    shl     rax, 6
    lea     rdi, [ct_buf]
    add     rdi, rax
    lea     rsi, [pt_buf]
    add     rsi, rax
    lea     rdx, [enc_key]
    call    chacha_block
    ret

; ------------------------------------------------------------
; REV.3 · log_badtag — "✂ ОТРЯЗАНО (фалшив таг — пакет N); получен: HH…
;   | ct0: HH… (първите 16 B)" — суровите байтове на нарушителя
; ------------------------------------------------------------
log_badtag:
    cmp     dword [log_fd], 0
    jl      .ret
    push    r14
    lea     rdi, [log_buf]
    call    fmt_ts                         ; rcx = дължина на префикса
    lea     r14, [log_buf]
    add     r14, rcx
    lea     rsi, [lg_tagf]
    mov     edx, lg_tagf_len
    call    cp_log
    mov     rdi, r14
    mov     rax, [p_c2s]
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_tagf2]
    mov     edx, lg_tagf2_len
    call    cp_log
    ; получен таг (16 B hex)
    xor     ecx, ecx
.th:
    movzx   eax, byte [tag_rx + rcx]
    mov     rdi, r14
    call    fmt_hex2
    add     r14, 2
    inc     ecx
    cmp     ecx, TAG_LEN
    jb      .th
    lea     rsi, [lg_tagf3]
    mov     edx, lg_tagf3_len
    call    cp_log
    ; първите 16 B ct
    xor     ecx, ecx
.ch:
    movzx   eax, byte [ct_buf + rcx]
    mov     rdi, r14
    call    fmt_hex2
    add     r14, 2
    inc     ecx
    cmp     ecx, 16
    jb      .ch
    lea     rsi, [lg_tagf4]
    mov     edx, lg_tagf4_len
    call    cp_log
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
    pop     r14
.ret:
    ret

; ------------------------------------------------------------
; REV.3 · log_lsan — "✂ ОТРЯЗАНО (невалиден пакет, L=N B) … | сурови: HH HH HH HH"
; ------------------------------------------------------------
log_lsan:
    cmp     dword [log_fd], 0
    jl      .ret
    push    r14
    lea     rdi, [log_buf]
    call    fmt_ts
    lea     r14, [log_buf]
    add     r14, rcx
    lea     rsi, [lg_lsan]
    mov     edx, lg_lsan_len
    call    cp_log
    mov     rdi, r14
    mov     eax, [pkt_len_be]
    bswap   eax
    mov     eax, eax                       ; u64 (без знаково разширение)
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_lsan2]
    mov     edx, lg_lsan2_len
    call    cp_log
    xor     ecx, ecx
.rh:
    movzx   eax, byte [pkt_len_be + rcx]
    mov     rdi, r14
    call    fmt_hex2
    add     r14, 2
    mov     byte [r14], ' '
    inc     r14
    inc     ecx
    cmp     ecx, 4
    jb      .rh
    dec     r14                            ; последното празно
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
    pop     r14
.ret:
    ret

; ============================================================
; recv_msg() → rax = len / -1 ; данните в pt_buf+4 (NUL-terminated)
;   REV.3: единиците [L][ct][tag] се верифицират и дешифроват
;   блоково (leader/feedback веригата на REV.2 е непипната).
; ============================================================
recv_msg:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    lea     rbx, [pt_buf]
    lea     rbp, [ct_buf]
    ; ---------- единица 0: [L][ct][tag] → ct_buf, verify, decrypt ----------
    mov     rdi, rbp
    call    read_pkt                       ; r15d = L (ct байтове)
    test    rax, rax
    js      .fail
    mov     r13d, r15d
    shr     r13d, 6                        ; u0 = блокове в единица 0
    mov     [up_u0], r13d                  ; за upload пътя (hdr/data от единица 0)
    xor     r12d, r12d                     ; j = глобален блоков индекс
.dl:
    call    dec_c2s_blk                    ; ct_buf+64j → pt_buf+64j (leader: p_c2s++)
    inc     r12d
    dec     r13d
    jnz     .dl
    ; ---------- блок 0 наличен ----------
    mov     eax, [rbx]
    bswap   eax
    test    eax, eax
    jz      .fail                          ; len==0 от client → drop (както REV.2)
    mov     r14d, eax                      ; msg_len
    ; нулевият байт в началото на payload-а = КАЧВАНЕ НА ФАЙЛ
    ; (командите са текст и никога не почват с \0 — колизия е невъзможна)
    cmp     byte [rbx + 4], 0
    jne     .try_get
    mov     [up_msglen], eax               ; do_upload_core чете оттук (r12 вече е j)
    call    auth_now                       ; В3 фикс: тагът мина = ключът доказан —
                                           ; @put-първи сесии умираха на 3 s дедлайна
    call    do_upload_core                 ; обработва всичко: hdr/stream/лог/отговор
    test    rax, rax
    js      .fail                          ; нарушение на протокола → drop
    jmp     .up_alive                      ; връзката е жива → следващата команда
.try_get:
    ; Вълна 3: байт 0x01 = @get — [01][path_len BE16][път]
    cmp     byte [rbx + 4], 1
    jne     .cmd
    cmp     eax, 4099                      ; 3 + max path_len — @get е малко съобщение
    ja      .get_bad
    mov     [get_msglen], eax              ; do_get_core чете оттук
    call    auth_now                       ; тагът мина = ключът доказан (rax е пазен)
    mov     eax, [get_msglen]
    add     eax, 67
    shr     eax, 6
    mov     [rmsg_n], eax                  ; N = общо блокове (както .cmd)
    cmp     r12d, eax
    jae     .get_go                        ; цялото съобщение е в единица 0
.moreg:
    ; следваща единица → ct_buf + 64·j (@get ≤ 65 блока = 4160 B < 16384)
    mov     eax, r12d
    shl     eax, 6
    lea     rdi, [rbp]
    add     rdi, rax
    call    read_pkt
    test    rax, rax
    js      .fail
    mov     r13d, r15d
    shr     r13d, 6
.dl3:
    call    dec_c2s_blk
    inc     r12d
    dec     r13d
    jnz     .dl3
    cmp     r12d, [rmsg_n]
    jb      .moreg
.get_go:
    call    do_get_core
    test    rax, rax
    js      .fail
    jmp     .up_alive
.get_bad:
    ; ✂: @get с невалидна дължина — мълчалив close + доказателство (първите 60 B)
    lea     rsi, [lg_get_bad]
    mov     edx, lg_get_bad_len
    call    log_line
    lea     rdi, [pt_buf + 4]
    mov     esi, 60
    call    log_junk
    jmp     .fail
.cmd:
    cmp     eax, MAX_CMD
    ja      .over_cmd
    add     eax, 67
    shr     eax, 6
    mov     [rmsg_n], eax                  ; N = общо блокове на съобщението
    cmp     r12d, eax
    jae     .done                          ; цялото съобщение е в единица 0
.moreu:
    ; следваща единица → ct_buf + 64·j (cmd ≤ 130 блока = 8320 B < 16384)
    mov     eax, r12d
    shl     eax, 6
    lea     rdi, [rbp]
    add     rdi, rax
    call    read_pkt
    test    rax, rax
    js      .fail
    mov     r13d, r15d
    shr     r13d, 6
.dl2:
    call    dec_c2s_blk
    inc     r12d
    dec     r13d
    jnz     .dl2
    cmp     r12d, [rmsg_n]
    jb      .moreu
.done:
    mov     rax, r14
    add     rax, 4
    mov     byte [rbx + rax], 0            ; NUL на data_len
    mov     rax, r14
    jmp     .out
.over_cmd:
    ; ✂: командата надхвърля 8192 — мълчалив close; доказателство = декларираният
    ; размер + първите 60 B (дешифрирани), преди връзката да падне
    mov     r13d, eax
    lea     r14, [tmp32]
    lea     rsi, [lg_ovcmd]
    mov     edx, lg_ovcmd_len
    call    cp_log
    mov     rdi, r14
    mov     eax, r13d
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_ovcmd2]
    mov     edx, lg_ovcmd2_len
    call    cp_log
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
    lea     rdi, [pt_buf + 4]
    mov     esi, 60
    call    log_junk
    jmp     .fail
.up_alive:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    add     rsp, 8                         ; QA FIX (GLM): изхвърляме return address-а от
                                           ; call recv_msg — иначе всеки upload изтича 8B стек
    jmp     cmd_loop                       ; качването е обработено — следваща команда
.fail:
    movsxd  rax, dword [rf_err]           ; -1 (EOF/нарушение) или -errno (напр. -110 timeout)
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ============================================================
; do_upload_core — приемане на качен файл (payload[0] == 0x00)
;   вход:  rbx = pt_buf (блок 0 дешифриран), rbp = ct_buf, r12d = msg_len
;   изход: rax = 0  — обработено (отговорът е изпратен, връзката жива)
;          rax = -1 — нарушение на протокола → връзката умира
;   формат (след 4B BE дължина на съобщението):
;     [00] [path_len BE16 ≤4096] [път] [size BE64] [данни]
;   size ТРЯБВА да е равен на msg_len - 11 - path_len (строга проверка)
; ============================================================
do_upload_core:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    mov     r12d, [up_msglen]              ; REV.3: recv_msg я записа в .bss
    cmp     r12d, (UP_MAX + 8192)          ; QA FIX (DeepSeek): ранна горна граница —
    ja      .bad                           ; иначе eax+67 wrap-ва при msg_len близо до 2^32
    mov     eax, r12d
    add     eax, 67
    shr     eax, 6
    mov     [up_blocks], eax               ; общо 64B блокове
    mov     dword [up_mode], 0
    mov     dword [up_ion], 0
    mov     qword [up_written], 0

    ; ---- path_len (BE16 при msg[5..7)) ----
    movzx   eax, byte [rbx + 5]
    shl     eax, 8
    movzx   ecx, byte [rbx + 6]
    or      eax, ecx
    test    eax, eax
    jz      .bad
    cmp     eax, 4096
    ja      .bad
    mov     [up_pathlen], eax

    ; ---- дължини: msg_len ≥ 11+path_len; 4+msg_len ≥ 15+path_len ----
    mov     ecx, eax
    add     ecx, 11
    cmp     r12d, ecx
    jb      .bad                           ; няма място за size полето
    add     eax, 15
    mov     [up_hneed], eax                ; 15+path_len (край на хедъра)
    mov     ecx, r12d
    add     ecx, 4
    cmp     ecx, eax
    jb      .bad
    mov     eax, [up_hneed]
    add     eax, 63
    shr     eax, 6
    mov     [up_js], eax                   ; първият чисто-даннов блок

    ; ---- хедър-блоковете [1, js) → pt_buf (size може да е в по-късен блок) ----
    call    up_hdr_read
    test    rax, rax
    js      .out_err

    ; ---- size (BE64 при msg[7+path_len)) ----
    mov     edx, [up_pathlen]
    lea     rdi, [rbx + 7]
    add     rdi, rdx
    mov     rax, [rdi]
    bswap   rax
    mov     [up_size], rax
    mov     ecx, r12d
    sub     ecx, [up_pathlen]
    sub     ecx, 11
    cmp     rax, rcx
    jne     .bad                           ; size ≠ msg_len-11-path_len → нарушение
    mov     rcx, UP_MAX
    cmp     rax, rcx
    ja      .bad

    ; ---- пътят → up_path (+NUL), без вътрешни \0 ----
    mov     ecx, [up_pathlen]
    lea     rsi, [rbx + 7]
    lea     rdi, [up_path]
.pth:
    mov     al, [rsi]
    test    al, al
    jz      .bad
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     ecx
    jnz     .pth
    mov     byte [rdi], 0

    ; ---- данните живеят в msg[dstart, dend) ----
    mov     eax, [up_pathlen]
    add     eax, 15
    mov     [up_dstart], eax
    mov     eax, r12d
    add     eax, 4
    mov     [up_dend], eax

    ; ---- ЛОГ: upload: <път> (<size> B) ----
    lea     r14, [up_reply]
    lea     rsi, [lg_up]
    mov     edx, lg_up_len
    call    cp_log
    lea     rsi, [up_path]
    mov     edx, [up_pathlen]
    call    cp_log
    lea     rsi, [lg_up2]
    mov     edx, lg_up2_len
    call    cp_log
    mov     rdi, r14
    mov     rax, [up_size]
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_up3]
    mov     edx, lg_up3_len
    call    cp_log
    lea     rsi, [up_reply]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line

    ; ---- --yn: операторът решава ПРЕДИ отварянето на файла ----
    cmp     dword [yn_flag], 0
    jz      .no_yn
    lea     rcx, [yn_up1]
    mov     [yn_h1], rcx
    mov     dword [yn_h1l], yn_up1_len
    lea     rcx, [yn_up2]
    mov     [yn_h2], rcx
    mov     dword [yn_h2l], yn_up2_len
    lea     rdi, [up_path]
    mov     esi, [up_pathlen]
    call    yn_prompt
    test    rax, rax
    jns     .yn_allow
    lea     rsi, [lg_yn_no]
    mov     edx, lg_yn_no_len
    call    log_line
    mov     dword [up_mode], 1
    mov     eax, [up_js]
    mov     [up_j], eax
    call    up_recv_loop                   ; дренирай [js, blocks) — веригата синхронна
    lea     rdi, [yn_deny]
    mov     esi, yn_deny_len
    call    send_msg
    mov     edi, 126
    call    send_end
    xor     eax, eax
    jmp     .out
.yn_allow:
    lea     rsi, [lg_yn_ok]
    mov     edx, lg_yn_ok_len
    call    log_line
.no_yn:
    ; ---- отваряне (O_TRUNC: съществуващ файл се презаписва) ----
    mov     eax, SYS_open
    lea     rdi, [up_path]
    mov     esi, 1 | O_CREAT | O_TRUNC | O_CLOEXEC
    mov     edx, 0600o                     ; V8: качените файлове са само за оператора
    syscall
    test    eax, eax
    js      .openfail
    mov     [up_fd], eax

    ; ---- данните от буферираните блокове ([dstart, 64*js)) ----
    call    up_prewrite
    test    rax, rax
    js      .wfail
    ; ---- стрийм на останалите блокове [js, blocks) ----
    mov     eax, [up_js]
    mov     [up_j], eax
    call    up_recv_loop
    test    rax, rax
    js      .stream_bad
    ; ---- flush на остатъка в io_buf ----
    cmp     dword [up_ion], 0
    jz      .flushed
    call    up_flush
    test    rax, rax
    js      .wfail
.flushed:
    mov     eax, SYS_close
    mov     edi, [up_fd]
    syscall
    mov     dword [up_fd], -1
    mov     rax, [up_written]
    cmp     rax, [up_size]
    jne     .wfail_noclose                 ; параноя: не е записано всичко

    ; ---- ЛОГ: upload: OK <size> B ----
    lea     r14, [up_reply]
    lea     rsi, [lg_up_ok]
    mov     edx, lg_up_ok_len
    call    cp_log
    mov     rdi, r14
    mov     rax, [up_size]
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_up_ok2]
    mov     edx, lg_up_ok2_len
    call    cp_log
    lea     rsi, [up_reply]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line

    ; ---- отговор: upload: OK <size> B -> <път> + END 0 ----
    lea     r14, [up_reply]
    lea     rsi, [up_rep_ok]
    mov     edx, up_rep_ok_len
    call    cp_log
    mov     rdi, r14
    mov     rax, [up_size]
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [up_rep_mid]
    mov     edx, up_rep_mid_len
    call    cp_log
    lea     rsi, [up_path]
    mov     edx, [up_pathlen]
    call    cp_log
    lea     rdi, [up_reply]
    mov     rsi, r14                        ; send_msg(rdi=data, rsi=len)!
    sub     rsi, rdi
    call    send_msg
    test    rax, rax
    js      .out_err
    xor     edi, edi
    call    send_end
    xor     eax, eax
    jmp     .out

.stream_bad:
    cmp     dword [up_mode], 0
    jne     .wfail                         ; write грешка (дренирането вече е извършено)
    jmp     .out_err                       ; EOF по средата → връзката умира
.wfail:
    mov     eax, SYS_close
    mov     edi, [up_fd]
    syscall
    mov     dword [up_fd], -1
.wfail_noclose:
    lea     rsi, [lg_up_fail]
    mov     edx, lg_up_fail_len
    call    log_line
    lea     rdi, [lg_up_fail]
    mov     esi, lg_up_fail_len
    call    send_msg
    test    rax, rax
    js      .out_err
    mov     edi, 1
    call    send_end
    xor     eax, eax
    jmp     .out
.openfail:
    lea     rsi, [lg_up_open]
    mov     edx, lg_up_open_len
    call    log_line
    mov     dword [up_mode], 1
    mov     eax, [up_js]
    mov     [up_j], eax
    call    up_recv_loop                   ; дренирай и отговори — връзката живее
    lea     rdi, [lg_up_open]
    mov     esi, lg_up_open_len
    call    send_msg
    test    rax, rax
    js      .out_err
    mov     edi, 1
    call    send_end
    xor     eax, eax
    jmp     .out
.bad:
    lea     rsi, [lg_up_bad]
    mov     edx, lg_up_bad_len
    call    log_line
.out_err:
    mov     rax, -1
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ============================================================
; do_get_core — изпращане на файл на клиента (payload[0] == 0x01)
;   вход:  rbx = pt_buf (единица 0 дешифрирана), rbp = ct_buf
;          get_msglen = msg_len (записан от recv_msg)
;   изход: rax = 0  — обработено (END изпратен, връзката жива)
;          rax = -1 — нарушение на протокола → връзката умира
;   формат (след 4B BE дължина на съобщението):
;     [01] [path_len BE16 ≤4096] [път]
;   path_len ТРЯБВА да е равен на msg_len - 3 (строга проверка, като @put).
;   Отговор: DATA chunkове ≤4096 B + END (0 = OK, 1 = FAIL, 126 = отказ).
;   СЪДЪРЖАНИЕТО НЕ СЕ СЪХРАНЯВА В ЖУРНАЛА — само метаредове (път/размер/статус).
;   Всички пътеки затварят get_fd (+ conn_close като последна защита).
; ============================================================
do_get_core:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    mov     r12d, [get_msglen]
    cmp     r12d, 3
    jb      .bad                           ; не стига дори за [01][plen]
    ; ---- path_len (BE16 при msg[5..7)) ----
    movzx   eax, byte [rbx + 5]
    shl     eax, 8
    movzx   ecx, byte [rbx + 6]
    or      eax, ecx
    test    eax, eax
    jz      .bad
    cmp     eax, 4096
    ja      .bad
    mov     [get_pathlen], eax
    ; ---- строга проверка: path_len == msg_len - 3 ----
    lea     ecx, [rax + 3]
    cmp     ecx, r12d
    jne     .bad

    ; ---- пътят → get_path (+NUL), без вътрешни \0 ----
    mov     ecx, [get_pathlen]
    lea     rsi, [rbx + 7]
    lea     rdi, [get_path]
.gpth:
    mov     al, [rsi]
    test    al, al
    jz      .bad
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     ecx
    jnz     .gpth
    mov     byte [rdi], 0

    ; ---- ЛОГ: "get: <esc път>" (+ ✂ САНИТ при замени) — V7 урокът важи ----
    cmp     dword [log_fd], 0
    js      .log1_done
    lea     rdi, [log_buf]
    call    fmt_ts
    lea     r14, [log_buf]
    add     r14, rcx
    lea     rsi, [lg_get]
    mov     edx, lg_get_len
    call    cp_log
    mov     rdi, r14
    lea     rsi, [get_path]
    mov     edx, [get_pathlen]              ; 32-БИТОВ товар! (rdx дърпаше 4 B от get_path)
    lea     rcx, [log_buf + 16384]
    sub     rcx, r14
    dec     rcx                             ; място и за \n
    call    esc_copy                        ; → rax=екейпнати, r9=написани, r11=кап
    add     r14, r9
    push    rax
    push    r11
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
    pop     r11
    pop     rax
    test    rax, rax
    jz      .log1_done
    push    rax                             ; cp_log (al!) яде rax
    lea     r14, [tmp32]
    lea     rsi, [lg_san]
    mov     edx, lg_san_len
    call    cp_log
    pop     rax
    mov     rdi, r14
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_getsan2]
    mov     edx, lg_getsan2_len
    call    cp_log
    test    r11, r11
    jz      .san1_emit
    lea     rsi, [lg_san3]
    mov     edx, lg_san3_len
    call    cp_log
.san1_emit:
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
.log1_done:

    ; ---- --yn: операторът решава ПРЕДИ отварянето на файла ----
    cmp     dword [yn_flag], 0
    jz      .no_yn
    lea     rcx, [yn_get1]
    mov     [yn_h1], rcx
    mov     dword [yn_h1l], yn_get1_len
    lea     rcx, [yn_get2]
    mov     [yn_h2], rcx
    mov     dword [yn_h2l], yn_get2_len
    lea     rdi, [get_path]
    mov     esi, [get_pathlen]
    call    yn_prompt
    test    rax, rax
    jns     .yn_allow
    lea     rsi, [lg_yn_no]
    mov     edx, lg_yn_no_len
    call    log_line
    mov     edi, 126
    call    send_end                        ; БЕЗ текст — клиентът пише chunks във ФАЙЛ
    xor     eax, eax
    jmp     .out
.yn_allow:
    lea     rsi, [lg_yn_ok]
    mov     edx, lg_yn_ok_len
    call    log_line
.no_yn:
    ; ---- отваряне (само за четене) ----
    mov     eax, SYS_open
    lea     rdi, [get_path]
    mov     esi, O_RDONLY | O_CLOEXEC
    xor     edx, edx
    syscall
    test    eax, eax
    js      .openfail
    mov     [get_fd], eax

    ; ---- fstat: S_ISREG + кап (предварителна проверка) ----
    mov     eax, SYS_fstat
    mov     edi, [get_fd]
    lea     rsi, [get_stat]
    syscall
    test    rax, rax
    js      .statfail
    mov     ax, [get_stat + 24]             ; st_mode
    and     eax, 0170000o                   ; S_IFMT
    cmp     eax, 0100000o                   ; S_IFREG
    jne     .notreg
    mov     rax, [get_stat + 48]            ; st_size
    cmp     rax, UP_MAX
    ja      .toobig

    ; ---- четене → send_msg (съдържанието НЕ минава през log_out!) ----
    mov     qword [get_total], 0
.gread:
    mov     eax, SYS_read
    mov     edi, [get_fd]
    lea     rsi, [io_buf]
    mov     edx, CHUNK
    syscall
    test    rax, rax
    jz      .geof                           ; EOF → успех
    js      .readfail
    mov     rsi, rax                        ; дължина на ТОЗИ chunk
    add     [get_total], rsi
    mov     rax, [get_total]
    cmp     rax, UP_MAX
    ja      .toobig_mid                     ; файлът е пораснал след fstat
    lea     rdi, [io_buf]
    call    send_msg
    test    rax, rax
    js      .out_err                        ; клиентът си тръгна → връзката умира
    jmp     .gread
.geof:
    mov     eax, SYS_close
    mov     edi, [get_fd]
    syscall
    mov     dword [get_fd], -1
    ; ---- ЛОГ: get: OK <total> B ----
    lea     r14, [up_reply]
    lea     rsi, [lg_get_ok]
    mov     edx, lg_get_ok_len
    call    cp_log
    mov     rdi, r14
    mov     rax, [get_total]
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_get_ok2]
    mov     edx, lg_get_ok2_len
    call    cp_log
    lea     rsi, [up_reply]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
    xor     edi, edi
    call    send_end
    xor     eax, eax
    jmp     .out

.statfail:
    mov     eax, SYS_close
    mov     edi, [get_fd]
    syscall
    mov     dword [get_fd], -1
    jmp     .openfail                       ; същият смисъл за оператора/клиента
.notreg:
    mov     eax, SYS_close
    mov     edi, [get_fd]
    syscall
    mov     dword [get_fd], -1
    lea     rsi, [lg_get_irr]
    mov     edx, lg_get_irr_len
    call    log_line
    mov     edi, 1
    call    send_end
    xor     eax, eax
    jmp     .out
.toobig:
    mov     eax, SYS_close
    mov     edi, [get_fd]
    syscall
    mov     dword [get_fd], -1
    jmp     .big_common
.toobig_mid:
    mov     eax, SYS_close
    mov     edi, [get_fd]
    syscall
    mov     dword [get_fd], -1
.big_common:
    lea     rsi, [lg_get_big]
    mov     edx, lg_get_big_len
    call    log_line
    mov     edi, 1
    call    send_end
    xor     eax, eax
    jmp     .out
.readfail:
    mov     eax, SYS_close
    mov     edi, [get_fd]
    syscall
    mov     dword [get_fd], -1
    lea     rsi, [lg_get_rf]
    mov     edx, lg_get_rf_len
    call    log_line
    mov     edi, 1
    call    send_end
    xor     eax, eax
    jmp     .out
.openfail:
    lea     rsi, [lg_get_open]
    mov     edx, lg_get_open_len
    call    log_line
    mov     edi, 1
    call    send_end
    xor     eax, eax
    jmp     .out
.bad:
    lea     rsi, [lg_get_bad]
    mov     edx, lg_get_bad_len
    call    log_line
.out_err:
    mov     rax, -1                         ; get_fd си го затваря conn_close (R6)
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ------------------------------------------------------------
; up_hdr_read (REV.3) — хедър-блоковете [1, up_js) в pt_buf слотовете:
;   блок < up_u0  → ВЕЧЕ дешифровани от recv_msg (единица 0) — пропуск;
;   блок ≥ up_u0  → единици (read_pkt → ct_buf + 64·16m) + dec_c2s_blk.
;   (js ≤ 66 блока → ct_buf + 4288 B < 16384 ✔)
;   rax = 0 / -1 (EOF/грешка)
; ------------------------------------------------------------
up_hdr_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    mov     r12d, 1                        ; j
.h:
    cmp     r12d, [up_js]
    jae     .hd
    cmp     r12d, [up_u0]
    jb      .next                          ; блокът е дешифрован от единица 0
    test    r12b, 15
    jnz     .dec                           ; вътре в единица — ct вече е прочетен
    ; нова единица → ct_buf + 64·j
    mov     eax, r12d
    shl     eax, 6
    lea     rdi, [ct_buf]
    add     rdi, rax
    call    read_pkt
    test    rax, rax
    js      .hfail
.dec:
    call    dec_c2s_blk
.next:
    inc     r12d
    jmp     .h
.hd:
    xor     eax, eax
    jmp     .hout
.hfail:
    mov     rax, -1
.hout:
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ------------------------------------------------------------
; REV.3 · up_cut(rsi = 64B източник, r12d = 64·j) — сечението
;   [dstart, dend) през блока → io_buf (up_append); write грешка →
;   up_mode = 1. Цапа rax,rcx,rdx,rsi,rdi,r14.
; ------------------------------------------------------------
up_cut:
    mov     eax, [up_dstart]
    cmp     eax, r12d
    ja      .f1
    mov     eax, r12d                      ; from = max(dstart, 64j)
.f1:
    mov     r14d, eax
    lea     eax, [r12 + 64]
    mov     ecx, [up_dend]
    cmp     ecx, eax
    jae     .t1
    mov     eax, ecx                       ; to = min(dend, 64j+64)
.t1:
    cmp     eax, r14d
    jbe     .next                          ; to ≤ from → няма данни в блока
    sub     eax, r14d                      ; n байта
    mov     ecx, r14d
    sub     ecx, r12d                      ; офсет в блока
    add     rsi, rcx
    mov     edx, eax
    call    up_append
    test    rax, rax
    jns     .next
    mov     dword [up_mode], 1             ; write грешка → дренирай остатъка
.next:
    ret

; ------------------------------------------------------------
; up_recv_loop (REV.3) — блоковете [up_j, up_blocks):
;   блок < up_u0 → вече дешифрован в pt_buf (единица 0) — само сечение;
;   блок ≥ up_u0 → единици (read_pkt → ФИКСИРАН ct_buf слот ≤1024 B) +
;                  decrypt в up_blk (leader при j%16==0: p_c2s++).
;   up_mode=0: данните → io_buf (up_append), flush при 4096
;   up_mode=1: само дрениране (веригата/броячите остават синхронни)
;   rax = 0 (успех / чисто дрениране) / -1 (write грешка — остатъкът Е
;          дрениран, или EOF — връзката умира)
; ------------------------------------------------------------
up_recv_loop:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r13d, [up_j]
    cmp     r13d, [up_blocks]
    jae     .fin
    ; feedback init (само ако първият wire-блок не е leader — js > 16)
    test    r13b, 15
    jz      .loop
    mov     eax, r13d
    dec     eax
    shl     eax, 6
    add     eax, 56
    mov     rax, [ct_buf + rax]            ; ct на блок (j-1) — още в хедъра
    mov     [up_fb], rax
    jmp     .loop
.loop:
    mov     r13d, [up_j]
    cmp     r13d, [up_blocks]
    jae     .fin
    cmp     r13d, [up_u0]
    jae     .wire
    ; --- блок от единица 0: дешифрован в pt_buf ---
    mov     r12d, r13d
    shl     r12d, 6                        ; 64j
    cmp     dword [up_mode], 0
    jne     .nxt                           ; дрениране — данните вече са прочетени
    lea     rsi, [pt_buf]
    add     rsi, r12
    call    up_cut
    jmp     .nxt
.wire:
    test    r13b, 15
    jnz     .haveu                         ; вътре в текущата единица
    ; --- нова единица: [L][ct][tag] → ct_buf (фиксиран слот) ---
    lea     rdi, [ct_buf]
    call    read_pkt
    test    rax, rax
    js      .netfail
.haveu:
    ; --- decrypt: ct = ct_buf + 64·(j&15) → up_blk (nonce СЛЕД read_pkt!) ---
    mov     eax, r13d
    and     eax, 15
    shl     eax, 6
    lea     rdi, [ct_buf]
    add     rdi, rax
    test    r13b, 15
    jnz     .fb
    mov     rcx, [seed_c2s]                ; leader
    add     rcx, [p_c2s]
    inc     qword [p_c2s]
    jmp     .nn
.fb:
    mov     rcx, [up_fb]
.nn:
    lea     rsi, [up_blk]
    lea     rdx, [enc_key]
    call    chacha_block
    ; feedback: tail на ТОЗИ блок (ct_buf + 64·(j&15) + 56)
    mov     eax, r13d
    and     eax, 15
    shl     eax, 6
    add     rax, 56
    mov     rax, [ct_buf + rax]
    mov     [up_fb], rax
    cmp     dword [up_mode], 0
    jne     .nxt                           ; дрениране — без запис
    mov     r12d, r13d
    shl     r12d, 6                        ; 64j
    lea     rsi, [up_blk]
    call    up_cut
.nxt:
    inc     dword [up_j]
    jmp     .loop
.fin:
    cmp     dword [up_mode], 0
    jne     .err
    xor     eax, eax
    jmp     .out
.netfail:
.err:
    mov     rax, -1
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ------------------------------------------------------------
; up_append(rsi = src, edx = n) → rax = 0/-1
;   копира n байта в io_buf; при пълнеж (4096) — up_flush
; ------------------------------------------------------------
up_append:
    push    rbx
    push    r12
    push    r13
    mov     r12, rsi
    mov     r13d, edx
.l:
    test    r13d, r13d
    jz      .ok
    mov     eax, 4096
    sub     eax, [up_ion]                  ; свободно място
    cmp     eax, r13d
    jbe     .cap
    mov     eax, r13d                      ; min(свободно, n)
.cap:
    mov     ecx, eax
    lea     rdi, [io_buf]
    mov     edx, [up_ion]
    add     rdi, rdx
    mov     r8d, eax                       ; дължината оцелява през .cpl (al се цапа!)
.cpl:
    mov     al, [r12]
    mov     [rdi], al
    inc     r12
    inc     rdi
    dec     ecx
    jnz     .cpl
    add     [up_ion], r8d
    sub     r13d, r8d
    cmp     dword [up_ion], 4096
    jb      .l
    call    up_flush
    test    rax, rax
    js      .out
    jmp     .l
.ok:
    xor     eax, eax
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret

; ------------------------------------------------------------
; up_flush() → rax = 0/-1 — записва io_buf[0..up_ion) на диска
; ------------------------------------------------------------
up_flush:
    push    rbx
    push    r12
    mov     r12d, [up_ion]
    test    r12d, r12d
    jz      .ok
    xor     ebx, ebx                       ; записани до момента
.w:
    mov     eax, SYS_write
    mov     edi, [up_fd]
    lea     rsi, [io_buf]
    add     rsi, rbx
    mov     edx, r12d
    sub     edx, ebx
    syscall
    test    rax, rax
    jle     .fail
    add     rbx, rax
    cmp     ebx, r12d
    jb      .w
    add     [up_written], rbx
    mov     dword [up_ion], 0
.ok:
    xor     eax, eax
    jmp     .out
.fail:
    mov     rax, -1
.out:
    pop     r12
    pop     rbx
    ret

; ------------------------------------------------------------
; up_prewrite — данните от буферираните блокове:
;   [dstart, min(64*up_js, dend)) от pt_buf → io_buf; rax = 0/-1
; ------------------------------------------------------------
up_prewrite:
    mov     eax, [up_js]
    shl     eax, 6
    mov     ecx, [up_dend]
    cmp     ecx, eax
    jae     .cap
    mov     eax, ecx                       ; to = min(64*js, dend)
.cap:
    mov     edx, [up_dstart]
    cmp     edx, eax
    jae     .empty                         ; данните започват след буфера
    mov     ecx, eax
    sub     ecx, edx                       ; n байта
    lea     rsi, [pt_buf]
    add     rsi, rdx
    mov     edx, ecx
    call    up_append
    ret
.empty:
    xor     eax, eax
    ret

; ============================================================
; send_msg(rdi=data, rsi=len) → rax = 0/-1
;   len==0 → END (data сочи 4B статус BE)
; ============================================================
send_msg:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    lea     rbx, [pt_buf]
    lea     rbp, [ct_buf]
    mov     r12, rsi                       ; len
    ; len BE → pt_buf
    mov     eax, esi
    bswap   eax
    mov     [rbx], eax
    ; копирай len?4 байта (END: статусът е данните)
    mov     r13, rdi                       ; src
    mov     r14, r12
    test    r14, r14
    jnz     .cn
    mov     r14, 4
.cn:
    xor     ecx, ecx
.cpl:
    cmp     rcx, r14
    jae     .cpd
    mov     al, [r13 + rcx]
    mov     [rbx + rcx + 4], al
    inc     rcx
    jmp     .cpl
.cpd:
    ; blocks = ceil((len+4)/64), min 1
    mov     rax, r12
    add     rax, 67
    shr     rax, 6
    jnz     .nb
    mov     eax, 1
.nb:
    mov     r15, rax                       ; blocks
    ; zero-pad: [pt+4+copied, pt+64*blocks)
    lea     rax, [rbx + 4]
    add     rax, r14                       ; курсор
    mov     rdx, r15
    shl     rdx, 6
    add     rdx, rbx                       ; край
.zp:
    cmp     rax, rdx
    jae     .zd
    mov     byte [rax], 0
    inc     rax
    jmp     .zp
.zd:
    ; REV.3: p в началото на съобщението — таговете на пакетите са p_start + k
    ; (лидърите по време на шифроването инкрементират p_s2c точно веднъж на пакет)
    mov     rax, [p_s2c]
    mov     [p_start_tx], rax
    ; криптирай блокове
    xor     r14, r14                       ; j
.el:
    cmp     r14, r15
    jae     .ed
    mov     rax, r14
    test    al, 15
    jnz     .efb
    mov     rcx, [seed_s2c]                ; leader
    add     rcx, [p_s2c]
    inc     qword [p_s2c]
    jmp     .en
.efb:
    mov     rax, r14
    dec     rax
    shl     rax, 6
    add     rax, 56
    mov     rcx, [rbp + rax]               ; feedback
.en:
    mov     rax, r14
    shl     rax, 6
    mov     rdi, rbx
    add     rdi, rax
    mov     rsi, rbp
    add     rsi, rax
    lea     rdx, [key]
    call    chacha_block
    inc     r14
    jmp     .el
.ed:
    ; REV.3: пакети [L u32 BE][ct L B][tag 16B] — по 16 блока ct, 1 send на пакет
    shl     r15, 6                         ; total ct байтове
    xor     r14, r14                       ; k (пакетен индекс в съобщението)
.pl:
    mov     rax, r14
    shl     rax, 10
    cmp     rax, r15
    jae     .pd
    mov     rsi, r15
    sub     rsi, rax
    cmp     rsi, 1024
    jbe     .pln
    mov     esi, 1024                      ; L = ct байтове в този пакет
.pln:
    ; --- MAC вход: [dir 'S'][p_start+k u64 LE][L u32 BE][pad 3] ‖ ct ---
    mov     [pkt_L], esi
    mov     byte [pkt_hdr], 'S'
    mov     rax, [p_start_tx]
    add     rax, r14
    mov     [pkt_hdr + 1], rax
    mov     eax, esi
    bswap   eax
    mov     [pkt_hdr + 9], eax
    mov     word [pkt_hdr + 13], 0
    mov     byte [pkt_hdr + 15], 0
    lea     rdi, [kpoly]
    call    poly1305_init
    lea     rsi, [pkt_hdr]
    mov     edx, 16
    call    poly1305_update
    mov     rax, r14
    shl     rax, 10
    lea     rsi, [rbp]
    add     rsi, rax                       ; ct слайсът в ct_buf
    mov     edx, [pkt_L]
    call    poly1305_update
    lea     rcx, [tag_calc]
    call    poly1305_final
    ; --- pkt_buf = [L BE][ct][tag] — ЕДИН send (без Nagle закъснения) ---
    mov     eax, [pkt_L]
    bswap   eax
    lea     rdi, [pkt_buf]
    mov     [rdi], eax
    mov     rax, r14
    shl     rax, 10
    lea     rsi, [rbp]
    add     rsi, rax
    lea     rdi, [pkt_buf + 4]
    mov     ecx, [pkt_L]
.cpc:
    mov     al, [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     ecx
    jnz     .cpc
    xor     ecx, ecx
.tgc:
    mov     al, [tag_calc + rcx]
    mov     [rdi], al
    inc     rdi
    inc     ecx
    cmp     ecx, TAG_LEN
    jb      .tgc
    lea     rdi, [pkt_buf]
    mov     esi, [pkt_L]
    add     esi, 4 + TAG_LEN
    call    send_all
    test    rax, rax
    js      .fail
    inc     r14
    jmp     .pl
.pd:
    xor     eax, eax
    jmp     .out
.fail:
    mov     rax, -1
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ============================================================
; send_end(edi = статус) → END frame
; ============================================================
send_end:
    mov     eax, edi
    bswap   eax
    mov     [status_buf], eax
    lea     rdi, [status_buf]
    xor     esi, esi
    jmp     send_msg

; ============================================================
; read_full(rdi=buf, rsi=n) → rax = 0/-1   (използва [sock_fd])
; ============================================================
read_full:
    push    rbx
    push    rbp
    mov     rbx, rdi
    mov     rbp, rsi
    mov     dword [rf_got], 0              ; статистика за повикващия (дъмпа на джънка)
    mov     dword [rf_err], -1             ; по подразбиране: EOF/грешка без код
    test    rbp, rbp
    jz      .ok
.rf:
    cmp     dword [authed], 0
    jne     .rf_read
    mov     eax, SYS_clock_gettime         ; V5: absolute дедлайн на ВСЕКИ заворот —
    mov     edi, 1                         ; дрип/бавно четене умира ТУК, не само при EAGAIN
    lea     rsi, [mono_ts]
    syscall
    mov     rax, [mono_ts]
    cmp     rax, [deadline]
    jge     .rf_dead
.rf_read:
    xor     eax, eax                       ; SYS_read
    mov     edi, [sock_fd]
    mov     rsi, rbx
    mov     rdx, rbp
    syscall
    test    rax, rax
    jg      .have
    js      .err                           ; <0 = -errno (напр. -11 EAGAIN от SO_RCVTIMEO)
    jmp     .fail                          ; 0 = EOF
.have:
    add     rbx, rax
    add     [rf_got], eax
    sub     rbp, rax
    jnz     .rf
.ok:
    xor     eax, eax
    pop     rbp
    pop     rbx
    ret
.err:
    mov     [rf_err], eax
    cmp     rax, -11                       ; EAGAIN — времето за това четене изтече
    jne     .fail_raw
    cmp     dword [authed], 0
    jne     .fail_raw                      ; post-auth: без дедлайн изобщо
    jmp     .rf                            ; дедлайнът се гледа на върха (.rf)
.rf_dead:
    mov     dword [rf_err], -110           ; ETIMEDOUT (absolute, V5)
.fail_raw:
    movsxd  rax, dword [rf_err]
    pop     rbp
    pop     rbx
    ret
.fail:
    mov     rax, -1
    pop     rbp
    pop     rbx
    ret

; ============================================================
; send_all(rdi=buf, rsi=n) → rax = 0/-1   (MSG_NOSIGNAL — без SIGPIPE)
; ============================================================
send_all:
    push    rbx
    push    rbp
    mov     rbx, rdi
    mov     rbp, rsi
    test    rbp, rbp
    jz      .ok
.sa:
    mov     eax, SYS_sendto
    mov     edi, [sock_fd]
    mov     rsi, rbx
    mov     rdx, rbp
    mov     r10d, MSG_NOSIGNAL
    xor     r8d, r8d
    xor     r9d, r9d
    syscall
    test    rax, rax
    jle     .fail
    add     rbx, rax
    sub     rbp, rax
    jnz     .sa
.ok:
    xor     eax, eax
    pop     rbp
    pop     rbx
    ret
.fail:
    mov     rax, -1
    pop     rbp
    pop     rbx
    ret

; ============================================================
; parse_cmd(rsi = NUL-terminated команда)
;   → bin_path, cwd_ptr, argv_arr[], envp_arr[] (в .bss)
;   → rax = 0/-1 (няма binary). Модифицира стринга in-place.
;   ENV=токени САМО преди binary-то; CWD= → chdir, не е env... тъп UNIX
; ============================================================
parse_cmd:
    mov     qword [bin_path], 0
    mov     qword [cwd_ptr], 0
    mov     qword [argv_cnt], 0
    mov     qword [envp_cnt], 0
    mov     r8, rsi                        ; курсор
.tok:
    movzx   eax, byte [r8]
    cmp     al, ' '
    je      .skip
    cmp     al, 9
    je      .skip
    test    al, al
    jz      .end
    jmp     .found
.skip:
    inc     r8
    jmp     .tok
.found:
    mov     r9, r8                         ; начало на токена
.scan:
    movzx   eax, byte [r8]
    test    al, al
    jz      .classify                      ; край на стринга
    cmp     al, ' '
    je      .cut
    cmp     al, 9
    je      .cut
    inc     r8
    jmp     .scan
.cut:
    mov     byte [r8], 0                   ; терминатор нулев, а не Т800
    inc     r8
.classify:
    cmp     qword [bin_path], 0
    jne     .argv_tok
    ; '=' в токена? (само преди binary-то)
    mov     r10, r9
.findeq:
    movzx   eax, byte [r10]
    test    al, al
    jz      .no_eq
    cmp     al, '='
    je      .has_eq
    inc     r10
    jmp     .findeq
.no_eq:
    mov     [bin_path], r9
    mov     rax, [argv_cnt]
    cmp     rax, 1023
    jae     .tokov
    mov     [argv_arr + rax*8], r9
    inc     qword [argv_cnt]
    jmp     .tok
.has_eq:
    cmp     dword [r9], 0x3D445743        ; "CWD="
    jne     .env_tok
    add     r9, 4
    mov     [cwd_ptr], r9
    jmp     .tok
.env_tok:
    mov     rax, [envp_cnt]
    cmp     rax, 1023
    jae     .tokov
    mov     [envp_arr + rax*8], r9
    inc     qword [envp_cnt]
    jmp     .tok
.argv_tok:
    mov     rax, [argv_cnt]
    cmp     rax, 1023
    jae     .tokov
    mov     [argv_arr + rax*8], r9
    inc     qword [argv_cnt]
    jmp     .tok
.tokov:
    ; V9: >1023 argv/envp → МЪЛЧАЛИВ close без предупреждение към пиъра.
    ; Пълният вход вече е в журнала (log_cmd2, ескейпнат) — тук е само белегът.
    lea     rsi, [lg_over]
    mov     edx, lg_over_len
    call    log_line
    mov     rax, -1
    ret
.end:
    mov     rax, [argv_cnt]
    mov     qword [argv_arr + rax*8], 0
    mov     rax, [envp_cnt]
    mov     qword [envp_arr + rax*8], 0
    cmp     qword [bin_path], 0
    je      .fail
    xor     eax, eax
    ret
.fail:
    mov     rax, -1
    ret

; ============================================================
; load_binary() → rax = 0/-1
;   memfd_create(CLOEXEC|EXEC → CLOEXEC → 0), open, copy, seal
; ============================================================
load_binary: ; late 00's milw0rm vibe in 2026
    mov     eax, SYS_memfd_create
    lea     rdi, [memfd_name]
    mov     esi, MFD_CLOEXEC | MFD_EXEC
    syscall
    cmp     eax, -22
    jne     .have
    mov     esi, MFD_CLOEXEC
    mov     eax, SYS_memfd_create
    lea     rdi, [memfd_name]
    syscall
    cmp     eax, -22
    jne     .have
    xor     esi, esi
    mov     eax, SYS_memfd_create
    lea     rdi, [memfd_name]
    syscall
.have:
    test    eax, eax
    js      .fail
    mov     [memfd], eax
    mov     qword [lb_total], 0

    mov     eax, SYS_open
    mov     rdi, [bin_path]
    mov     esi, O_RDONLY | O_CLOEXEC
    syscall
    test    eax, eax
    js      .fail_close_memfd
    mov     r8d, eax                       ; src fd
.copy:
    xor     eax, eax                       ; SYS_read
    mov     edi, r8d
    lea     rsi, [io_buf]
    mov     edx, CHUNK
    syscall
    test    rax, rax
    jle     .copy_done
    mov     r9, rax
    ; V4: кап на memfd — /dev/zero няма EOF; капата умира ТУК, преди spawn:
    ; дете изобщо не се ражда → agentshell няма какво да килва (и не пада от OOM)
    add     [lb_total], r9
    mov     rax, [lb_total]
    cmp     rax, MEMFD_CAP
    ja      .cap_hit
    xor     r11d, r11d                     ; QA FIX (Luna/Copilot): write_full —
.wl:                                       ; partial write на memfd не губи байтове
    mov     eax, SYS_write
    mov     edi, [memfd]
    lea     rsi, [io_buf]
    add     rsi, r11
    mov     rdx, r9
    sub     rdx, r11
    syscall
    test    rax, rax
    js      .copy_err
    add     r11, rax
    cmp     r11, r9
    jb      .wl
    jmp     .copy
.copy_done:
    test    rax, rax
    js      .copy_err
    mov     eax, SYS_close
    mov     edi, r8d
    syscall
    ; seal (грешка → игнорираме, стари ядра)
    mov     eax, SYS_fcntl
    mov     edi, [memfd]
    mov     esi, F_ADD_SEALS
    mov     edx, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK
    syscall
    xor     eax, eax
    ret
.cap_hit:
    push    r8                             ; r8 = src fd — оцелява през логването
    lea     r14, [tmp32]
    lea     rsi, [lg_cap]
    mov     edx, lg_cap_len
    call    cp_log
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
    pop     r8
    jmp     .copy_err
.copy_err:
    mov     eax, SYS_close
    mov     edi, r8d
    syscall
.fail_close_memfd:
    mov     eax, SYS_close
    mov     edi, [memfd]
    syscall
.fail:
    mov     rax, -1
    ret

; ============================================================
; spawn() → rax = 0/-1
;   pipe2(O_CLOEXEC) + clone(CLONE_VM|CLONE_VFORK|SIGCHLD)
;      p.s. винаги съм се чудил за къв чеп са тея секции...
;           за кво направо не се набухат всички секции в .text
;           и да се набуха RWX ?
;   Child: собственик на СВОЯ стек; чете .bss (parent-ът е
;   замразен до exec/exit → няма race). Никакви close-ове в
;   child-а: всичко е CLOEXEC, освен dup2-натите 0/1/2.
;   Parent: затваря pipe_w и memfd (иначе няма EOF на pipe_r).
; ============================================================
spawn:
    mov     eax, SYS_pipe2
    lea     rdi, [pipe_r]
    mov     esi, O_CLOEXEC
    syscall
    test    eax, eax
    js      .fail

    mov     eax, SYS_clone
    mov     edi, CLONE_VM | CLONE_VFORK | SIGCHLD
    mov     rsi, [stack_top]
    xor     edx, edx
    xor     r10d, r10d
    xor     r8d, r8d
    syscall
    test    eax, eax
    js      .fail_pipe
    jnz     .parent
    ; ---- CHILD: rsp = stack_top, rax = 0 ----
    and     rsp, -16
    call    child_body                     ; не се връща
    mov     eax, SYS_exit                  ; (не би трябвало да се случи)
    mov     edi, 127
    syscall
.parent:
    mov     [child_pid], eax
    mov     eax, SYS_close
    mov     edi, [pipe_w]
    syscall
    mov     eax, SYS_close
    mov     edi, [memfd]
    syscall
    xor     eax, eax
    ret
.fail_pipe:
    mov     eax, SYS_close
    mov     edi, [pipe_r]
    syscall
    mov     eax, SYS_close
    mov     edi, [pipe_w]
    syscall
.fail:
    mov     rax, -1
    ret

; ============================================================
; child_body — само сурови syscalls (споделен mm с parent!)
; ============================================================
child_body:
    ; stdin = /dev/null
    mov     eax, SYS_open
    lea     rdi, [devnull]
    mov     esi, O_RDONLY | O_CLOEXEC
    syscall
    test    eax, eax
    js      .no_stdin
    mov     edi, eax
    xor     esi, esi
    mov     eax, SYS_dup2
    syscall
.no_stdin:
    ; stdout + stderr → общия pipe
    mov     edi, [pipe_w]
    mov     esi, 1
    mov     eax, SYS_dup2
    syscall
    mov     edi, [pipe_w]
    mov     esi, 2
    mov     eax, SYS_dup2
    syscall
    ; cwd
    mov     rdi, [cwd_ptr]
    test    rdi, rdi
    jz      .no_chdir
    mov     eax, SYS_chdir
    syscall
.no_chdir:
    ; exec
    mov     eax, SYS_execveat
    mov     edi, [memfd]
    lea     rsi, [empty]
    lea     rdx, [argv_arr]
    lea     r10, [envp_arr]
    mov     r8d, AT_EMPTY_PATH
    syscall
    ; грешка → "execveat failed errno=N\n" → fd 2 → _exit(127)
    ; ВНИМАВАЙ: CLONE_VM|CLONE_VFORK → child-ът пише в ПАМЕТТА
    ; НА РОДИТЕЛЯ. str_execfail няма NUL, а старият .cp беше
    ; NUL-скан → дръпна и 64-те байта на st_vec (тестовият вектор)
    ; → 86 B в 64 B errno_msg → препълване в yn_flag → сървърът
    ; "замръзваше" на y/n въпрос при --yn: изкл (журналът на mx:
    ; cmd 14:28:04 → "yn: позволено" чак 15:12:49). Сега: копиране
    ; по ДЪЛЖИНА (22+10+1 = 33 макс < 64) + errno в r11d — старият
    ; .cp цапаше AL и div-ът щеше да печата errno & 0xFFFFFF00.
    neg     eax
    mov     r11d, eax                      ; errno на сохр (AL се цапа)
    lea     rdi, [errno_msg]
    lea     rsi, [str_execfail]
    mov     ecx, str_execfail_len
.cp:
    mov     al, [rsi]
    mov     [rdi], al
    inc     rdi
    inc     rsi
    dec     ecx
    jnz     .cp
.cpd:
    mov     eax, r11d                      ; възстанови errno
    mov     r8, rdi                        ; начало на цифрите
    add     rdi, 12                        ; край на scratch
    mov     r9, rdi
    mov     r10d, 10
.dg:
    xor     edx, edx
    div     r10d
    add     dl, '0'
    dec     r9
    mov     [r9], dl
    test    eax, eax
    jnz     .dg
.dc:
    cmp     r9, rdi
    jae     .dd
    mov     al, [r9]
    mov     [r8], al
    inc     r8
    inc     r9
    jmp     .dc
.dd:
    mov     byte [r8], 10
    inc     r8
    lea     rsi, [errno_msg]
    mov     rdx, r8
    sub     rdx, rsi
    mov     eax, SYS_write
    mov     edi, 2
    syscall
    mov     eax, SYS_exit
    mov     edi, 127
    syscall

; ============================================================
; ЛОГ — файл DD-MM-YYYY_HH-MM-SS.txt, един write на ред
; ============================================================

; ------------------------------------------------------------
; cp_log(r14 = курсор, rsi = src, edx = len) → r14 напред
; (цапа rax/rcx; курсорът r14 е callee-save за callers)
; ------------------------------------------------------------
cp_log:
    xor     ecx, ecx
.l:
    cmp     ecx, edx
    jae     .d
    mov     al, [rsi + rcx]
    mov     [r14], al
    inc     r14
    inc     ecx
    jmp     .l
.d:
    ret

; ------------------------------------------------------------
; fmt_dec(rdi = buf, rax = u64) → rcx = брой цифри (без водещи нули)
; ------------------------------------------------------------
fmt_dec:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi
    sub     rsp, 32
    lea     r12, [rsp + 31]                ; пише от края назад
    mov     r13, r12
    mov     rcx, 10
.dl:
    xor     edx, edx
    div     rcx
    add     dl, '0'
    dec     r13
    mov     [r13], dl
    test    rax, rax
    jnz     .dl
.cpl:
    cmp     r13, r12
    jae     .done
    mov     al, [r13]
    mov     [rbx], al
    inc     rbx
    inc     r13
    jmp     .cpl
.done:
    mov     rcx, rbx
    sub     rcx, rdi
    add     rsp, 32
    pop     r13
    pop     r12
    pop     rbx
    ret

; ------------------------------------------------------------
; fmt_dec2(rdi = buf, eax = 0..99) → rcx = 2 (с водеща нула)
; ------------------------------------------------------------
fmt_dec2:
    cmp     eax, 10
    jae     .two
    mov     edx, eax
    add     dl, '0'
    mov     byte [rdi], '0'
    mov     [rdi + 1], dl
    mov     ecx, 2
    ret
.two:
    movzx   eax, al
    jmp     fmt_dec

; ------------------------------------------------------------
; fmt_hex2(rdi = buf, al = байт) → 2 hex символа (дължина винаги 2)
; ------------------------------------------------------------
fmt_hex2:
    movzx   eax, al
    mov     edx, eax
    shr     edx, 4
    movzx   edx, byte [hexd + rdx]
    mov     [rdi], dl
    and     eax, 15
    movzx   eax, byte [hexd + rax]
    mov     [rdi + 1], al
    ret

; ------------------------------------------------------------
; ts_refresh — epoch (UTC) + TZ_OFFSET → ts_d/mo/y/hh/mm/ss
; Датата по Hinnant civil_from_days (всичко unsigned div).
; zashtoto nqkoi kompleksar e smetnal che...
; ... trqbva da broim sekundi :D
; ------------------------------------------------------------
ts_refresh:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 16
    mov     eax, SYS_clock_gettime
    xor     edi, edi                        ; CLOCK_REALTIME
    mov     rsi, rsp                        ; timespec на стека
    syscall
    mov     rax, [rsp]                      ; tv_sec
    add     rsp, 16
    add     rax, TZ_OFFSET
    xor     edx, edx
    mov     rcx, 86400
    div     rcx                             ; rax = дни, rdx = сек_в_деня
    mov     r9, rax
    mov     r8, rdx
    mov     rax, r8
    xor     edx, edx
    mov     rcx, 3600
    div     rcx                             ; rax = hh
    mov     [ts_hh], eax
    mov     rax, rdx
    xor     edx, edx
    mov     rcx, 60
    div     rcx                             ; rax = mm, rdx = ss
    mov     [ts_mm], eax
    mov     [ts_ss], edx
    ; дни → (y, m, d)
    add     r9, 719468
    mov     rax, r9
    xor     edx, edx
    mov     rcx, 146097
    div     rcx                             ; rax = era, rdx = doe
    imul    r10, rax, 400                   ; y = era*400 (+yoe по-долу)
    mov     r11, rdx                        ; doe [0..146096]
    mov     rax, r11
    xor     edx, edx
    mov     rcx, 1460
    div     rcx
    mov     r12, rax                        ; doe/1460
    mov     rax, r11
    xor     edx, edx
    mov     rcx, 36524
    div     rcx
    mov     r13, rax                        ; doe/36524
    mov     rax, r11
    xor     edx, edx
    mov     rcx, 146096
    div     rcx
    mov     r14, rax                        ; doe/146096
    mov     rax, r11
    sub     rax, r12
    add     rax, r13
    sub     rax, r14
    xor     edx, edx
    mov     rcx, 365
    div     rcx                             ; rax = yoe
    add     r10, rax                        ; y
    mov     r15, rax
    ; doy = doe - (365*yoe + yoe/4 - yoe/100)
    mov     rax, r15
    xor     edx, edx
    mov     rcx, 100
    div     rcx
    mov     r12, rax                        ; yoe/100
    mov     rax, r15
    imul    rax, rax, 365
    mov     rdx, r15
    shr     rdx, 2
    add     rax, rdx
    sub     rax, r12
    mov     r13, r11
    sub     r13, rax                        ; doy [0..365]
    ; mp = (5*doy + 2) / 153
    mov     rax, r13
    imul    rax, rax, 5
    add     rax, 2
    xor     edx, edx
    mov     rcx, 153
    div     rcx
    mov     r12, rax                        ; mp [0..11]
    ; d = doy - (153*mp + 2)/5 + 1
    imul    rax, r12, 153
    add     rax, 2
    xor     edx, edx
    mov     rcx, 5
    div     rcx
    mov     r14, r13
    sub     r14, rax
    inc     r14                             ; d
    ; m = mp<10 ? mp+3 : mp-9
    lea     rax, [r12 + 3]
    lea     r15, [r12 - 9]
    cmp     r12, 10
    cmovae  rax, r15                        ; m
    ; y += (m <= 2)
    cmp     eax, 2
    ja      .store
    inc     r10
.store:
    mov     [ts_y], r10d
    mov     [ts_mo], eax
    mov     [ts_d], r14d
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ------------------------------------------------------------
; fmt_ts(rdi = buf) → rcx = 22: "[DD-MM-YYYY HH:MM:SS] "
; ------------------------------------------------------------
fmt_ts:
    push    rbx
    push    r12
    mov     r12, rdi
    mov     rbx, rdi
    call    ts_refresh
    mov     byte [rbx], '['
    inc     rbx
    mov     eax, [ts_d]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], '-'
    inc     rbx
    mov     eax, [ts_mo]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], '-'
    inc     rbx
    mov     eax, [ts_y]
    mov     rdi, rbx
    call    fmt_dec
    add     rbx, rcx
    mov     byte [rbx], ' '
    inc     rbx
    mov     eax, [ts_hh]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], ':'
    inc     rbx
    mov     eax, [ts_mm]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], ':'
    inc     rbx
    mov     eax, [ts_ss]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     word [rbx], '] '
    add     rbx, 2
    mov     rcx, rbx
    sub     rcx, r12
    pop     r12
    pop     rbx
    ret

; ------------------------------------------------------------
; fmt_tsname(rdi = buf) → rcx = 19: "DD-MM-YYYY_HH-MM-SS"
; ------------------------------------------------------------
fmt_tsname:
    push    rbx
    push    r12
    mov     r12, rdi
    mov     rbx, rdi
    call    ts_refresh
    mov     eax, [ts_d]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], '-'
    inc     rbx
    mov     eax, [ts_mo]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], '-'
    inc     rbx
    mov     eax, [ts_y]
    mov     rdi, rbx
    call    fmt_dec
    add     rbx, rcx
    mov     byte [rbx], '_'
    inc     rbx
    mov     eax, [ts_hh]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], '-'
    inc     rbx
    mov     eax, [ts_mm]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], '-'
    inc     rbx
    mov     eax, [ts_ss]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     rcx, rbx
    sub     rcx, r12
    pop     r12
    pop     rbx
    ret

; ------------------------------------------------------------
; log_open — създава лог-файла в CWD (при грешка: stderr + без лог)
; ------------------------------------------------------------
; ------------------------------------------------------------
; log_rotchk — ротация на журнала: месецът е сменен ИЛИ размерът е
;   ≥ ROT_SIZE (250 MB). Маркерът се пише ДИРЕКТНО в новия файл (без
;   log_line — иначе рекурсия през log_buf). Пази ВСИЧКИ регистри.
; ------------------------------------------------------------
log_rotchk:
    push    rax
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    cmp     dword [log_fd], 0
    jl      .pop
    mov     eax, SYS_fstat
    mov     edi, [log_fd]
    sub     rsp, 144                        ; struct stat
    mov     rsi, rsp
    syscall
    cmp     rax, 0
    jl      .sz_done
    mov     rax, [rsp + 48]                 ; st_size
    cmp     rax, ROT_SIZE
    jae     .sz_rot
.sz_done:
    add     rsp, 144
    call    ts_refresh
    mov     eax, [ts_mo]
    cmp     eax, [log_mo]
    jne     .rotate
    jmp     .pop
.sz_rot:
    add     rsp, 144
    jmp     .rotate
.rotate:
    ; старото име → log_prev (NUL-терминирано, макс 31)
    lea     rsi, [log_name]
    lea     rdi, [log_prev]
    xor     rcx, rcx
.rn:
    cmp     rcx, 31
    jae     .rn_done
    mov     al, [rsi + rcx]
    mov     [rdi + rcx], al
    test    al, al
    jz      .rn_done
    inc     rcx
    jmp     .rn
.rn_done:
    mov     byte [rdi + rcx], 0
    mov     eax, SYS_close
    mov     edi, [log_fd]
    syscall
    call    log_open                        ; ново име (ts_refresh+log_mo вътре)
    cmp     dword [log_fd], 0
    jl      .pop                            ; без лог — тихо
    ; маркер в НОВИЯ файл: "=== ротация от <prev> ==="
    lea     r14, [rot_msg]
    lea     rsi, [lg_rot]
    mov     edx, lg_rot_len
    call    cp_log
    lea     rsi, [log_prev]
.rp:
    movzx   eax, byte [rsi]
    test    al, al
    jz      .rp_done
    mov     [r14], al
    inc     r14
    inc     rsi
    jmp     .rp
.rp_done:
    lea     rsi, [lg_rot2]
    mov     edx, lg_rot2_len
    call    cp_log
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [rot_msg]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
.pop:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rax
    ret

; ------------------------------------------------------------
; esc_copy(rdi=dst, rsi=src, rdx=len, rcx=cap)
;   → rax = екейпнати байтове, r9 = написани, r11 = 1 при ударен кап
;   \n→\n  \r→\r  \t→\t  ESC→\e  NUL→\0; други <0x20/0x7F → \xHH;
;   печатаемото и UTF-8 (≥0x80) минават сурово. Без вътрешни call-ове.
; ------------------------------------------------------------
esc_copy:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx
    mov     r13, rcx
    xor     r14d, r14d                      ; replaced
    xor     r9d, r9d                        ; written
    xor     r11d, r11d                      ; cap flag
    test    r12, r12
    jz      .done
.loop:
    test    r13, r13
    jz      .capfl
    movzx   ecx, byte [rbp]
    cmp     cl, 0x20
    jb      .ctl
    cmp     cl, 0x7f
    je      .ctl
    mov     [rbx], cl                       ; сурово (вкл. UTF-8 ≥0x80)
    inc     rbx
    inc     r9
    dec     r13
    jmp     .nxt
.ctl:
    cmp     r13, 4
    jb      .capfl                          ; за \xHH трябват 4 байта място
    inc     r14
    mov     byte [rbx], '\'
    cmp     cl, 10
    je      .e_n
    cmp     cl, 13
    je      .e_r
    cmp     cl, 9
    je      .e_t
    cmp     cl, 0x1b
    je      .e_e
    test    cl, cl
    je      .e_z
    mov     byte [rbx + 1], 'x'             ; \xHH
    mov     eax, ecx
    shr     eax, 4
    movzx   edx, byte [hexd + rax]
    mov     [rbx + 2], dl
    mov     eax, ecx
    and     eax, 15
    movzx   edx, byte [hexd + rax]
    mov     [rbx + 3], dl
    add     rbx, 4
    add     r9, 4
    sub     r13, 4
    jmp     .nxt
.e_n:
    mov     byte [rbx + 1], 'n'
    jmp     .e2
.e_r:
    mov     byte [rbx + 1], 'r'
    jmp     .e2
.e_t:
    mov     byte [rbx + 1], 't'
    jmp     .e2
.e_e:
    mov     byte [rbx + 1], 'e'
    jmp     .e2
.e_z:
    mov     byte [rbx + 1], '0'
.e2:
    add     rbx, 2
    add     r9, 2
    sub     r13, 2
    jmp     .nxt
.nxt:
    inc     rbp
    dec     r12
    jnz     .loop
.done:
    mov     rax, r14
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.capfl:
    mov     r11d, 1
    jmp     .done

log_open:
    push    rbx
    call    ts_refresh
    lea     rdi, [log_name]
    call    fmt_tsname
    lea     rbx, [log_name]
    add     rbx, rcx
    mov     dword [rbx], '.txt'
    mov     byte [rbx + 4], 0
    mov     eax, SYS_open
    lea     rdi, [log_name]
    mov     esi, 1 | O_CREAT | O_APPEND | O_CLOEXEC    ; O_WRONLY|...
    mov     edx, 0600o                     ; V8: 0644 беше вратата на replay-оракула
    syscall
    test    eax, eax
    js      .fail
    mov     [log_fd], eax
    mov     eax, [ts_mo]                   ; ротация: месецът на този журнал
    mov     [log_mo], eax
    pop     rbx
    ret
.fail:
    mov     dword [log_fd], -1
    mov     eax, SYS_write
    mov     edi, 2
    lea     rsi, [log_openfail]
    mov     edx, log_openfail_len
    syscall
    pop     rbx
    ret

; ------------------------------------------------------------
; log_line(rsi = msg, rdx = len) — "[ts] msg\n" с ЕДИН write
; ------------------------------------------------------------
log_line:
    cmp     dword [log_fd], 0
    jl      .ret
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    mov     r12, rsi
    mov     r13, rdx
    call    log_rotchk                      ; месец|250 MB → нов файл (пази r12/r13)
    lea     rdi, [log_buf]
    call    fmt_ts                          ; rcx = дължина на префикса
    lea     rbx, [log_buf]
    add     rbx, rcx
    xor     ecx, ecx
.cp:
    cmp     rcx, r13
    jae     .cpd
    mov     al, [r12 + rcx]
    mov     [rbx], al
    inc     rbx
    inc     rcx
    jmp     .cp
.cpd:
    mov     byte [rbx], 10
    inc     rbx
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, rbx
    sub     rdx, rsi
    syscall
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
.ret:
    ret

; ------------------------------------------------------------
; log_cmd2(rdi = команда, rsi = len) → rax = len
;   "[ts] cmd: <командата>\n" — СЛЕД prefix-а има "cmd: "
; ------------------------------------------------------------
log_cmd2:
    push    r12
    push    r13
    push    r14
    mov     r12, rdi
    mov     r13, rsi
    cmp     dword [log_fd], 0
    js      .out
    lea     rdi, [log_buf]
    call    fmt_ts
    lea     r14, [log_buf]
    add     r14, rcx
    lea     rsi, [lg_cmd]
    mov     edx, lg_cmd_len
    call    cp_log
    ; V7: командата отива в журнала ЕСКЕЙПНАТА — лог-инжекцията умира;
    ; при ≥1 замяма → ✂ САНИТ белег
    mov     rdi, r14
    mov     rsi, r12
    mov     rdx, r13
    lea     rcx, [log_buf + 16384]
    sub     rcx, r14
    dec     rcx                             ; място и за \n
    call    esc_copy                        ; → rax=екейпнати, r9=написани, r11=кап
    add     r14, r9
    push    rax
    push    r11
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
    pop     r11
    pop     rax
    test    rax, rax
    jz      .out
    push    rax                            ; replaced: cp_log (al!) яде rax
    lea     r14, [tmp32]
    lea     rsi, [lg_san]
    mov     edx, lg_san_len
    call    cp_log
    pop     rax
    mov     rdi, r14
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_san2]
    mov     edx, lg_san2_len
    call    cp_log
    test    r11, r11
    jz      .san_emit
    lea     rsi, [lg_san3]
    mov     edx, lg_san3_len
    call    cp_log
.san_emit:
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
.out:
    mov     rax, r13
    pop     r14
    pop     r13
    pop     r12
    ret

; ------------------------------------------------------------
; auth_now — първата валидна команда мина: authed=1 + без SO_RCVTIMEO
; ------------------------------------------------------------
auth_now:
    push    rax                            ; ПАЗИ rax — повикващият го носи към log_cmd2!
    mov     dword [authed], 1
    mov     eax, SYS_setsockopt
    mov     edi, [sock_fd]
    mov     esi, SOL_SOCKET
    mov     edx, SO_RCVTIMEO
    lea     r10, [tv_off]
    mov     r8d, 16
    syscall
    pop     rax
    ret

; ------------------------------------------------------------
; log_junk(rdi = buf, esi = n) — "[ts] джънк (N B): HH HH …" (макс 64 B)
; суровите байтове на пиър, който не говори ЕО-42
; ------------------------------------------------------------
log_junk:
    cmp     dword [log_fd], 0
    jl      .ret
    push    rbx
    push    r12
    push    r14
    mov     rbx, rdi                       ; buf (fmt_ts пази rbx/r12)
    mov     r12d, esi                      ; n
    call    log_rotchk                     ; ротация (пази rax/rbx/r12-r15)
    cmp     r12d, 64
    jbe     .cap
    mov     r12d, 64
.cap:
    test    r12d, r12d
    jle     .pop
    lea     rdi, [log_buf]
    call    fmt_ts                         ; rcx = дължина на префикса
    lea     r14, [log_buf]
    add     r14, rcx
    lea     rsi, [lg_junk]
    mov     edx, lg_junk_len
    call    cp_log
    mov     rdi, r14
    mov     eax, r12d
    call    fmt_dec                        ; rcx = цифри
    add     r14, rcx
    lea     rsi, [lg_junk2]
    mov     edx, lg_junk2_len
    call    cp_log
    xor     ecx, ecx
.hex:
    cmp     ecx, r12d
    jae     .flush
    movzx   eax, byte [rbx + rcx]
    mov     rdi, r14
    call    fmt_hex2                       ; 2 hex символа
    add     r14, 2
    mov     byte [r14], ' '
    inc     r14
    inc     ecx
    jmp     .hex
.flush:
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
.pop:
    pop     r14
    pop     r12
    pop     rbx
.ret:
    ret

; ------------------------------------------------------------
; drain_junk — изсмуква ВСИЧКИ останали (като бившата ти) байтове от sock_fd след
;   пре-auth провал: чете на 64 B стъпки до EOF/EAGAIN/грешка/дедлайн;
;   всеки стъпка → log_junk (hex ред); накрая обобщен ред
;   "джънк общо (N B)" [+ "; дъмпнати първите M B" при отрязане].
;   Кап JUNK_CAP hex-байта на връзка (flood → дискът остама жив),
;   но RULE 9 бие първи: 63 последователни junk четива → мълчалив close.
;   Край: EOF / EAGAIN (3 s мълчание по SO_RCVTIMEO) / грешка / 3 s дедлайн.
;   Пази r14 (cp_log пише през него); стекът е балансиран.
; ------------------------------------------------------------
JUNK_CAP equ 4*1024*1024                ; макс hex-нати байтове на връзка (~13 MB журнал)
drain_junk:
    cmp     dword [log_fd], 0
    jl      .ret
    mov     qword [junk_total], 0
    mov     qword [junk_dmpd], 0
    mov     dword [junk_chunks], 0
.dj:
    xor     eax, eax                       ; SYS_read
    mov     edi, [sock_fd]
    lea     rsi, [junk_buf]
    mov     edx, 64
    syscall
    test    rax, rax
    jg      .have
    jmp     .done                          ; 0 = EOF / <0 = EAGAIN или грешка → край
.have:
    push    rax
    add     [junk_total], rax
    call    log_rotchk                     ; пази rax; ротация при дълъг дрейн
    inc     dword [junk_chunks]
    mov     rcx, [junk_dmpd]
    cmp     rcx, JUNK_CAP
    jae     .nodump                        ; над капа — само броим, без hex
    mov     esi, eax                       ; n (<=64; log_junk сам капира)
    lea     rdi, [junk_buf]
    call    log_junk
    pop     rcx
    add     [junk_dmpd], rcx
    cmp     dword [junk_chunks], JUNK63
    jae     .done                          ; RULE 9: 63 junk четива → край
    jmp     .tick
.nodump:
    pop     rcx
.tick:
    mov     eax, SYS_clock_gettime
    mov     edi, 1                         ; CLOCK_MONOTONIC
    lea     rsi, [mono_ts]
    syscall
    mov     rax, [mono_ts]
    cmp     rax, [deadline]
    jge     .done                          ; 3 s пре-auth дедлайн важи и тук (flood не държи слота вечно)
    jmp     .dj
.done:
    cmp     qword [junk_total], 0
    je      .ret                           ; нищо ново — 64 B редът на caller-а стига
    lea     rdi, [log_buf]
    call    fmt_ts                         ; rcx = дължина на префикса
    lea     r14, [log_buf]
    add     r14, rcx
    lea     rsi, [lg_jtot]
    mov     edx, lg_jtot_len
    call    cp_log
    mov     rdi, r14
    mov     rax, [junk_total]
    call    fmt_dec                        ; rcx = цифри
    add     r14, rcx
    mov     rax, [junk_dmpd]
    cmp     rax, [junk_total]
    jae     .simple                        ; всичко е дъмпнато → без отрязка
    lea     rsi, [lg_jtot2]
    mov     edx, lg_jtot2_len
    call    cp_log
    mov     rdi, r14
    mov     rax, [junk_dmpd]
    call    fmt_dec
    add     r14, rcx
.simple:
    lea     rsi, [lg_jend]
    mov     edx, lg_jend_len
    call    cp_log
.flush:
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
    cmp     dword [junk_chunks], JUNK63
    jb      .ret
    lea     r14, [tmp32]
    lea     rsi, [lg_jcut]
    mov     edx, lg_jcut_len
    call    cp_log
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
.ret:
    ret

; ------------------------------------------------------------
; log_out(rdi = buf, rsi = len) — суровият изход на командата
;   управл. символи (<0x20 освен \n,\t; 0x7F) → \xHH; UTF-8 минава
;   ПАЗИ rdi/rsi (caller-ът send_msg ги ползва веднага след това)
; ------------------------------------------------------------
log_out:
    cmp     dword [log_fd], 0
    jl      .ret
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    mov     rbx, rdi
    mov     rbp, rsi
    lea     r14, [log_buf]
    xor     r12, r12
.l:
    cmp     r12, rbp
    jae     .flush
    ; място в буфера? (esc = 4B, raw = 1B → резерв ≥8)
    lea     rax, [log_buf + 16376]
    cmp     r14, rax
    jb      .room
    call    .do_flush
.room:
    movzx   r13d, byte [rbx + r12]
    cmp     r13b, 10
    je      .raw
    cmp     r13b, 9
    je      .raw
    cmp     r13b, 0x20
    jb      .esc
    cmp     r13b, 0x7f
    je      .esc
.raw:
    mov     [r14], r13b
    inc     r14
    jmp     .next
.esc:
    mov     byte [r14], '\'
    mov     byte [r14 + 1], 'x'
    movzx   eax, r13b
    shr     eax, 4
    movzx   edx, byte [hexd + rax]
    mov     [r14 + 2], dl
    movzx   eax, r13b
    and     eax, 15
    movzx   edx, byte [hexd + rax]
    mov     [r14 + 3], dl
    add     r14, 4
.next:
    inc     r12
    jmp     .l
.flush:
    ; ако не завършва на \n → добави (за чистота на редовете)
    lea     rax, [log_buf]
    cmp     r14, rax
    je      .emit
    cmp     byte [r14 - 1], 10
    je      .emit
    mov     byte [r14], 10
    inc     r14
.emit:
    lea     rax, [log_buf]
    cmp     r14, rax
    jbe     .done
    call    .do_flush
.done:
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
.ret:
    ret
.do_flush:
    push    rdi                             ; caller-ът (send_msg) чака
    push    rsi                             ; същите rdi/rsi след нас!
    call    log_rotchk                      ; ротация при голям изход
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
    lea     r14, [log_buf]
    pop     rsi
    pop     rdi
    ret

; ------------------------------------------------------------
; log_exit(edi = статус) — "exit: N" или "exit: убит от сигнал N"
; ------------------------------------------------------------
log_exit:
    push    r13
    push    r14
    mov     r13d, edi
    lea     r14, [tmp32]
    lea     rsi, [lg_exit]
    mov     edx, lg_exit_len
    call    cp_log
    cmp     r13d, 1000
    jb      .num
    lea     rsi, [lg_sig]
    mov     edx, lg_sig_len
    call    cp_log
    mov     eax, r13d
    sub     eax, 1000
    jmp     .dec
.num:
    mov     eax, r13d
.dec:
    mov     rdi, r14
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
    pop     r14
    pop     r13
    ret

; ------------------------------------------------------------
; sig_restore — restorer на signal frame (SA_RESTORER).
; sig_handler никога не се връща (exit_group), но на x86-64 ядрото
; изисква валиден restorer още при доставката на сигнала: без
; SA_RESTORER setup_rt_frame се проваля → force_sigsegv → процесът
; умира със SIGSEGV при ПЪРВИЯ сигнал (напр. Ctrl+C).
; ------------------------------------------------------------
sig_restore:
    mov     eax, SYS_rt_sigreturn
    syscall

; ============================================================
; sig_handler(rdi = сигнал) — убий child, излез
; ============================================================
sig_handler:
    mov     r13d, edi                       ; сигналът (rdi от ядрото)
    ; ЛОГ: изключване — сглоби "=== изключване (сигнал N) ==="
    lea     r14, [tmp32]
    lea     rsi, [lg_down1]
    mov     edx, lg_down1_len
    call    cp_log
    mov     rdi, r14
    movzx   eax, r13b
    call    fmt_dec
    add     r14, rcx
    lea     rsi, [lg_down2]
    mov     edx, lg_down2_len
    call    cp_log
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
    mov     edi, [child_pid]
    test    edi, edi
    jz      .die
    lea     rsi, [lg_childkill]
    mov     edx, lg_childkill_len
    call    log_line
    mov     eax, SYS_kill
    mov     esi, SIGKILL
    syscall
.die:
    mov     eax, SYS_exit_group
    xor     edi, edi
    syscall

; ============================================================
; atoi(rdi = str) → rax = число / -1
; ============================================================
atoi:
    xor     rax, rax                       ; QA FIX (Qwen/Luna): 64-битова акумулация —
.l:                                        ; 32-bit wrap правеше 20-цифрен вход валиден порт
    movzx   edx, byte [rdi]
    test    dl, dl
    jz      .ok
    sub     dl, '0'
    cmp     dl, 9
    ja      .bad
    imul    rax, rax, 10
    add     rax, rdx
    mov     ecx, 0xFFFFFFFF
    cmp     rax, rcx
    ja      .bad                           ; overflow guard — отказвай, не wrap-вай
    inc     rdi
    jmp     .l
.ok:
    ret
.bad:
    mov     rax, -1
    ret

; ============================================================
; parse_hex64(rdi = 64 hex символа, rsi = 32B изход) → rax 0/-1
; ============================================================
parse_hex64:
    xor     ecx, ecx
.bl:
    cmp     ecx, 32
    jae     .ok
    movzx   eax, byte [rdi]
    call    hexnib
    cmp     eax, 16
    jae     .bad
    shl     eax, 4
    mov     r8d, eax
    movzx   eax, byte [rdi + 1]
    call    hexnib
    cmp     eax, 16
    jae     .bad
    or      eax, r8d
    mov     [rsi + rcx], al
    add     rdi, 2
    inc     rcx
    jmp     .bl
.ok:
    xor     eax, eax
    ret
.bad:
    mov     rax, -1
    ret

; ============================================================
; hexnib(eax = символ) → eax = 0..15 / 16 при грешка
; ============================================================
hexnib:
    cmp     al, '9'
    jbe     .dig
    and     al, 0xdf                        ; → главни
    cmp     al, 'A'
    jb      .bad
    sub     al, 'A' - 10
    cmp     al, 15
    ja      .bad
    movzx   eax, al
    ret
.dig:
    sub     al, '0'
    cmp     al, 9
    ja      .bad
    movzx   eax, al
    ret
.bad:
    mov     eax, 16
    ret

; ============================================================
usage:
    mov     eax, SYS_write
    mov     edi, 2
    lea     rsi, [usage_msg]
    mov     edx, usage_len
    syscall
    mov     eax, SYS_exit
    mov     edi, 1
    syscall

fatal:
    lea     rsi, [lg_fatal]
    mov     edx, lg_fatal_len
    call    log_line
    mov     eax, SYS_write                 ; и на stderr — операторът го вижда в screen
    mov     edi, 2
    lea     rsi, [lg_fatal]
    mov     edx, lg_fatal_len
    syscall
    mov     eax, SYS_exit
    mov     edi, 1
    syscall

; bind()/listen() провал: явен съобщение с errno — на stderr И в журнала,
; после exit 1. (rax = -errno при скока)
fatal_bl:
    neg     eax
    mov     r12d, eax                      ; errno (положително)
    lea     r14, [tmp32]
    lea     rsi, [lg_blfail]
    mov     edx, lg_blfail_len
    call    cp_log
    mov     rdi, r14
    mov     eax, r12d
    call    fmt_dec                        ; rcx = цифри
    add     r14, rcx
    lea     rsi, [lg_blhint]
    mov     edx, lg_blhint_len
    call    cp_log
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write                 ; STDERR — човекът да го види веднага
    mov     edi, 2
    lea     rsi, [tmp32]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
    lea     rsi, [tmp32]                   ; ЖУРНАЛ (с [ts])
    mov     rdx, r14
    sub     rdx, rsi
    call    log_line
    mov     eax, SYS_exit
    mov     edi, 1
    syscall


