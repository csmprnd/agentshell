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
;   ./agentshell &lt;port&gt; &lt;hex_key_64&gt;
;   ./agentshell --selftest
;
; Протокол ЕО-42 (wire v1 — непроменен; детайли: README REV. 2, §3–§7):
;   salt 64B (ChaCha20(key, BASE_dir) XOR random64; seed = ct[56..63])
;   съобщение = [len u32 BE][data] zero-pad до %64
;   пакет = ≤16 блока (1024B), 1 send()
;   nonce: j%16==0 → seed_dir + p (p = брояч пакети, uint64, не се
;          нулира между съобщения); иначе → ct предходен блок [56..64)
;   len==0 от client → drop; len==0 от server → END (status в data)
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
; ---------- константи ----------
%define AF_INET        2
%define SOCK_STREAM    1
%define SOCK_CLOEXEC   0x80000
%define MSG_NOSIGNAL   0x4000
%define SOL_SOCKET     1
%define SO_REUSEADDR   2
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
              incbin &quot;ISOM.ANSI&quot;           ; самият арт (UTF-8, завършва с \n)
              db 10                        ; празен ред след арта
isom_ansi_len equ $ - isom_ansi
devnull:      db &quot;/dev/null&quot;,0
empty:        db 0
memfd_name:   db &quot;payload&quot;,0
str_selftest: db &quot;--selftest&quot;,0
str_openfail: db &quot;cannot open binary&quot;,10
str_openfail_len equ $ - str_openfail
st_ok:        db &quot;selftest OK&quot;,10
st_ok_len     equ $ - st_ok
st_fail:      db &quot;selftest FAIL&quot;,10
st_fail_len   equ $ - st_fail
usage_msg:    db &quot;usage: agentshell &lt;port&gt; &lt;hex_key_64&gt; [--yn] | --selftest | --help&quot;,10
usage_len     equ $ - usage_msg
str_help:     db &quot;--help&quot;,0
str_h:        db &quot;-h&quot;,0
str_yn:       db &quot;--yn&quot;,0
help_msg:     db 10
              db &quot;ЕО-42 · agentshell — криптиран remote-exec сървър (x86-64, без libc)&quot;,10,10
              db &quot;употреба:&quot;,10
              db &quot;  agentshell &lt;port&gt; &lt;hex_key_64&gt; [--yn]&quot;,10
              db &quot;  agentshell --selftest | --help&quot;,10,10
              db &quot;аргументи:&quot;,10
              db &quot;  &lt;port&gt;        TCP порт (1-65535)&quot;,10
              db &quot;  &lt;hex_key_64&gt;  64 hex символа = 32B pre-shared ключ (openssl rand -hex 32)&quot;,10,10
              db &quot;флагове:&quot;,10
              db &quot;  --yn        преди всяка команда пита в конзолата (stderr):&quot;,10
              db &quot;                агентът се опитва да изпълни команда: &lt;cmd&gt;&quot;,10
              db &quot;                да се изпълни ли? y/n&quot;,10
              db &quot;              y/Y/д/Д = изпълни;  n/N/н/Н = отказ (клиентът получава&quot;,10
              db &quot;              exit 126);  EOF от stdin = отказ (безопасно)&quot;,10
              db &quot;  --selftest  ChaCha20 векторен тест и изход&quot;,10
              db &quot;  --help      този текст&quot;,10,10
              db &quot;лог: при всяко пускане се създава DD-MM-YYYY_HH-MM-SS.txt&quot;,10
              db &quot;              в текущата директория — пълен одит (връзки, команди,&quot;,10
              db &quot;              y/n решения, изход, статуси, изключване)&quot;,10,10
              db &quot;upload: съобщение, започващо с нулев байт = запис на файл:&quot;,10
              db &quot;        [00][дълж.на пътя BE16 ≤4096][път][размер BE64][данни]&quot;,10
              db &quot;        директорията трябва да съществува; съществуващ файл се&quot;,10
              db &quot;        презаписва (O_TRUNC); размер ≤1GB; --yn пита и за това&quot;,10,10
              db &quot;клиент:  agentshell.py &lt;host&gt; &lt;port&gt; &lt;hex_key_64&gt; [--yn]&quot;,10
              db &quot;протокол: ЕО-42 — виж README.md&quot;,10
help_len      equ $ - help_msg
yn_hdr1:      db 10,&quot;[agentshell] агентът се опитва да изпълни команда:&quot;,10,&quot;  &quot;
yn_hdr1_len   equ $ - yn_hdr1
yn_hdr2:      db 10,&quot;да се изпълни ли? y/n: &quot;
yn_hdr2_len   equ $ - yn_hdr2
yn_more:      db &quot;отговори y или n: &quot;
yn_more_len   equ $ - yn_more
yn_yes_log:   db &quot;[agentshell] позволено от оператора&quot;,10
yn_yes_len    equ $ - yn_yes_log
yn_no_log:    db &quot;[agentshell] отказано от оператора&quot;,10
yn_no_len     equ $ - yn_no_log
yn_deny:      db &quot;[agentshell] отказано от оператора (y/n)&quot;,10
yn_deny_len   equ $ - yn_deny

; ---------- качване (съобщение, започващо с нулев байт) ----------
lg_up:        db &quot;upload: &quot;
lg_up_len     equ $ - lg_up
lg_up2:       db &quot; (&quot;
lg_up2_len    equ $ - lg_up2
lg_up3:       db &quot; B)&quot;
lg_up3_len    equ $ - lg_up3
lg_up_ok:     db &quot;upload: OK &quot;
lg_up_ok_len  equ $ - lg_up_ok
lg_up_ok2:    db &quot; B&quot;
lg_up_ok2_len equ $ - lg_up_ok2
lg_up_fail:   db &quot;upload: FAIL — грешка при запис&quot;
lg_up_fail_len equ $ - lg_up_fail
lg_up_open:   db &quot;upload: FAIL — файлът не се отваря&quot;
lg_up_open_len equ $ - lg_up_open
lg_up_bad:    db &quot;upload: невалидно съобщение — прекъсвам&quot;
lg_up_bad_len equ $ - lg_up_bad
up_rep_ok:    db &quot;upload: OK &quot;
up_rep_ok_len equ $ - up_rep_ok
up_rep_mid:   db &quot; B -&gt; &quot;
up_rep_mid_len equ $ - up_rep_mid
yn_up1:       db 10,&quot;[agentshell] агентът иска да запише файл:&quot;,10,&quot;  &quot;
yn_up1_len    equ $ - yn_up1
yn_up2:       db 10,&quot;да се запише ли? y/n: &quot;
yn_up2_len    equ $ - yn_up2

; ---------- лог ----------
log_suffix:   db &quot;.txt&quot;,0
hexd:         db &quot;0123456789abcdef&quot;
log_openfail: db &quot;[agentshell] лог-файл не се създаде — продължавам без лог&quot;,10
log_openfail_len equ $ - log_openfail
lg_start:     db &quot;=== agentshell стартира — порт &quot;
lg_start_len  equ $ - lg_start
lg_key:       db &quot;, ключ &quot;
lg_key_len    equ $ - lg_key
lg_yn1:       db &quot;, --yn: вкл, TZ=UTC+&quot;
lg_yn1_len    equ $ - lg_yn1
lg_yn0:       db &quot;, --yn: изкл, TZ=UTC+&quot;
lg_yn0_len    equ $ - lg_yn0
lg_end:       db &quot; ===&quot;
lg_end_len    equ $ - lg_end
lg_conn:      db &quot;+ връзка от &quot;
lg_conn_len   equ $ - lg_conn
lg_hs:        db &quot;handshake OK (ЕО-42)&quot;
lg_hs_len     equ $ - lg_hs
lg_cmd:       db &quot;cmd: &quot;
lg_cmd_len    equ $ - lg_cmd
lg_yn_ok:     db &quot;yn: позволено от оператора&quot;
lg_yn_ok_len  equ $ - lg_yn_ok
lg_yn_no:     db &quot;yn: отказано от оператора&quot;
lg_yn_no_len  equ $ - lg_yn_no
lg_exit:      db &quot;exit: &quot;
lg_exit_len   equ $ - lg_exit
lg_sig:       db &quot;убит от сигнал &quot;
lg_sig_len    equ $ - lg_sig
lg_close:     db &quot;- връзката затворена&quot;
lg_close_len  equ $ - lg_close
lg_down1:     db &quot;=== изключване (сигнал &quot;
lg_down1_len  equ $ - lg_down1
lg_down2:     db &quot;) ===&quot;
lg_down2_len  equ $ - lg_down2
lg_childkill: db &quot;   child: SIGKILL при изключване&quot;
lg_childkill_len equ $ - lg_childkill
lg_fatal:     db &quot;=== FATAL: syscall грешка, exit 1 ===&quot;
lg_fatal_len  equ $ - lg_fatal
str_execfail: db &quot;execveat failed errno=&quot;
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
yn_h1:      resq 1                ; динамични заглавки за yn_prompt
yn_h1l:     resd 1
yn_h2:      resq 1
yn_h2l:     resd 1
peer_len:   resd 1                ; за getpeername
tmp32:      resb 256              ; буфер за сглобяване на съобщения (стартовият ред е ~102B)
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

    ; fd слотовете тръгват &quot;затворени&quot; — иначе при паднала връзка
    ; преди първата команда conn_close би затворил fd 0 (stdin!)
    mov     dword [pipe_r], -1
    mov     dword [pipe_w], -1
    mov     dword [memfd], -1
    mov     dword [log_fd], -1

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
    lea     rsi, [lg_key]
    mov     edx, lg_key_len
    call    cp_log
    lea     rsi, [key]
    mov     r12d, 4
.hexfp:
    movzx   eax, byte [rsi]
    mov     rdi, r14
    call    fmt_hex2
    add     r14, 2
    inc     rsi
    dec     r12d
    jnz     .hexfp
    mov     byte [r14], &apos;.&apos;
    mov     byte [r14+1], &apos;.&apos;
    mov     byte [r14+2], &apos;.&apos;
    add     r14, 3
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
    js      fatal

    mov     eax, SYS_listen
    mov     edi, [listen_fd]
    mov     esi, 1
    syscall
    test    eax, eax
    js      fatal

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
    mov     byte [r14], &apos;.&apos;
    inc     r14
    inc     rsi
    dec     r12d
    jnz     .ip_oct
    dec     r14                             ; последната точка → &apos;:&apos;
    mov     byte [r14], &apos;:&apos;
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
    js      conn_close
    mov     rax, [salt_rx + 56]
    mov     [seed_c2s], rax

    ; ЛОГ: ръкостискането мина - &quot;в кавички&quot;
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
    js      conn_close                     ; EOF / грешка / нарушение

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
    mov     rsi, rbx                        ; самата команда/пътят
    mov     rdx, rbp
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
    cmp     al, &apos;y&apos;
    je      .yes
    cmp     al, &apos;Y&apos;
    je      .yes
    cmp     al, &apos;n&apos;
    je      .deny
    cmp     al, &apos;N&apos;
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
    mov     dword [rsp+0],  0x61707865     ; &quot;expa&quot;
    mov     dword [rsp+4],  0x3320646e     ; &quot;nd 3&quot;
    mov     dword [rsp+8],  0x79622d32     ; &quot;2-by&quot;
    mov     dword [rsp+12], 0x6b206574     ; &quot;te k&quot;
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
; recv_msg() → rax = len / -1 ; данните в pt_buf+4 (NUL-terminated)
; ============================================================
recv_msg:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    lea     rbx, [pt_buf]
    lea     rbp, [ct_buf]
    ; блок 0: leader
    mov     rdi, rbp
    mov     esi, 64
    call    read_full
    test    rax, rax
    js      .fail
    mov     rcx, [seed_c2s]
    add     rcx, [p_c2s]
    inc     qword [p_c2s]
    mov     rdi, rbp
    mov     rsi, rbx
    lea     rdx, [key]
    call    chacha_block
    mov     eax, [rbx]
    bswap   eax
    test    eax, eax
    jz      .fail                          ; len==0 от client → drop
    mov     r12d, eax                      ; len (и за upload пътя)
    ; нулевият байт в началото на payload-а = КАЧВАНЕ НА ФАЙЛ (по умно от това не измислих)
    ; (командите са текст и никога не почват с \0 — колизия е невъзможна)
    cmp     byte [rbx + 4], 0
    jne     .cmd
    call    do_upload_core                 ; обработва всичко: hdr/stream/лог/отговор
    test    rax, rax
    js      .fail                          ; нарушение на протокола → drop
    jmp     .up_alive                      ; връзката е жива → следващата команда
.cmd:
    cmp     eax, MAX_CMD
    ja      .fail
    add     eax, 67
    shr     eax, 6
    mov     r13d, eax                      ; blocks
    mov     r14, 1                         ; j
.blk:
    cmp     r14, r13
    jae     .done
    mov     rax, r14
    shl     rax, 6
    mov     rdi, rbp
    add     rdi, rax
    mov     esi, 64
    call    read_full
    test    rax, rax
    js      .fail
    mov     rax, r14
    test    al, 15
    jnz     .fb
    mov     rcx, [seed_c2s]                ; j%16==0 → leader
    add     rcx, [p_c2s]
    inc     qword [p_c2s]
    jmp     .nonce
.fb:
    mov     rax, r14
    dec     rax
    shl     rax, 6
    add     rax, 56
    mov     rcx, [rbp + rax]               ; feedback: ct tail
.nonce:
    mov     rax, r14
    shl     rax, 6
    mov     rdi, rbp
    add     rdi, rax
    mov     rsi, rbx
    add     rsi, rax
    lea     rdx, [key]
    call    chacha_block
    inc     r14
    jmp     .blk
.done:
    mov     rax, r12
    add     rax, 4
    mov     byte [rbx + rax], 0            ; NUL на data_len
    mov     rax, r12
    jmp     .out
.up_alive:
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    add     rsp, 8                         ; QA FIX (GLM): изхвърляме return address-а от
                                           ; call recv_msg — иначе всеки upload изтича 8B стек
    jmp     cmd_loop                       ; качването е обработено — следваща команда
.fail:
    mov     rax, -1
.out:
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

    mov     [up_msglen], r12d
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

    ; ---- ЛОГ: upload: &lt;път&gt; (&lt;size&gt; B) ----
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
    mov     edx, 0644o
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
    mov     rax, [up_written]
    cmp     rax, [up_size]
    jne     .wfail_noclose                 ; параноя: не е записано всичко

    ; ---- ЛОГ: upload: OK &lt;size&gt; B ----
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

    ; ---- отговор: upload: OK &lt;size&gt; B -&gt; &lt;път&gt; + END 0 ----
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

; ------------------------------------------------------------
; up_hdr_read — чете хедър-блоковете [1, up_js) в pt_buf слотовете
;   (при път &gt; 57B полето size е в по-късен блок)
;   rax = 0 / -1 (EOF/грешка)
; ------------------------------------------------------------
up_hdr_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    xor     r14d, r14d
    inc     r14d                           ; j = 1
.h:
    cmp     r14d, [up_js]
    jae     .hd
    mov     eax, r14d
    shl     eax, 6
    lea     rdi, [ct_buf]
    add     rdi, rax
    mov     esi, 64
    call    read_full
    test    rax, rax
    js      .hfail
    test    r14b, 15
    jnz     .hfb
    mov     rcx, [seed_c2s]                ; j%16==0 → leader
    add     rcx, [p_c2s]
    inc     qword [p_c2s]
    jmp     .hn
.hfb:
    mov     eax, r14d
    dec     eax
    shl     eax, 6
    add     eax, 56
    mov     rcx, [ct_buf + rax]            ; ct[56..64) на предходния блок
.hn:
    mov     eax, r14d
    shl     eax, 6
    lea     rdi, [ct_buf]
    add     rdi, rax
    lea     rsi, [pt_buf]
    add     rsi, rax
    lea     rdx, [key]
    call    chacha_block
    inc     r14d
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
; up_recv_loop — чете блоковете [up_j, up_blocks)
;   up_mode=0: данните → io_buf (up_append), flush при 4096
;   up_mode=1: само дрениране (nonce веригата остава синхронна)
;   rax = 0 (успех / чисто дрениране) / -1 (write грешка — остатъкът Е
;          дрениран, или EOF — връзката умира)
; ------------------------------------------------------------
up_recv_loop:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    mov     r13d, [up_j]
    cmp     r13d, [up_blocks]
    jae     .fin
    ; init на feedback-а (само ако първият блок не е leader)
    test    r13b, 15
    jz      .loop
    mov     eax, r13d
    dec     eax
    shl     eax, 6
    add     eax, 56
    mov     rax, [ct_buf + rax]            ; ct на блок (j-1)
    mov     [up_fb], rax
    jmp     .loop
.loop:
    mov     r13d, [up_j]
    cmp     r13d, [up_blocks]
    jae     .fin
    lea     rdi, [ct_buf]                  ; ФИКСИРАН слот — големи съобщения!
    mov     esi, 64
    call    read_full
    test    rax, rax
    js      .netfail
    ; nonce СЛЕД read_full (то цапа rcx!)
    test    r13b, 15
    jnz     .fb
    mov     rcx, [seed_c2s]                ; leader
    add     rcx, [p_c2s]
    inc     qword [p_c2s]
    jmp     .nn
.fb:
    mov     rcx, [up_fb]
.nn:
    lea     rdi, [ct_buf]
    lea     rsi, [up_blk]
    lea     rdx, [key]
    call    chacha_block
    mov     rax, [ct_buf + 56]             ; feedback за следващия блок
    mov     [up_fb], rax
    cmp     dword [up_mode], 0
    jne     .next                          ; дрениране — без запис
    ; пресичане на блока с [dstart, dend)
    mov     r12d, r13d
    shl     r12d, 6                        ; 64j
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
    lea     rsi, [up_blk]
    add     rsi, rcx
    mov     edx, eax
    call    up_append
    test    rax, rax
    jns     .next
    mov     dword [up_mode], 1             ; write грешка → дренирай остатъка
.next:
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
    ; пакети по 16 блока = 1024B, 1 send на пакет
    shl     r15, 6                         ; total ct байтове (QA FIX: махнат no-op mov r15,r15)
    xor     r14, r14                       ; k
.pl:
    mov     rax, r14
    shl     rax, 10
    cmp     rax, r15
    jae     .pd
    mov     rsi, r15
    sub     rsi, rax
    cmp     rsi, 1024
    jbe     .pln
    mov     esi, 1024
.pln:
    lea     rdi, [rbp + rax]
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
    test    rbp, rbp
    jz      .ok
.rf:
    xor     eax, eax                       ; SYS_read
    mov     edi, [sock_fd]
    mov     rsi, rbx
    mov     rdx, rbp
    syscall
    test    rax, rax
    jle     .fail                          ; 0=EOF, &lt;0=грешка
    add     rbx, rax
    sub     rbp, rax
    jnz     .rf
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
    cmp     al, &apos; &apos;
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
    cmp     al, &apos; &apos;
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
    ; &apos;=&apos; в токена? (само преди binary-то)
    mov     r10, r9
.findeq:
    movzx   eax, byte [r10]
    test    al, al
    jz      .no_eq
    cmp     al, &apos;=&apos;
    je      .has_eq
    inc     r10
    jmp     .findeq
.no_eq:
    mov     [bin_path], r9
    mov     rax, [argv_cnt]
    cmp     rax, 1023
    jae     .tok
    mov     [argv_arr + rax*8], r9
    inc     qword [argv_cnt]
    jmp     .tok
.has_eq:
    cmp     dword [r9], 0x3D445743        ; &quot;CWD=&quot;
    jne     .env_tok
    add     r9, 4
    mov     [cwd_ptr], r9
    jmp     .tok
.env_tok:
    mov     rax, [envp_cnt]
    cmp     rax, 1023
    jae     .tok
    mov     [envp_arr + rax*8], r9
    inc     qword [envp_cnt]
    jmp     .tok
.argv_tok:
    mov     rax, [argv_cnt]
    cmp     rax, 1023
    jae     .tok
    mov     [argv_arr + rax*8], r9
    inc     qword [argv_cnt]
    jmp     .tok
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
load_binary: ; late 00&apos;s milw0rm vibe in 2026
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
    ; грешка → &quot;execveat failed errno=N\n&quot; → fd 2 → _exit(127)
    neg     eax
    lea     rdi, [errno_msg]
    lea     rsi, [str_execfail]
.cp:
    mov     al, [rsi]
    test    al, al
    jz      .cpd
    mov     [rdi], al
    inc     rdi
    inc     rsi
    jmp     .cp
.cpd:
    mov     r8, rdi                        ; начало на цифрите
    add     rdi, 12                        ; край на scratch
    mov     r9, rdi
    mov     r10d, 10
.dg:
    xor     edx, edx
    div     r10d
    add     dl, &apos;0&apos;
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
    add     dl, &apos;0&apos;
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
    add     dl, &apos;0&apos;
    mov     byte [rdi], &apos;0&apos;
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
    ; m = mp&lt;10 ? mp+3 : mp-9
    lea     rax, [r12 + 3]
    lea     r15, [r12 - 9]
    cmp     r12, 10
    cmovae  rax, r15                        ; m
    ; y += (m &lt;= 2)
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
; fmt_ts(rdi = buf) → rcx = 22: &quot;[DD-MM-YYYY HH:MM:SS] &quot;
; ------------------------------------------------------------
fmt_ts:
    push    rbx
    push    r12
    mov     r12, rdi
    mov     rbx, rdi
    call    ts_refresh
    mov     byte [rbx], &apos;[&apos;
    inc     rbx
    mov     eax, [ts_d]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], &apos;-&apos;
    inc     rbx
    mov     eax, [ts_mo]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], &apos;-&apos;
    inc     rbx
    mov     eax, [ts_y]
    mov     rdi, rbx
    call    fmt_dec
    add     rbx, rcx
    mov     byte [rbx], &apos; &apos;
    inc     rbx
    mov     eax, [ts_hh]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], &apos;:&apos;
    inc     rbx
    mov     eax, [ts_mm]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], &apos;:&apos;
    inc     rbx
    mov     eax, [ts_ss]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     word [rbx], &apos;] &apos;
    add     rbx, 2
    mov     rcx, rbx
    sub     rcx, r12
    pop     r12
    pop     rbx
    ret

; ------------------------------------------------------------
; fmt_tsname(rdi = buf) → rcx = 19: &quot;DD-MM-YYYY_HH-MM-SS&quot;
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
    mov     byte [rbx], &apos;-&apos;
    inc     rbx
    mov     eax, [ts_mo]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], &apos;-&apos;
    inc     rbx
    mov     eax, [ts_y]
    mov     rdi, rbx
    call    fmt_dec
    add     rbx, rcx
    mov     byte [rbx], &apos;_&apos;
    inc     rbx
    mov     eax, [ts_hh]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], &apos;-&apos;
    inc     rbx
    mov     eax, [ts_mm]
    mov     rdi, rbx
    call    fmt_dec2
    add     rbx, rcx
    mov     byte [rbx], &apos;-&apos;
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
log_open:
    push    rbx
    call    ts_refresh
    lea     rdi, [log_name]
    call    fmt_tsname
    lea     rbx, [log_name]
    add     rbx, rcx
    mov     dword [rbx], &apos;.txt&apos;
    mov     byte [rbx + 4], 0
    mov     eax, SYS_open
    lea     rdi, [log_name]
    mov     esi, 1 | O_CREAT | O_APPEND | O_CLOEXEC    ; O_WRONLY|...
    mov     edx, 0644o
    syscall
    test    eax, eax
    js      .fail
    mov     [log_fd], eax
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
; log_line(rsi = msg, rdx = len) — &quot;[ts] msg\n&quot; с ЕДИН write
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
;   &quot;[ts] cmd: &lt;командата&gt;\n&quot; — СЛЕД prefix-а има &quot;cmd: &quot;
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
    mov     rsi, r12
    mov     edx, r13d
    call    cp_log
    mov     byte [r14], 10
    inc     r14
    mov     eax, SYS_write
    mov     edi, [log_fd]
    lea     rsi, [log_buf]
    mov     rdx, r14
    sub     rdx, rsi
    syscall
.out:
    mov     rax, r13
    pop     r14
    pop     r13
    pop     r12
    ret

; ------------------------------------------------------------
; log_out(rdi = buf, rsi = len) — суровият изход на командата
;   управл. символи (&lt;0x20 освен \n,\t; 0x7F) → \xHH; UTF-8 минава
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
    mov     byte [r14], &apos;\&apos;
    mov     byte [r14 + 1], &apos;x&apos;
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
; log_exit(edi = статус) — &quot;exit: N&quot; или &quot;exit: убит от сигнал N&quot;
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
    ; ЛОГ: изключване — сглоби &quot;=== изключване (сигнал N) ===&quot;
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
    sub     dl, &apos;0&apos;
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
    cmp     al, &apos;9&apos;
    jbe     .dig
    and     al, 0xdf                        ; → главни
    cmp     al, &apos;A&apos;
    jb      .bad
    sub     al, &apos;A&apos; - 10
    cmp     al, 15
    ja      .bad
    movzx   eax, al
    ret
.dig:
    sub     al, &apos;0&apos;
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
    mov     eax, SYS_exit
    mov     edi, 1
    syscall
