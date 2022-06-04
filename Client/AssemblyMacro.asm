.CODE
TrapflagCheck PROC
pushfq
or dword ptr[rsp],10100h
popfq
db 0fh ;cpuid 
db 0a2h
nop
nop
nop
ret
TrapflagCheck ENDP

LazyCheckHyperv PROC
xor ecx,ecx 
mov eax,1 
cpuid
test    ecx, 80000000h
jne detect
xor eax,eax
ret

detect:
mov al,1
ret
LazyCheckHyperv ENDP


END
