format pe console 5.0
include 'win32a.inc'

ERROR_INSUFFICIENT_BUFFER equ 7ah

struct MFT_REF
  .indexLow  dd ?
  .indexHigh dw ?
  .ordinal   dw ?
ends
struct FILE_FRAGMENT
  .lcnLow  dd ?
  .lcnHigh dd ?
  .count   dd ?
ends

section '.data' data readable writeable
record1 MFT_REF
fragments FILE_FRAGMENT 0, 0, 0
dd 21 dup (0)
fraglength dd 8
context dd 26 dup(0)
pathlen dd 0
path du 'c:/Program Files/Java/jre1.8.0_161/lib/rt.jar',0
padpath du 0
fmt db 'found at %x%x', 13, 10, 0
fmt1 db 'File reference not found', 13, 10, 0
fmt2 db 'File is resident',13,10,0
fmt3 db 'Buffer too small for accepting of all file fragments', 13, 10, 0
fmt4 db 'Fragment %d, start cluster:%x%x, length:%x',13,10,0
fmt5 db 'Press enter to exit',0
section '.code' code readable executable
entry $
or dword [pathlen], -1
mov ecx, record1
mov dword[ecx], 5
and dword[ecx+4], 0
xor eax, eax
mov ax, [path]
bt eax, 7
jc .notfound
or eax, 32
cmp eax, 'z'
ja .notfound
cmp eax, 'a'
jb .notfound
sub eax, 'a'
shl eax, 2
add eax, context
invoke Get_MFT_EntryForPath, eax, path, dword[pathlen], record1
test eax, eax; if (eax==0)
je .notfound
mov eax, [record1]
mov ecx, [record1+4]
and ecx, 0ffffh
cinvoke printf, fmt, ecx, eax
xor eax, eax
mov ax, [path]
or eax, 32
sub eax, 'a'
shl eax, 2
add eax, context
invoke GetFileClusters, dword[eax], dword[record1], dword[record1+4], fraglength, fragments
test eax, eax
je .fixerror
xor ecx, ecx
@@:
push ecx
mov eax, ecx
shl ecx, 2
lea ecx, [ecx+ecx*2];ecx*=3
add ecx, fragments
cinvoke printf, fmt4, eax, dword[ecx+4], dword[ecx], dword[ecx+8]
pop ecx
inc ecx
cmp ecx, [fraglength]
jb @b
jmp .end
.fixerror:
invoke GetLastError
cmp eax, ERROR_INSUFFICIENT_BUFFER
jne .resident
cinvoke printf, fmt3
jmp .end
.resident:
cinvoke printf, fmt2
jmp .end
.notfound:
cinvoke printf, fmt1
jmp .end
.end:
cinvoke printf, fmt5
cinvoke getchar
ret 4

section '.idata' import data readable writeable
  library kernel32,'KERNEL32.DLL',\
	  user32,'USER32.DLL',\
	  msvcrt, 'msvcrt.dll',\
	  ntfs, 'ntfs.dll'

include '\api\kernel32.inc'
include '\api\user32.inc'

import msvcrt,\
	  fopen, 'fopen',\
	  fwrite, 'fwrite',\
	  fclose, 'fclose',\
	  printf, 'printf',\
	  fprintf, 'fprintf',\
	  malloc, 'malloc',\
	  free, 'free',\
	  strlen, 'strlen',\
	  sscanf, 'sscanf',\
	  getchar, 'getchar'
	  
import ntfs,\
   Get_MFT_EntryForPath,'Get_MFT_EntryForPath',\
   GetFileClusters, 'GetFileClusters'
