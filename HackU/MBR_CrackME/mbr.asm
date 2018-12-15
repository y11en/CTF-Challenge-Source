jmp START
DATA:
    MSG         db "Hello , LyOS loading ..." , 0xD , 0xA , 0x00
    BOOTDRIVER  db 0x00
	Line        db 0x00
	
	APP_START       equ  0x3
	BASE_ADDR       equ  0x400
	APP_SIZE        equ  0x3
	ABS_APP_START   equ   (APP_START - 0x1)
	
START:
    xor bx , bx
    mov ds , bx
    mov ax , [0x413]        ; 0x413记录了bios的内存可用区域
                            ; 由高到底分配
    sub ax , 0x2
    mov [0x413] , ax        ; 更新原值
    shl ax , 0x4            ; 2^4 = 16  ax * 1024 / 16
    mov es , ax             ; es = ax
    
    mov  si , 0x7C00        ; 拷贝自己到新的地方去
    xor  di , di
    mov  cx , 0x200     
    rep  movsb
    push es
    push NEW_START
    retf
    
NEW_START:

    mov  si,MSG
	call SHOWMESSAGE
	
    push es
    pop  ds					;更新数据段
    mov  [BOOTDRIVER] , dl  ;保存启动驱动器号

	;处理环境
	pushad
	
	push ABS_APP_START + 1
	call LOAD_APP
	add sp , 2
	
	popad
	
	xor dx ,dx
	;读取第二个扇区数据到7c00
;	push es
	xor ax ,ax
	push ax
	pop es
	mov al , 1
	mov bx , 0x7C00
	mov cl , 2
	
	call int_13_read
	;恢复原始MBR内容
	dec cl
	
    call int_13_write
;    pop es
	push es
	push bx
	retf
			;jmp bx ;转入执行


;al 扇区个数
;es 和 bx 
;cl 起始
int_13_write:
;RECOVER_MBR:
    ;xor ax , ax 
    ;mov es , ax     
    ;mov ax , 0x0301         ;功能号3，写参数1：扇区个数
	mov ah , 0x03
    mov dl , [BOOTDRIVER]   ;磁盘号
    mov dh , 0x00           ;磁头
    mov ch , 0x00           ;磁道号
    ;mov cl , 0x01           ;扇区
    ;mov bx , 0x7C00         ;从es：bx写入
    int 13h
    ret 

;al 扇区个数
;es 和 bx 
;cl 起始
;LOAD_MBR:
int_13_read:
	mov ah , 0x02
    ;mov ax , 0x0201         ;功能号2，读参数1：扇区个数
    mov dl , [BOOTDRIVER]   ;磁盘号
    mov dh , 0x00           ;磁头
    mov ch , 0x00           ;磁道号
    ;mov cl , 0x02           ;扇区
    ;xor ax , ax 
    ;mov es , ax
	;mov bx , 0x7C00         ;读取到es：bx中
    int 13h
    ret 
	
LOAD_APP:
;我们的app大小最大2个扇区...
	mov bx , sp
	mov bx , word [ss:bx + 0x2]
		;这里导入app,2333
	
	; int 13 扩展读
	;mov si , DiskAddressPacket
	;xor ax , ax
	;mov word [si + 8] , bx    ;起始扇区数
	;mov word [si + 4] ,BASE_ADDR  ;填写offset
	;mov bx , cs
	;mov [si + 6] ,  bx 	 	  ;填写段地址
	;mov word [si + 2] , 0x2   ;填写读出的块个数
	;mov ah , 0x42
	;mov dl , [BOOTDRIVER]
	;int 13h
	
	xor cx,cx
	mov cl,bl
	
	mov bx , BASE_ADDR
	push cs
	pop es
	
	mov al,APP_SIZE
	
	call int_13_read
	
	;sub  sp , 0x200
	push BASE_ADDR
	push es
	call BASE_ADDR
	add sp , 0x4
	;add  sp , 0x204	;平衡
	
	ret

	 ;[in] si ,  字符串地址
	;[out] cx ,  长度
GET_STR_LEN:
		xor cx,cx
		cwd
	nextchar:
		lodsb
		or al,al
		jz ret0
		inc cx
		jmp nextchar
	ret0:
		ret
	
; [in] ax->地址,cx->长度  
SHOWMESSAGE:
	mov bx,000Ch                                    ; Page Number = 0, Attribute = 07h
	mov ah,0Eh                                      ; Function 0Eh: Teletype Output
	cs lodsb                                                  ; load the first character
Next_Char:
	int 10h
	cs lodsb                                        ; al = next character
	or al,al                                        ; last letter?
	jnz Next_Char                                   ; if not print next letter

RETURNBACK:
	ret
;-------------------------------------------------------------------------------

DiskAddressPacket:
	db 10h
	db 0
	dw 01h
	dd 0h
	dd 0x2 ; 低8  实际扇区数 - 1
	dd 0

 ; struct DiskAddressPacket 
 ; { 
 ;   BYTE PacketSize;  // 数据包尺寸(16字节) 
 ;   BYTE Reserved;// ==0 
 ;   WORD BlockCount;  // 要传输的数据块个数(以扇区为单位) 
 ;   DWORD BufferAddr; // 传输缓冲地址(segment:offset) 
 ;   QWORD BlockNum;   // 磁盘起始绝对块地址(以扇区为单位) 
 ; }; 

times 510 - ($-$$) db 0 
db 0x55 , 0xAA