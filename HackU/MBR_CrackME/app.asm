jmp _start
	BASEADDR dw 0
_start:  
  
    ;初始化数据段，使其指向段基址0X7C00处，即Boot代码被加载的地方
	mov bp , sp 
	
	mov bx , [bp + 2]	;段
	mov es , bx
	
	mov bx , [bp + 4]
	mov [es : bx + BASEADDR] , bx  ;偏移
	
	push es
	pop ds
	

    ;将文本显示内存段基址 放在ES中，供后面显示字符使用  
    ;mov     ax, DISPLAYSEG  
    ;mov     es, ax  
	
	;所有全局变量的访问 使用 bx 作为基地址
	;==========================================
		;JMP INPUT0
		
		lea si , [BANNA + bx]
		push bx
		call SHOWMESSAGE
		pop bx
		
		lea  si ,[Welcome + bx]
		
		push bx
		call SHOWMESSAGE
		pop  bx 
		
		lea  si , [ShowEnterMessage + bx]
		
		push bx
		call SHOWMESSAGE
		pop bx

INPUT0:		
		lea  di , [InputBuff + bx]
		mov  cx , [InputBuffLen + bx]
		

		push bx
		call  GETKEY
		pop bx
		;mov cx , ax		;实际输入的长度
		
		;ok fuck key
		call CrackME
		test al , 1
		jnz  GameOver
		
	;==========================================
		jmp near $      ;死循环，程序在此处终止  

GameOver:
		ret 

;API ----------------------------------------

;===========================================================
; [in] ax->地址,cx->长度  
SHOWMESSAGE:
	cwd
	mov bx,0007h                                    ; Page Number = 0, Attribute = 07h
	mov ah,0Eh                                      ; Function 0Eh: Teletype Output											
	lodsb											; load the first character
Next_Char:
	int 10h
	lodsb                                        	; al = next character
	or al,al                                        ; last letter?
	jnz Next_Char                                   ; if not print next letter

RETURNBACK:
	ret
;===========================================================
; cx -> 最大缓冲区长度
; di -> 缓冲区
GETKEY:
	;mov word [bp - 0x2] , 0					; 当前长度
	;mov [bp - 0x4] , cx						; 最大长度
	;mov [bp - 0x6] , di						; 取buf
	
	XOR CX,CX
LOOP:

	MOV AH,0
	INT 16H

	; enter 退出
	CMP AL,0DH                             ;判断是否Enter键
	JZ RETGETKEY
	
	; 长度越界 退出
	mov cx , [bx + num_idx]
	inc cx
	cmp cx , [bx + InputBuffLen]
	ja RETGETKEY
	
	;更新长度
	mov [bx + num_idx] , cx
	;写入数据
	dec cx
	lea si , [bx + InputBuff]
	add si , cx
	mov [si] ,al
	
	
	;ADD CX,bx                                   ;存入CX中
	
	push bx
	;MOV AL,2AH
	mov al , [si]
	MOV BX,07H                         
	MOV AH,0EH
	INT 10H                                      ;显示*号，继续等待输入
	pop bx
	
	JMP LOOP
RETGETKEY:
	JMP RETURNBACK
;===========================================================
Match:
	lea si , [bx + GoodBoy]
	push bx
	call SHOWMESSAGE
	pop bx
	mov al , 1
	ret
CrackME:
	lea si , [bx + InputBuff]
	xor cx , cx			; i = 0
_ForLoop:
	; ax dx bp
	cmp cx , [bx + InputBuffLen] 
	jnb Check		; i < InputBuffLen
	
	push si
	pop bp
	
	xor ax , ax
	add bp , cx
	mov al , [es:bp]
	;mov al, [es:bp + cx]
	ROR al , 3
	
	push ax
	call JUCK1
	pop ax
	
	XOR al , 0x74
NOT_JUMP_THIS:	
	ROL al , 5
	ADD al , 0x47
	test al, 1
	jz OuShu
	jnz JiShu
OuShu:
	dec al
	dec al
JiShu:
	inc al

	mov [es:bp] , al
	
	inc cx
	jmp _ForLoop

Check:
	lea si , [bx + InputBuff]
	lea di , [bx + CheckData]
	mov cx , [bx + InputBuffLen]
	repz cmpsb
	jz Match
NoMatch:
	xor ax , ax
	ret

JUCK1:
	add ax , 0x4
	xor ax , 0x74
	ror ax , 3
	ret 

sub_0:
	push sp
	pop ax
	push bx
	mov byte [bx+2] , 0x74
	call NOT_JUMP_THIS
	pop bx
	ret 
DATA:
;数据区-------------------
    Welcome     	  db "BB is cheap,Show me the Password",0xD,0xA,0
	ShowEnterMessage  db "$>", 0
	GoodBoy			  db "}" , 0xD,0xA , 0
	num_idx  		  dw 0
	CheckData	  	  db 0x25,0xa1,0x39,0x89,0xa6,0x9d,0xd5,0xa5,0x75,0x8d,0x4a,0x92,0xf1,0x59,0x5e,0x91
	;CheckData	  	  db 0x92
	InputBuff	      resb 0x10
	InputBuffLen	  dd ($ - InputBuff)
	;InputBuffLen	  dd  0x1
	TellU			  db "bu hunxiao le,HaveFun~"
	
	BANNA  	db  "      ___           ___           ___           ___           ___     " , 0xD , 0xA 
			db  "     /\__\         /\  \         /\  \         /\__\         /\__\    " , 0xD , 0xA 
			db  "    /:/  /        /::\  \       /::\  \       /:/  /        /:/  /    " , 0xD , 0xA 
		db  	"   /:/__/        /:/\:\  \     /:/\:\  \     /:/__/        /:/  /     " , 0xD , 0xA 
		db  	"  /::\  \ ___   /::\~\:\  \   /:/  \:\  \   /::\__\____   /:/  /  ___ " , 0xD , 0xA 
		db  	" /:/\:\  /\__\ /:/\:\ \:\__\ /:/__/ \:\__\ /:/\:::::\__\ /:/__/  /\__\" , 0xD , 0xA 
		db  	" \/__\:\/:/  / \/__\:\/:/  / \:\  \  \/__/ \/_|:|~~|~    \:\  \ /:/  /" , 0xD , 0xA 
		db  	"      \::/  /       \::/  /   \:\  \          |:|  |      \:\  /:/  / " , 0xD , 0xA 
		db  	"      /:/  /        /:/  /     \:\  \         |:|  |       \:\/:/  /  " , 0xD , 0xA 
		db  	"     /:/  /        /:/  /       \:\__\        |:|  |        \::/  /   " , 0xD , 0xA 
		db  	"     \/__/         \/__/         \/__/         \|__|         \/__/    " , 0xD , 0xA  , 0x00
		
times 0x600 - ($-$$) db 0 