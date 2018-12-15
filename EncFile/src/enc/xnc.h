#pragma once
#include "pch.h"
#define RSA_ENC	0x0001
#define RSA_DEC	0x0002
#define RSA_GEN 0x0003


#define AES_DEC 0x0000
#define AES_ENC 0x0001

int encfile(char* filepath, char* newfilepath);

#ifdef _DECOPEN
int decfile(char* filepath, char* newfilepath);
#endif

int doRSA(BYTE** publicKey,
	DWORD* publicKeyLen,
	BYTE** privateKey,
	DWORD* privateKeyLen,
	BYTE* oldBuf,
	BYTE** newbuf,
	DWORD* pInOutSz,
	int flag, bool b64);
int doAES(BYTE* aeskey, DWORD keySize, BYTE* oldBuf, BYTE** newbuf, DWORD* pInOutSz, bool bEnc, bool b64);