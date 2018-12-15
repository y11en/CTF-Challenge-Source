#pragma once
#include "pch.h"

namespace myRSA
{
	//生成key
	//int Gen(BYTE **pub, DWORD* szPub, BYTE** pri, DWORD* szPri);
	
	// 公钥加密
	//int Enc(BYTE* pData, DWORD szData, BYTE* key, DWORD keyLen, OUT BYTE** ppOut, OUT DWORD* szOut);
	
	// 私钥解密
	//int Dec(BYTE* pData, DWORD szData, BYTE* key, DWORD keyLen, OUT BYTE** ppOut, OUT DWORD* szOut);

	namespace _2048
	{
		bool CryptoInit(HCRYPTKEY *key, HCRYPTPROV *provider, BYTE**publicKey, unsigned long* pubkl, BYTE **privateKey , unsigned long* prikl);
		bool Encrypt(HCRYPTKEY key, BYTE **cipherText, BYTE *plainText, IN OUT unsigned long* pinOutLen , bool b64 = true);

#ifdef _DECOPEN
		bool Decrypt(HCRYPTKEY key, BYTE **plainText, BYTE *cipherText, IN OUT unsigned long* pinOutLen , bool b64 = true);
#endif
		int CryptoUninit(HCRYPTKEY key, HCRYPTPROV provider);
	};


};