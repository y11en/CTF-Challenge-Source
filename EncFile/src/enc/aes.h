#pragma once



namespace  myAES
{
	//int Enc(BYTE* pData, unsigned int szData, BYTE* key, BYTE* IV, OUT BYTE** ppOut, OUT DWORD* szOut);
	//int Dec(BYTE* pcData, unsigned int szData, BYTE* key, BYTE* IV, BYTE** ppOut, DWORD* szOut);
	
	namespace _256
	{// AES-256-CBC
		bool CryptoInit(HCRYPTKEY *key, HCRYPTPROV *provider, BYTE **iv, const BYTE *password, unsigned long pLen);
		bool Encrypt(HCRYPTKEY key, BYTE **cipherText, BYTE *plainText, IN OUT unsigned long* pinOutLen ,bool b64 = true);
#ifdef _DECOPEN
		bool Decrypt(HCRYPTKEY key, BYTE **plainText,BYTE *cipherText, IN OUT unsigned long* pinOutLen , bool b64 = true);
#endif
		int CryptoUninit(HCRYPTKEY key, HCRYPTPROV provider);
	}


};