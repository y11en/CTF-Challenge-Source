#pragma once
#include "pch.h"



namespace myMISC
{
	DWORD readFile(char* filepath, OUT BYTE** pBuf);
	DWORD writeFile(char* filepath, BYTE *pData, DWORD szData);

	namespace b64
	{
		bool Base64EncodeW(WCHAR **dest, unsigned long *dlen, const BYTE*src, unsigned long slen);
		bool Base64EncodeA(BYTE **dest, unsigned long *dlen, const BYTE *src, unsigned long slen);

		bool Base64DecodeW(BYTE **dest, unsigned long *dlen, const WCHAR *src, unsigned long slen);
		bool Base64DecodeA(BYTE **dest, unsigned long *dlen, const BYTE*src, unsigned long slen);
	};

};