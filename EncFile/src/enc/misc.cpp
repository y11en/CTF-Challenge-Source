#include "pch.h"
#include "misc.h"

//成功*pBuf != NULL ， 返回值为文件大小
DWORD myMISC::readFile(char* filepath, OUT BYTE** pBuf)
{
	DWORD szOut = 0 , szRet = 0;
	PVOID pb = NULL;
	HANDLE hfile = CreateFileA(filepath,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if ( INVALID_HANDLE_VALUE != hfile )
	{
		pb = NULL;
		szOut = GetFileSize(hfile, NULL);
		pb = malloc(szOut + 1);
		if (pb != NULL)
		{
			szRet = 0;
			// 异常
			ReadFile(hfile, pb, szOut, &szRet, NULL);
		}
		*pBuf = (BYTE*)pb;
		CloseHandle(hfile);
	}
	
	//理论相等
	if (szRet == szOut)
	{

	}
	else
	{
		//失败
		if (pb != NULL)
		{
			delete pb;
			*pBuf = NULL;
		}
	}

	return szRet;
}

// 假设能写成功
DWORD myMISC::writeFile(char* filepath, BYTE *pData, DWORD szData)
{
	HANDLE hfile = CreateFileA(filepath,
		GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	DWORD szWrite = 0;

	if (INVALID_HANDLE_VALUE != hfile)
	{
		// 异常
		WriteFile(hfile, pData, szData, &szWrite, NULL);
		FlushFileBuffers(hfile);
		CloseHandle(hfile);
	}

	return szWrite;
}

bool myMISC::b64::Base64EncodeW(WCHAR **dest, unsigned long *dlen, const BYTE *src, unsigned long slen)
{
	if (src == NULL)
		return false;

	if (!CryptBinaryToStringW(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, dlen))
		return false;

	*dest = (WCHAR *)malloc(*dlen * sizeof(WCHAR));
	if (*dest == NULL) return false;
	SecureZeroMemory(*dest, *dlen * sizeof(WCHAR));

	if (!CryptBinaryToStringW(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *dest, dlen))
	{
		SAFE_FREE(*dest);
		return false;
	}

	return true;
}

bool myMISC::b64::Base64EncodeA(BYTE **dest, unsigned long *dlen, const BYTE *src, unsigned long slen)
{
	if (src == NULL)
		return false;

	if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, dlen))
		return false;

	*dest = (BYTE *)malloc(*dlen * sizeof(char));
	if (*dest == NULL) return false;
	SecureZeroMemory(*dest, *dlen * sizeof(char));

	if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,(LPSTR)*dest, dlen))
	{
		SAFE_FREE(*dest);
		return false;
	}

	return true;
}

bool myMISC::b64::Base64DecodeW(BYTE **dest, unsigned long *dlen, const WCHAR *src, unsigned long slen)
{
	if (src == NULL)
		return false;

	if (!CryptStringToBinaryW(src, slen, CRYPT_STRING_BASE64, NULL, dlen, NULL, NULL))
		return false;

	*dest = (unsigned char *)malloc((*dlen + 1) * sizeof(unsigned char));
	if (*dest == NULL) return false;
	SecureZeroMemory(*dest, (*dlen + 1) * sizeof(unsigned char));

	if (!CryptStringToBinaryW(src, slen, CRYPT_STRING_BASE64, *dest, dlen, NULL, NULL))
	{
		SAFE_FREE(*dest);
		return false;
	}

	return true;
}

bool myMISC::b64::Base64DecodeA(BYTE **dest, unsigned long *dlen, const BYTE *src, unsigned long slen)
{
	if (src == NULL)
		return false;

	if (!CryptStringToBinaryA((LPCSTR)src, slen, CRYPT_STRING_BASE64, NULL, dlen, NULL, NULL))
		return false;

	*dest = (unsigned char *)malloc((*dlen + 1) * sizeof(unsigned char));
	if (*dest == NULL) return false;
	SecureZeroMemory(*dest, (*dlen + 1) * sizeof(unsigned char));

	if (!CryptStringToBinaryA((LPCSTR)src, slen, CRYPT_STRING_BASE64, *dest, dlen, NULL, NULL))
	{
		SAFE_FREE(*dest);
		return false;
	}

	return true;
}