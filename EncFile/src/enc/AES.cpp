#include "pch.h"
#include "aes.h"
#include "misc.h"

#include "stdio.h"

static bool generateKey(HCRYPTKEY *key, HCRYPTPROV provider, ALG_ID algid, const BYTE *password, unsigned long pLen)
{
	if (!provider || password == NULL)
		return false;

	HCRYPTHASH hash;

	if (!CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash))
	{
		//printf("Error: %d\n", GetLastError());
		return false;
	}

	if (!hash)
		return false;

	if (!CryptHashData(hash, password, pLen, 0))
	{
		CryptDestroyHash(hash);
		return false;
	}

	if (!CryptDeriveKey(provider, algid, hash, CRYPT_EXPORTABLE, key))
	{
		CryptDestroyHash(hash);
		return false;
	}

	CryptDestroyHash(hash);
	return true;
}

bool myAES::_256::CryptoInit(HCRYPTKEY *key, HCRYPTPROV *provider, BYTE **iv, const BYTE *password, unsigned long pLen)
{
	unsigned long mode = CRYPT_MODE_CBC;
	unsigned long blockSize, blockSizeLen = sizeof(unsigned long);

	if (!CryptAcquireContextW(provider, NULL, NULL, PROV_RSA_AES, 0))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContextW(provider, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
			{
				//printf("Error: %d\n", GetLastError());
				return false;
			}
		}
		else
		{
			//printf("Error: %d\n", GetLastError());
			return false;
		}
	}

	if (!generateKey(key, *provider, CALG_AES_256, password, pLen))
	{
		//printf("Error: %d\n", GetLastError());
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	if (!CryptSetKeyParam(*key, KP_MODE, (BYTE *)&mode, 0))
	{
		//printf("Error: %d\n", GetLastError());
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	if (!CryptGetKeyParam(*key, KP_BLOCKLEN, (BYTE *)&blockSize, &blockSizeLen, 0))
	{
		//printf("Error: %d\n", GetLastError());
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	blockSize /= 8;

//随机IV
/*
	*iv = (unsigned char *)malloc(blockSize * sizeof(unsigned char));
	if (*iv == NULL)
	{
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}
	SecureZeroMemory(*iv, blockSize * sizeof(unsigned char));

	if (!CryptGenRandom(*provider, blockSize, *iv))
	{
		//printf("Error: %d\n", GetLastError());
		SAFE_FREE(*iv);
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	if (!CryptSetKeyParam(*key, KP_IV, *iv, 0))
	{
		//printf("Error: %d\n", GetLastError());
		SAFE_FREE(*iv);
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}
*/
	return true;
}

// plainText = NULL
// 返回 需要的 cipherText 的大小

bool myAES::_256::Encrypt(HCRYPTKEY key, BYTE **cipherText, BYTE *plainText, unsigned long* pinOutLen , bool b64)
{
	unsigned long len = 0;
	unsigned char *encrypted = 0;
	unsigned long enLen = 0;

	len = *pinOutLen;

	if (!CryptEncrypt(key, 0, TRUE, 0, NULL, &len, 0))
	{
		if (key) CryptDestroyKey(key);
		return false;
	}

	enLen = len;

	encrypted = (BYTE *)malloc(len * sizeof(BYTE));
	if (encrypted == NULL)
	{
		if (key) CryptDestroyKey(key);
		return false;
	}
	SecureZeroMemory(encrypted, len * sizeof(unsigned char));

	memcpy_s(encrypted, len, plainText, *pinOutLen);

	len = *pinOutLen;
	if (!CryptEncrypt(key, 0, TRUE, 0, encrypted, &len, enLen))
	{
		SAFE_FREE(encrypted);
		if (key) CryptDestroyKey(key);
		return false;
	}

	if (b64 && myMISC::b64::Base64EncodeA(cipherText, pinOutLen, encrypted, enLen))
	{

	}
	else if (!b64 )
	{

		//memcpy_s(*cipherText, enLen, encrypted, enLen);
		*pinOutLen = enLen;
		*cipherText = encrypted;
	}
	else
	{
		SAFE_FREE(encrypted);
		if (key) CryptDestroyKey(key);
		return false;
	}

	if (b64)
		SAFE_FREE(encrypted);
	
	return true;
}
#ifdef _DECOPEN
bool myAES::_256::Decrypt(HCRYPTKEY key, BYTE **plainText, BYTE *cipherText, unsigned long* pinOutLen , bool b64)
{
	unsigned long len = 0;
	unsigned long decodedLen = 0;
	BYTE *decoded = 0;

	if (b64 && myMISC::b64::Base64DecodeA(&decoded, &decodedLen, cipherText, *pinOutLen))
	{

	}
	else if (!b64)
	{
		//memcpy_s(decoded, *pinOutLen, cipherText, *cipherText);
		decoded = cipherText;
		decodedLen = *pinOutLen;
	}
	else
	{
		if (key) CryptDestroyKey(key);
		return false;
	}

	*plainText = (BYTE *)malloc(decodedLen * sizeof(BYTE));
	if (*plainText == NULL)
	{
		if (key) CryptDestroyKey(key);
		return false;
	}
	SecureZeroMemory(*plainText, decodedLen * sizeof(unsigned char));

	memcpy_s(*plainText, decodedLen, decoded, decodedLen);

	if (b64)
		SAFE_FREE(decoded);

	len = decodedLen;
	if (!CryptDecrypt(key, 0, TRUE, 0, *plainText, &len))
	{
		printf("err = %x\n",GetLastError());
		SAFE_FREE(*plainText);
		if (key) CryptDestroyKey(key);
		return false;
	}

	*pinOutLen = len;
	return true;
}
#endif
int myAES::_256::CryptoUninit(HCRYPTKEY key, HCRYPTPROV provider)
{
	int ret = 0;
	do
	{
		if (key) if (!CryptDestroyKey(key))
		{	//printf("Error: %d\n", GetLastError());
			ret = -1;
			break;
		}
		if (provider) if (!CryptReleaseContext(provider, 0))
		{		//printf("Error: %d\n", GetLastError());
			ret = -2;
			break;
		}
	} while (FALSE);
	return ret;
}

























/***
#include <iostream>
void CancelByError(const char* info)
{
	printf("%s\n", info);
}

//成功返回0 失败-1
int myAES_128::Enc(BYTE* pData , unsigned int szData , BYTE* key , BYTE* iv, OUT BYTE** ppOut , OUT DWORD* szOut)
{
	CRYPT_DATA_BLOB orgBlob;
	memset(&orgBlob, 0, sizeof(orgBlob));
	
	HCRYPTKEY hKey = NULL;

	//准备数据
	orgBlob.pbData = pData;
	orgBlob.cbData = szData;
	
	// 创建 Key
	struct keyBlob
	{
		BLOBHEADER hdr;
		DWORD cbKeySize;
		BYTE rgbKeyData[16];  // FOR AES-256 = 32
	} keyBlob;

	HCRYPTPROV hProv = NULL;
	if (!CryptAcquireContext(
		&hProv,  // 返回的句柄
		NULL,  // CSP 容器名称
		NULL,  // CSP 提供者名称
		PROV_RSA_AES,         // CSP 提供者类型
		0))             // 附加参数：
	{
		//delete[] orgBlob.pbData;
		//CancelByError(L"Get provider context failed!\n");
		goto errExit;
	}

	keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
	keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
	keyBlob.hdr.reserved = 0;
	keyBlob.hdr.aiKeyAlg = CALG_AES_128;    // FOR AES-256 = CALG_AES_256
	keyBlob.cbKeySize = 16;      // FOR AES-256 = 32
	CopyMemory(keyBlob.rgbKeyData, key, keyBlob.cbKeySize);

	if (!CryptImportKey(hProv, (BYTE*)(&keyBlob), sizeof(keyBlob), NULL, CRYPT_EXPORTABLE, &hKey))
	{
		//delete orgBlob.pbData;
		CryptReleaseContext(hProv, 0);
		//CancelByError(L"Create key failed!\n");
		goto errExit;
	}

	// 设置初始向量
	if (iv == NULL)
	{
		if (!CryptSetKeyParam(hKey, KP_IV, key, 0))
		{
			//delete orgBlob.pbData;
			CryptDestroyKey(hKey);
			CryptReleaseContext(hProv, 0);
			//CancelByError(L"Set key's IV parameter failed!\n");
			goto errExit;
		}
	}
	else
	{
		if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
		{
			//delete orgBlob.pbData;
			CryptDestroyKey(hKey);
			CryptReleaseContext(hProv, 0);
			//CancelByError(L"Set key's IV parameter failed!\n");
			goto errExit;
		}
	}


	// 加密处理
	CRYPT_DATA_BLOB encBlob;
	memset(&encBlob, 0, sizeof(encBlob));
	encBlob.cbData = orgBlob.cbData;
	encBlob.pbData = (BYTE*) new char[(orgBlob.cbData / 16 + 1) * 16];

	if (encBlob.pbData == NULL)
	{
		//delete orgBlob.pbData;
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		goto errExit;
	}

	memcpy(encBlob.pbData, orgBlob.pbData, orgBlob.cbData);
	if (!CryptEncrypt(hKey, NULL, TRUE, 0, encBlob.pbData, &encBlob.cbData, (orgBlob.cbData / 16 + 1) * 16))
	{
		//delete orgBlob.pbData;
		//delete encBlob.pbData;
		
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		//CancelByError(L"AES encrypt failed!\n");
		goto errExit;
	}

	// 释放获取的对象
	//delete orgBlob.pbData;
	//delete encBlob.pbData;

	//不释放原始内存，若成功返回enc内存，调用者清除
	*ppOut = encBlob.pbData;
	*szOut = encBlob.cbData;

	if (hKey != NULL)
	{
		CryptDestroyKey(hKey);
		hKey = NULL;
	}

	if (hProv != NULL)
	{
		CryptReleaseContext(hProv, 0);
		hProv = NULL;
	}

	return 0;
errExit:
	return -1;
}

int myAES_128::Dec(BYTE* pcData, unsigned int szData, BYTE* key, BYTE* iv, BYTE** ppOut, DWORD* szOut)
{
	//准备数据
	CRYPT_DATA_BLOB encBlob;
	memset(&encBlob, 0, sizeof(encBlob));
	HCRYPTKEY hKey = NULL;

	encBlob.pbData = pcData;
	encBlob.cbData = szData;


	HCRYPTPROV hProv = NULL;
	if (!CryptAcquireContext(
		&hProv,  // 返回的句柄
		NULL,  // CSP key 容器名称
		NULL,  // CSP 提供者名称
		PROV_RSA_AES,         // CSP 提供者类型
		0))             // 附加参数：
	{
		//delete encBlob.pbData;
		goto errExit;

		//CancelByError(L"Get provider context failed!\n");
	}

	// 创建 Key
	struct keyBlob
	{
		BLOBHEADER hdr;
		DWORD cbKeySize;
		BYTE rgbKeyData[16];  // FOR AES-256 = 32
	} keyBlob;

	keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
	keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
	keyBlob.hdr.reserved = 0;
	keyBlob.hdr.aiKeyAlg = CALG_AES_128;    // FOR AES-256 = CALG_AES_256
	keyBlob.cbKeySize = 16;      // FOR AES-256 = 32
	CopyMemory(keyBlob.rgbKeyData, key, keyBlob.cbKeySize);



	if (!CryptImportKey(hProv, (BYTE*)(&keyBlob), sizeof(keyBlob), NULL, CRYPT_EXPORTABLE, &hKey))
	{
		//delete encBlob.pbData;
		CryptReleaseContext(hProv, 0);
		//CancelByError("Create key failed!\n");
		goto errExit;
		
	}


	// 设置初始向量
	if (iv == NULL)
	{
		if (!CryptSetKeyParam(hKey, KP_IV, key, 0))
		{
			//delete encBlob.pbData;
			CryptDestroyKey(hKey);
			CryptReleaseContext(hProv, 0);
			//CancelByError("Set key's IV parameter failed!\n");
			goto errExit;
			
		}
	}
	else
	{
		if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
		{
			//delete encBlob.pbData;
			CryptDestroyKey(hKey);
			CryptReleaseContext(hProv, 0);
			//CancelByError("Set key's IV parameter failed!\n");
			goto errExit;
			
		}
	}


	// 加密处理
	CRYPT_DATA_BLOB orgBlob;
	memset(&orgBlob, 0, sizeof(orgBlob));
	orgBlob.cbData = encBlob.cbData;
	orgBlob.pbData = (BYTE*) new char[encBlob.cbData];
	memcpy(orgBlob.pbData, encBlob.pbData, encBlob.cbData);
	if (!CryptDecrypt(hKey, NULL, TRUE, 0, orgBlob.pbData, &orgBlob.cbData))
	{
		//delete orgBlob.pbData;
		//delete encBlob.pbData;
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		//CancelByError("AES encrypt failed!\n");
		goto errExit;
		
	}

	//保存结果
	*ppOut = orgBlob.pbData;
	*szOut = orgBlob.cbData;

	//清理
	//delete[] orgBlob.pbData;
	//delete[] encBlob.pbData;

	if (hKey != NULL)
	{
		CryptDestroyKey(hKey);
		hKey = NULL;
	}

	if (hProv != NULL)
	{
		CryptReleaseContext(hProv, 0);
		hProv = NULL;
	}

	return 0;
	
errExit:
	return -1;
}

***/