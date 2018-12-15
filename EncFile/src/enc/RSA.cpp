#include "pch.h"
#include "RSA.h"
#include "misc.h"
#define RSA2048BIT_KEY 0x8000000

#include "stdio.h"


static bool generateKeys(HCRYPTKEY *key, HCRYPTPROV provider, unsigned char **publicKey, unsigned long* pubkl, unsigned char **privateKey , unsigned long* prikl)
{
	unsigned long publicKeyLen = 0;
	unsigned long privateKeyLen = 0;

	if (!provider)
		return false;

	if (!CryptGenKey(provider, AT_KEYEXCHANGE, RSA2048BIT_KEY | CRYPT_EXPORTABLE, key))
	{
		return false;
	}

	if (!CryptExportKey(*key, 0, PUBLICKEYBLOB, 0, NULL, &publicKeyLen))
	{
		if (*key) CryptDestroyKey(*key);
		return false;
	}

	*publicKey = (unsigned char *)malloc(publicKeyLen * sizeof(unsigned char));
	if (*publicKey == NULL)
	{
		if (*key) CryptDestroyKey(*key);
		return false;
	}
	SecureZeroMemory(*publicKey, publicKeyLen * sizeof(unsigned char));

	if (!CryptExportKey(*key, 0, PUBLICKEYBLOB, 0, *publicKey, &publicKeyLen))
	{
		SAFE_FREE(*publicKey);
		if (*key) CryptDestroyKey(*key);
		return false;
	}

	if (!CryptExportKey(*key, 0, PRIVATEKEYBLOB, 0, NULL, &privateKeyLen))
	{
		SAFE_FREE(*publicKey);
		if (*key) CryptDestroyKey(*key);
		return false;
	}

	*privateKey = (unsigned char *)malloc(privateKeyLen * sizeof(unsigned char));
	if (*privateKey == NULL)
	{
		SAFE_FREE(*publicKey);
		if (*key) CryptDestroyKey(*key);
		return false;
	}
	SecureZeroMemory(*privateKey, privateKeyLen * sizeof(unsigned char));

	if (!CryptExportKey(*key, 0, PRIVATEKEYBLOB, 0, *privateKey, &privateKeyLen))
	{
		SAFE_FREE(*publicKey);
		SAFE_FREE(*privateKey);
		if (*key) CryptDestroyKey(*key);
		return false;
	}

	*pubkl = publicKeyLen;
	*prikl = privateKeyLen;

	return true;
}

bool myRSA::_2048::CryptoInit(HCRYPTKEY *key, HCRYPTPROV *provider, unsigned char **publicKey, unsigned long* pubkl , unsigned char **privateKey , unsigned long* prikl)
{
	if (!CryptAcquireContextW(provider, NULL, NULL, PROV_RSA_FULL, 0))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			// CRYPT_VERIFYCONTEXT 指出应用程序不需要使用公钥/私钥对，如程序只执行哈希和对称加密。只有程序需要创建签名和解密消息时才需要访问私钥。
			// CRYPT_NEWKEYSET  使用指定的密钥容器名称创建一个新的密钥容器。如果pszContainer为NULL，密钥容器就使用却省的名称创建。
			if (!CryptAcquireContextW(provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	if (pubkl != NULL && *pubkl != 0)
	{
		if (!CryptImportKey(*provider, *publicKey, *pubkl, NULL, NULL, key))
		{
			if (*provider) CryptReleaseContext(*provider, 0);
			return false;
		}
		
	}

	if (prikl != NULL && *prikl != 0)
	{
		if (!CryptImportKey(*provider, *privateKey, *prikl, NULL, NULL, key))
		{
			if (*provider) CryptReleaseContext(*provider, 0);
			return false;
		}
	}

	if (prikl && pubkl &&  *prikl == 0 && *pubkl == 0)
	{
		if (!generateKeys(key, *provider, publicKey, pubkl, privateKey, prikl))
		{
			if (*provider) CryptReleaseContext(*provider, 0);
			return false;
		}
	}



	return true;
}

bool myRSA::_2048::Encrypt(HCRYPTKEY key, BYTE **cipherText, BYTE *plainText,  unsigned long* pinOutLen , bool b64)
{
	unsigned long len = 0;
	unsigned char *encrypted = 0;
	unsigned long enLen = 0;

	len = *pinOutLen;

	if (!CryptEncrypt(key, 0, TRUE, 0, NULL, &len, 0))
	{
		if (key) CryptDestroyKey(key);
#ifdef _DEBUG
		printf("Error: %x\n", GetLastError());
#endif
		return false;
	}

	enLen = len;

	encrypted = (BYTE *)malloc(len * sizeof(BYTE));
	if (encrypted == NULL)
	{
		if (key) CryptDestroyKey(key);
		return false;
	}
	SecureZeroMemory(encrypted, len * sizeof(BYTE));

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
	else if (!b64)
	{

		//memcpy_s(*cipherText, enLen, encrypted, enLen);
		*cipherText = encrypted;
		*pinOutLen = enLen;
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
bool myRSA::_2048::Decrypt(HCRYPTKEY key, BYTE **plainText, BYTE *cipherText, unsigned long* pinOutLen , bool b64)
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


	*plainText = (unsigned char *)malloc(decodedLen * sizeof(unsigned char));
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
		SAFE_FREE(*plainText);
		if (key) CryptDestroyKey(key);
		return false;
	}

	*pinOutLen = len;
	return true;
}
#endif

int myRSA::_2048::CryptoUninit(HCRYPTKEY key, HCRYPTPROV provider)
{
	int ret = 0;
	do {
		if (key)
			if (!CryptDestroyKey(key))
				//printf("Error: %d\n", GetLastError());
			{
				ret = -1;
				break;
			}
		if (provider)
			if (!CryptReleaseContext(provider, 0))
				//printf("Error: %d\n", GetLastError());
			{
				ret = -1;
				break;
			}

		if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET))
			//printf("Error: %d\n", GetLastError());
		{
			ret = -1;
			break;
		}

	} while (FALSE);

	return ret;
}




















/*****
#define ALG_NAME "AlejaCMa.EncryptDecrypt"

int myRSA::Gen(BYTE **pub, DWORD* szPub, BYTE** pri, DWORD* szPri)
{
	// Variables
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD dwPublicKeyLen = 0;
	DWORD dwPrivateKeyLen = 0;
	BYTE* pbPublicKey = NULL;
	BYTE* pbPrivateKey = NULL;


	__try
	{
		// Acquire access to key container
		//_tprintf(_T("CryptAcquireContext...\n"));
		if (!CryptAcquireContextA(&hCryptProv, ALG_NAME, NULL, PROV_RSA_FULL, 0))
		{
			// Error
			//_tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());

			// Try to create a new key container
			if (!CryptAcquireContextA(&hCryptProv, ALG_NAME, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				// Error
				//_tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());
				return -1;
			}
		}

		// Generate new key pair
		//_tprintf(_T("CryptGenKey...\n"));
		if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_ARCHIVABLE, &hKey))
		{
			// Error
			//_tprintf(_T("CryptGenKey error 0x%x\n"), GetLastError());
			return -1;
		}

		// Get public key size
		//_tprintf(_T("CryptExportKey...\n"));
		if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen))
		{
			// Error
			//_tprintf(_T("CryptExportKey error 0x%x\n"), GetLastError());
			return -1;
		}

		// Create a buffer for the public key
		//_tprintf(_T("malloc...\n"));
		if (!(pbPublicKey = (BYTE *)new char[dwPublicKeyLen]))
		{
			// Error
			//_tprintf(_T("malloc error 0x%x\n"), GetLastError());
			return -1;
		}

		// Get public key
		//_tprintf(_T("CryptExportKey...\n"));
		if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen))
		{
			// Error
			//_tprintf(_T("CryptExportKey error 0x%x\n"), GetLastError());
			return -1;
		}

		// Get private key size
		//_tprintf(_T("CryptExportKey...\n"));
		if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwPrivateKeyLen))
		{
			// Error
			//_tprintf(_T("CryptExportKey error 0x%x\n"), GetLastError());
			return -1;
		}

		// Create a buffer for the private key
		//_tprintf(_T("malloc...\n"));
		if (!(pbPrivateKey = (BYTE *)new char [dwPrivateKeyLen]))
		{
			// Error
			//_tprintf(_T("malloc error 0x%x\n"), GetLastError());
			return -1;
		}

		// Get private key
		//_tprintf(_T("CryptExportKey...\n"));
		if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, pbPrivateKey, &dwPrivateKeyLen))
		{
			// Error
			//_tprintf(_T("CryptExportKey error 0x%x\n"), GetLastError());
			return -1;
		}

		// 已经获得 公钥和私钥
		*pub = pbPublicKey;
		*szPub = dwPublicKeyLen;

		*pri = pbPrivateKey;
		*szPri = dwPrivateKeyLen;

		return 0;
	}
	__finally
	{
// Clean up       
//		if (!pbPublicKey) {
			//_tprintf(_T("free...\n"));
//			delete (pbPublicKey);
//		}
//		if (!pbPrivateKey) {
			//_tprintf(_T("free...\n"));
//			delete (pbPrivateKey);
//		}
		if (hKey) {
			//_tprintf(_T("CryptDestroyKey...\n"));
			CryptDestroyKey(hKey);
		}
		if (hCryptProv) {
			//_tprintf(_T("CryptReleaseContext...\n"));
			CryptReleaseContext(hCryptProv, 0);
		}

	}

	return 0;
}
//
int myRSA::Enc(BYTE* pData, DWORD szData, BYTE* key, DWORD keyLen, OUT BYTE** ppOut, OUT DWORD* szOut)
{
	// Variables
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;

	DWORD dwPublicKeyLen = 0;
	DWORD dwDataLen = 0;
	DWORD dwEncryptedLen = 0;

	BYTE* pbPublicKey = NULL;
	BYTE* pbData = NULL;
	BYTE* pbEncData = NULL;



	__try
	{
		// Acquire access to key container
		//_tprintf(_T("CryptAcquireContext...\n"));
		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			// Error
			//_tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());
			return -1;
		}

		dwPublicKeyLen = keyLen;
		pbPublicKey = key;

		dwDataLen = szData;
		pbData = pData;


		// Import public key
		//_tprintf(_T("CryptImportKey...\n"));
		if (!CryptImportKey(hCryptProv, pbPublicKey, dwPublicKeyLen, 0, 0, &hKey))
		{
			// Error
			//_tprintf(_T("CryptImportKey error 0x%x\n"), GetLastError());
			return -1;
		}

		// Get lenght for encrypted data
		if (!CryptEncrypt(hKey, NULL, TRUE, 0, NULL, &dwEncryptedLen, 0))
		{
			// Error
			//_tprintf(_T("CryptEncrypt error 0x%x\n"), GetLastError());
			return -1;
		}

		// Create a buffer for encrypted data
		if (!(pbEncData = (BYTE*)new char[dwEncryptedLen]))
		{
			// Error
			//_tprintf(_T("malloc error 0x%x\n"), GetLastError());
			return -1;
		}

		CopyMemory(pbEncData, pbData, dwDataLen);
		// Encrypt data
		if (!CryptEncrypt(hKey, NULL, TRUE, 0, pbEncData, &dwDataLen, dwEncryptedLen))
		{
			// Error
			//_tprintf(_T("CryptEncrypt error 0x%x\n"), GetLastError());
			return -1;
		}

		//返回值
		*ppOut = pbEncData;
		*szOut = dwEncryptedLen;

		return 0;
	}
	__finally
	{
		// Clean up
//		if (!pbPublicKey) {
			//_tprintf(_T("free...\n"));
//			delete (pbPublicKey);
//		}
//		if (!pbData) {
			//_tprintf(_T("free...\n"));
//			delete (pbData);
//		}
		if (hKey) {
			//_tprintf(_T("CryptDestroyKey...\n"));
			CryptDestroyKey(hKey);
		}
		if (hCryptProv) {
			//_tprintf(_T("CryptReleaseContext...\n"));
			CryptReleaseContext(hCryptProv, 0);
		}

	}


	return 0;
}

int myRSA::Dec(BYTE* pData, DWORD szData, BYTE* key, DWORD keyLen, OUT BYTE** ppOut, OUT DWORD* szOut)
{
	// Variables
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD dwPrivateKeyLen = 0;
	DWORD dwDataLen = 0;
	BYTE* pbPrivateKey = NULL;
	BYTE* pbData = NULL;
	HANDLE hPrivateKeyFile = NULL;
	HANDLE hEncryptedFile = NULL;
	HANDLE hPlainFile = NULL;
	DWORD lpNumberOfBytesWritten = 0;


	__try
	{
		// Acquire access to key container
		//_tprintf(_T("CryptAcquireContext...\n"));
		if (!CryptAcquireContextA(&hCryptProv, ALG_NAME, NULL, PROV_RSA_FULL, 0))
		{
			// Error
			//_tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());

			// Try to create a new key container
			if (!CryptAcquireContextA(&hCryptProv, ALG_NAME, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				// Error
				//_tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());
				return -1;
			}
		}

		// import pri key
		pbPrivateKey = key;
		dwPrivateKeyLen = keyLen;

		// 
		dwDataLen = szData;
		if (!(pbData = (BYTE*) new char[szData]))
		{
			return -1;
		}

		CopyMemory(pbData, pData, szData);

		// Get lenght for plain text
		if (!CryptDecrypt(hKey, NULL, TRUE, 0, pbData, &dwDataLen))
		{
			// Error
			//_tprintf(_T("CryptDecrypt error 0x%x\n"), GetLastError());
			return -1;
		}
		*ppOut = pbData;
		*szOut = dwDataLen;

		return 0;
	}
	__finally
	{
		// Clean up       
//		if (!pbPrivateKey) {
			//_tprintf(_T("free...\n"));
//			delete (pbPrivateKey);
//		}
//		if (!pbData) {
			//_tprintf(_T("free...\n"));
//			delete (pbData);
//		}

		if (hKey) {
			//_tprintf(_T("CryptDestroyKey...\n"));
			CryptDestroyKey(hKey);
		}
		if (hCryptProv) {
			//_tprintf(_T("CryptReleaseContext...\n"));
			CryptReleaseContext(hCryptProv, 0);
		}
	}

	return 0;
}

*****/