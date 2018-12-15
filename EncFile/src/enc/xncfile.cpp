#include "pch.h"
#include "xnc.h"
#include "misc.h"
#include "aes.h"
#include "RSA.h"
#include "stdio.h"

#define PWD_LENGTH 32

void easyXor(BYTE *pCh , int sz)
{
	const BYTE fuck[] = {"It's+a-nice*day/today"};
	const DWORD szfuck = sizeof(fuck) - 1;
	//printf("�ַ�����С %d\n", szfuck);
	for(int i = 0; i < sz; ++i)
	{
		pCh[i] = (pCh[i] ^ fuck[i%szfuck]);
		//pCh[i] = (pCh[i] ^ 1);
	}
}
// �ɹ�0 ʧ��-1
int getRandom(BYTE* buf , int sz)
{
	int ret = -1;
	HCRYPTPROV hProv = NULL;
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (CryptGenRandom(hProv, sz, buf))
		{
			ret = 0;
		}
	}

	if (hProv)
		CryptReleaseContext(hProv,0);

	return ret;
}
// �����ͷ� Buf
int doAES(BYTE* aeskey , DWORD keySize, BYTE* oldBuf, BYTE** newbuf, DWORD* pInOutSz, bool bEnc ,bool b64)
{
	HCRYPTPROV hCryptProv = 0;
	HCRYPTKEY key = 0;
	unsigned char *iv = 0;
	unsigned long cLen = 0;

	if (!myAES::_256::CryptoInit(&key, &hCryptProv, &iv, (const BYTE*)aeskey, keySize))
	{
		//printf("Crypto initializing failed\n");
		return -1;
	}

	if (bEnc == AES_ENC)
	{
		if (!myAES::_256::Encrypt(key, newbuf, oldBuf, pInOutSz, b64))
		{
			//printf("Encryption failed\n");
			if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
			return -1;
		}
	}
#ifdef _DECOPEN
	else if (bEnc == AES_DEC)
	{
		if (!myAES::_256::Decrypt(key, newbuf, oldBuf, pInOutSz, b64))
		{
			printf("Decryption failed\n");
			if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
			return -1;
		}
	}
#endif

	myAES::_256::CryptoUninit(key, hCryptProv);

	SAFE_FREE(iv);

	return 0;
}
// �����ͷ� Buf
int doRSA(BYTE** publicKey, 
	DWORD* publicKeyLen, 
	BYTE** privateKey, 
	DWORD* privateKeyLen, 
	BYTE* oldBuf, 
	BYTE** newbuf, 
	DWORD* pInOutSz,
	int flag , bool b64)
{
	HCRYPTPROV hCryptProv = 0;
	HCRYPTKEY key = 0;


	if (flag == RSA_GEN)
	{
		if ( *publicKeyLen != 0 || *privateKeyLen != 0 || *publicKey != NULL || *privateKey != NULL)
		{
			//printf("Crypto args err -GEN\n");
			return -1;
		}
	}
	else
	{
		if (flag == RSA_ENC)
		{
			if (publicKeyLen == 0 || privateKeyLen != 0)
			{
				//printf("Crypto args err -ENC\n");
				return -1;
			}
		}
		else if (flag == RSA_DEC)
		{
			if (publicKeyLen != 0 || privateKeyLen == 0 )
			{
				//printf("Crypto args err -DEC\n");
				return -1;
			}
		}
	}

	if (!myRSA::_2048::CryptoInit(&key, &hCryptProv, publicKey, publicKeyLen, privateKey, privateKeyLen))
	{
		//printf("Crypto initializing failed\n");
		return -1;
	}

	if (flag == RSA_ENC)
	{
		if (!myRSA::_2048::Encrypt(key, newbuf, oldBuf, pInOutSz, b64))
		{
			//printf("Encryption failed\n");
			if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
			return -1;
		}
	}
#ifdef _DECOPEN
	else if (flag == RSA_DEC)
	{
		if (!myRSA::_2048::Decrypt(key, newbuf, oldBuf, pInOutSz, b64))
		{
			//printf("Decryption failed\n");
			if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
			return -1;
		}
	}
#endif 

	myRSA::_2048::CryptoUninit(key, hCryptProv);
	return 0;
}
#ifdef _DECOPEN
int decfile(char* filepath , char* newfilepath)
{
	int ret = 0;
	BYTE password[PWD_LENGTH] = { 0 };
	BYTE* pfileBuf = NULL;
	DWORD szfile = 0;
	DWORD szOutIn = 0;
	DWORD szAESKey = 0;

	DWORD szAESBuf = 0;
	DWORD szRSABuf = 0;

	BYTE* pAESDecBuf = NULL;
	BYTE* pRSADecBuf = NULL;
	BYTE* pAESBuf = NULL;
	//BYTE *publicKey = 0;
	BYTE *privateKey = 0;

	//unsigned long publicKeyLen = 0;
	unsigned long privateKeyLen = 0;

	// ���ս��ܺ��ļ�����С
	DWORD szPos = 0;

	// 1. ��ȡ�ļ�
	szfile = myMISC::readFile(filepath, &pfileBuf);
	szOutIn = szfile;

	if (szfile > 5120000 + 5000)
	{
		return -1;
	}

	// 2. ��ȡԭʼ�ļ���С
	printf("[+%x]ԭʼ�ļ���С=%d\n", szPos, *(DWORD*)&pfileBuf[0]);

	// 3. ��ȡaes���ܺ���ļ���С
	szPos = sizeof(DWORD);
	szAESBuf = *(DWORD*)(pfileBuf + szPos);
	printf("[+%x]AES���ܺ��ļ���С=%d\n", szPos, szAESBuf);

	// 4. ��ȡ��rsa��Կ���ܺ��aeskey���ĳ���
	szPos = szfile - sizeof(DWORD);
	szRSABuf = *(DWORD*)(pfileBuf + szPos);
	printf("[+%x]RSA���ܺ��AESkey��С=%d\n", szPos, szRSABuf);

	// 5.��λ(����)RSA˽Կ
	privateKeyLen = szfile - sizeof(DWORD) * 3 - szRSABuf - szAESBuf;
	szPos = (szfile - sizeof(DWORD) - privateKeyLen);
	privateKey = pfileBuf + szPos;
	easyXor(privateKey, privateKeyLen);
	printf("[+%x]RSA��Կ��С=%d\n", szPos, privateKeyLen);

	// 6.����RSA��Կ��������
	szOutIn = szRSABuf;
	ret = doRSA(NULL, NULL, &privateKey, &privateKeyLen, (pfileBuf + sizeof(DWORD) * 2 + szAESBuf), &pRSADecBuf, &szOutIn, RSA_DEC, false);
	printf("doRSA[RSA_DEC]=%d\n",ret);

	szAESKey = szOutIn;
	szOutIn = szAESBuf;
	// 7.���ܱ�AES���ܵ�ԭʼ����
	pAESBuf = (pfileBuf + sizeof(DWORD) * 2);
	ret = doAES(pRSADecBuf, szAESKey, pAESBuf , &pAESDecBuf, &szOutIn, AES_DEC, false);
	printf("doRSA[AES_DEC]=%d\n", ret);

	ret = myMISC::writeFile(newfilepath, pAESDecBuf, szOutIn);


	SAFE_FREE(pRSADecBuf);
	SAFE_FREE(pAESDecBuf);
	SAFE_FREE(pfileBuf);

	return 0;
}
#endif
int encfile(char* filepath, char* newfilepath)
{
	int ret = 0;
	BYTE password[PWD_LENGTH] = {0};
	BYTE* pfileBuf = NULL;
	DWORD szfile = 0;
	DWORD szOutIn = 0;
	BYTE* pAESEncBuf = NULL;
	BYTE* pRSAEncBuf = NULL;
	
	BYTE *publicKey = 0;
	BYTE *privateKey = 0;

	unsigned long publicKeyLen = 0;
	unsigned long privateKeyLen = 0;

	// ���ռ��ܺ��ļ�����С
	BYTE* pEnd = NULL;
	DWORD szEnd = 0;
	DWORD szPos = 0;

	// 0. ���������
	if (getRandom(password, PWD_LENGTH))
	{
		//printf("Crypto random failed\n");
		return -1;
	}

	// 1. ��ȡ�ļ�
	szfile = myMISC::readFile(filepath, &pfileBuf);
	szOutIn = szfile;

	if (szfile > 5120000)
	{
		return -1;
	}
	
	szEnd = szfile + 5000;
	pEnd = (BYTE*)malloc(szEnd);
	if (pEnd == NULL)
	{
		return -1;
	}
	
	memset(pEnd, 0, szEnd);

	// a.д��ԭʼ�ļ���С
	memcpy(pEnd + szPos, &szfile, sizeof(DWORD));
	//printf("[%x]д��ԭʼ�ļ���С\n", szPos);
	szPos += sizeof(DWORD);
	

	// 2. aes����ȫ��
	ret = doAES(password, PWD_LENGTH, pfileBuf, &pAESEncBuf, &szOutIn, AES_ENC,false);
	//printf("doAES = %d\n", ret);

	// b.д��AES���ܺ��ļ���С
	memcpy(pEnd + szPos, &szOutIn, sizeof(DWORD));
	//printf("[%x]д��AES���ܺ��ļ���С\n", szPos);
	szPos += sizeof(DWORD);
	

	// c.д��aes���ܺ�����
	memcpy(pEnd + szPos, pAESEncBuf, szOutIn);
	//printf("[%x]д��aes���ܺ�����\n", szPos);
	szPos += szOutIn;

	SAFE_FREE(pAESEncBuf);

	// 3. rsa ��Կ����aes��key
	ret = doRSA(&publicKey, &publicKeyLen, &privateKey, &privateKeyLen, NULL, NULL, NULL, RSA_GEN, false);
	//printf("doRSA [RSA_GEN]= %d\n", ret);

	szOutIn = PWD_LENGTH;
	ret = doRSA(&publicKey, &publicKeyLen, NULL, NULL, password, &pRSAEncBuf, &szOutIn, RSA_ENC, false);
	//printf("doRSA [RSA_ENC]= %d\n", ret);

	// d.д��rsa���ܺ��aeskey
	memcpy(pEnd + szPos, pRSAEncBuf, szOutIn);
	//printf("[%x]д��rsa���ܺ��aeskey��С=%d\n", szPos, szOutIn);
	szPos += szOutIn;


	SAFE_FREE(pRSAEncBuf);

	// e. д��rsa˽Կ
	easyXor(privateKey, privateKeyLen);
	memcpy(pEnd + szPos, privateKey, privateKeyLen);
	//printf("[%x]д��rsa˽Կ��С=%d\n", szPos, privateKeyLen);
	szPos += privateKeyLen;

	SAFE_FREE(publicKey);
	SAFE_FREE(privateKey);

	// f. д��d.�ĳ���
	memcpy(pEnd + szPos, &szOutIn, sizeof(DWORD));
	//printf("[%x]д��\"rsa���ܺ��aeskey\"\n", szPos);
	szPos += sizeof(DWORD);

	// 5. д�ļ�
	//pEnd = pEncBuf;
	//szEnd = szOutIn;

	ret = myMISC::writeFile(newfilepath, pEnd, szPos);
	
	SAFE_FREE(pEnd);
	SAFE_FREE(pfileBuf);
	return 0;
}