#include "stdafx.h"

_NT_BEGIN

#include "msgbox.h"
#include "pfx.h"
#include "tls.h"

NTSTATUS CreateAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE secret, _In_ ULONG cb)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
	{
		status = BCryptGenerateSymmetricKey(hAlgorithm, phKey, 0, 0, secret, cb, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS CreateSimplyPacket(_Out_ CDataPacket** ppacket, 
							_In_ LONG i,
							_In_ ULONG ckey,
							_In_ ULONG64 skey,
							_In_ const void* pbExtra,
							_In_ ULONG cbExtra)
{
	if (CDataPacket* packet = new(sizeof(G_PKT) + cbExtra) CDataPacket)
	{
		G_PKT* pkt = (G_PKT*)packet->getData();

		pkt->_M_i = i;
		pkt->_M_skey = skey;
		pkt->_M_ckey = ckey;

		packet->setDataSize(sizeof(G_PKT) + cbExtra);
		if (cbExtra)
		{
			memcpy(pkt->_M_buf, pbExtra, cbExtra);
		}
		*ppacket = packet;

		return STATUS_SUCCESS;
	}

	return NTE_NO_MEMORY;
}

NTSTATUS CreatePacket(_Out_ CDataPacket** ppacket, 
					  _In_ BCRYPT_KEY_HANDLE hKey,
					  _In_ LONG i,
					  _In_ ULONG ckey,
					  _In_ ULONG64 skey,
					  _In_ const void* pbData, 
					  _In_ ULONG cbData, 
					  _In_ const void* pbExtra,
					  _In_ ULONG cbExtra)
{
	PBYTE pb = 0;
	ULONG cb = 0;
	G_PKT* pkt = 0;
	CDataPacket* packet = 0;
	NTSTATUS status;

	ULONG dwFlags = i ? BCRYPT_BLOCK_PADDING : BCRYPT_PAD_PKCS1;

	while (0 <= (status = BCryptEncrypt(hKey, (PBYTE)pbData, cbData, 0, 0, 0, pb, cb, &cb, dwFlags)))
	{
		if (pb)
		{
			pkt->_M_i = i;
			pkt->_M_skey = skey;
			pkt->_M_ckey = ckey;

			if (cbExtra)
			{
				memcpy(pb + cb, pbExtra, cbExtra);
			}

			packet->setDataSize(cb += sizeof(G_PKT) + cbExtra);
			*ppacket = packet;
			return S_OK;
		}

		if (!(packet = new(sizeof(G_PKT) + cb + cbExtra) CDataPacket))
		{
			return NTE_NO_MEMORY;
		}

		pkt = (G_PKT*)packet->getData();
		pb = pkt->_M_buf;
	}

	if (packet) packet->Release();
	return status;
}

NTSTATUS CreatePacket(_Out_ CDataPacket** ppacket, 
					  _In_ BCRYPT_KEY_HANDLE hRsaKey,
					  _In_ BCRYPT_KEY_HANDLE hAesKey,
					  _In_ ULONG ckey,
					  _In_ ULONG64 skey,
					  _In_ const void* pbData, 
					  _In_ ULONG cbData, 
					  _In_ const void* pbExtra,
					  _In_ ULONG cbExtra)
{
	PBYTE pb = 0;
	ULONG cb1 = 0, cb2 = 0;
	G_PKT* pkt = 0;
	CDataPacket* packet = 0;
	NTSTATUS status;

	while (0 <= (status = BCryptEncrypt(hRsaKey, (PBYTE)pbData, cbData, 0, 0, 0, pb, cb1, &cb1, BCRYPT_PAD_PKCS1)) &&
		0 <= (status = BCryptEncrypt(hAesKey, (PBYTE)pbExtra, cbExtra, 0, 0, 0, pb ? pb + cb1 : 0, cb2, &cb2, BCRYPT_BLOCK_PADDING)))
	{
		if (pb)
		{
			pkt->_M_i = 0;
			pkt->_M_skey = skey;
			pkt->_M_ckey = ckey;
			packet->setDataSize(sizeof(G_PKT) + cb1 + cb2);

			*ppacket = packet;
			return S_OK;
		}

		if (!(packet = new(sizeof(G_PKT) + cb1 + cb2) CDataPacket))
		{
			return NTE_NO_MEMORY;
		}

		pkt = (G_PKT*)packet->getData();
		pb = pkt->_M_buf;
	}

	if (packet) packet->Release();
	return status;
}

NTSTATUS DecryptData(BCRYPT_KEY_HANDLE hKey, PBYTE pb, ULONG cb, PULONG pcb, ULONG dwFlags)
{
	return BCryptDecrypt(hKey, pb, cb, 0, 0, 0, pb, cb, pcb, dwFlags);
}

BOOL DecryptPacket(_Inout_ G_PKT* pkt, _In_ ULONG cb, _In_ BCRYPT_KEY_HANDLE hKey, _Out_ PULONG pcb)
{
	return sizeof(G_PKT) < cb && 0 <= DecryptData(hKey, pkt->_M_buf, cb - sizeof(G_PKT), pcb, BCRYPT_BLOCK_PADDING);
}

BOOL GetPubKeyFromPkt(_In_ G_PKT* pkt, _In_ ULONG cb, _In_ ULONG ofs, _Out_ BCRYPT_KEY_HANDLE *phKey)
{
	if (PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, 
		pkt->_M_buf + ofs, cb - ofs - sizeof(G_PKT)))
	{
		BOOL f = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &pCertContext->pCertInfo->SubjectPublicKeyInfo, 0, 0, phKey);
		CertFreeCertificateContext(pCertContext);

		return f;
	}

	return FALSE;
}

// client: 
// in:  [0][c-k][s-k][16r][s-cert]
// out: [1][c-k][s-k][16r][auth]
BOOL Client_0_1(_Inout_ G_PKT* pkt, 
				_In_ ULONG cb, 
				_In_ BCRYPT_KEY_HANDLE hKey,
				_In_ ULONG BlockLength,
				_In_ PVOID pvAuth,
				_In_ ULONG cbAuth,
				_Out_ CDataPacket** ppacket,
				_Out_ BCRYPT_KEY_HANDLE* phKey)
{
	if (cb <= sizeof(G_PKT) + BlockLength)
	{
		return FALSE;
	}

	UCHAR secret[32];

	ULONG s;
	BCRYPT_KEY_HANDLE hAesKey;
	if (0 <= BCryptDecrypt(hKey, pkt->_M_buf, BlockLength, 0, 0, 0, secret + 16, 16, &s, BCRYPT_PAD_PKCS1) &&
		16 == s &&
		0 <= BCryptGenRandom(0, secret, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) &&
		0 <= CreateAesKey(&hAesKey, secret, 32))
	{
		if (GetPubKeyFromPkt(pkt, cb, BlockLength, &hKey))
		{
			NTSTATUS status = CreatePacket(ppacket, hKey, hAesKey, pkt->_M_ckey, pkt->_M_skey, secret, 16, pvAuth, cbAuth);

			BCryptDestroyKey(hKey);

			if (0 <= status)
			{
				*phKey = hAesKey;
				return TRUE;
			}
		}

		BCryptDestroyKey(hAesKey);
	}

	return FALSE;
}

// client: 
// in:  [1][c-k][s-k][16r][auth]
BOOL Server_1_1(_Inout_ G_PKT* pkt, 
				_In_ ULONG cb, 
				_In_ BCRYPT_KEY_HANDLE hKey,
				_In_ ULONG BlockLength,
				_In_ UCHAR random[],
				_Out_ BCRYPT_KEY_HANDLE* phKey,
				_Out_ PULONG pcb)
{
	if (cb <= sizeof(G_PKT) + BlockLength)
	{
		return FALSE;
	}

	UCHAR secret[32];

	memcpy(secret + 16, random, 16);

	ULONG s;
	BCRYPT_KEY_HANDLE hAesKey;
	if (0 <= BCryptDecrypt(hKey, pkt->_M_buf, BlockLength, 0, 0, 0, secret, 16, &s, BCRYPT_PAD_PKCS1) &&
		16 == s &&
		0 <= CreateAesKey(&hAesKey, secret, 32))
	{
		if (0 <= DecryptData(hAesKey, pkt->_M_buf + BlockLength, cb - BlockLength - sizeof(G_PKT), pcb, BCRYPT_BLOCK_PADDING))
		{
			*phKey = hAesKey;
			return TRUE;
		}

		BCryptDestroyKey(hAesKey);
	}

	return FALSE;
}

PWSTR CreateStringBlock(PCSTR pcsz, PWSTR ppwsz[], ULONG n)
{
	PWSTR pwz = 0, pzAuth = 0;
	ULONG cb = 0, cch, len, cbNeed = 0;
	PCSTR psz = pcsz;

	do 
	{
		while ( cch = (ULONG)strlen(pcsz))
		{
			if ( len = MultiByteToWideChar(CP_UTF8, 0, pcsz, ++cch, pwz, cb))
			{
				if (pwz)
				{
					if (n)
					{
						*ppwsz++ = pwz, n--;
					}
					pwz += len, cb -= len;
				}
				else
				{
					cbNeed += len;
				}

				pcsz += cch;
				continue;
			}

			if (pzAuth)
			{
				delete [] pzAuth;
			}

			return 0;
		}

		if (pzAuth)
		{
			return pzAuth;
		}

		pcsz = psz;

	} while (pzAuth = pwz = new WCHAR[cb = cbNeed]);

	return 0;
}

_NT_END