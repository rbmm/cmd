#include "stdafx.h"
#include "../NtVer/nt_ver.h"

const BYTE* GetShrouedKeyBag(const BYTE* pbBuffer, ULONG cbLength, _Out_ PDATA_BLOB pdb);

_NT_BEGIN

#include "pkcs.h"
#include "msgbox.h"
#include "pfx.h"

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, 
					  _Out_ PBYTE* ppb, 
					  _Out_ ULONG* pcb)
{
	UNICODE_STRING ObjectName;
	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);
	HANDLE hFile;

	if (0 <= status)
	{
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		IO_STATUS_BLOCK iosb;
		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			FILE_STANDARD_INFORMATION fsi;
			if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
			{
				if (PBYTE pb = new BYTE[fsi.EndOfFile.LowPart])
				{
					if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
					{
						delete [] pb;
					}
					else
					{
						*ppb = pb;
						*pcb = (ULONG)iosb.Information;
					}
				}
				else
				{
					status = STATUS_NO_MEMORY;
				}
			}

			NtClose(hFile);
		}
	}

	return status;
}

BOOL HashKey(BCRYPT_RSAKEY_BLOB* pbrb, ULONG cb, PULONG pcrc)
{
	if (cb <= sizeof(BCRYPT_RSAKEY_BLOB))
	{
		return FALSE;
	}

	switch (pbrb->Magic)
	{
	case BCRYPT_RSAPUBLIC_MAGIC:
	case BCRYPT_RSAPRIVATE_MAGIC:
	case BCRYPT_RSAFULLPRIVATE_MAGIC:
		break;
	default:
		return FALSE;
	}

	cb -= sizeof(BCRYPT_RSAKEY_BLOB);

	ULONG cbPublicExp = pbrb->cbPublicExp;

	if (cb <= cbPublicExp)
	{
		return FALSE;
	}

	cb -= cbPublicExp;

	if (cb < pbrb->cbModulus)
	{
		return FALSE;
	}

	*pcrc = RtlComputeCrc32(pbrb->BitLength, pbrb + 1, cbPublicExp + pbrb->cbModulus);
	return TRUE;
}

BOOL IsCertMatch(_In_ PCCERT_CONTEXT pCertContext, _In_ ULONG crc)
{
	PBYTE pb;
	ULONG cb;
	if (NOERROR == Decode(CNG_RSA_PUBLIC_KEY_BLOB, 
		&pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey, &pb, &cb))
	{
		if (HashKey((BCRYPT_RSAKEY_BLOB*)pb, cb, &cb))
		{
			crc -= cb;
		}
		LocalFree(pb);
	}

	return !crc;
}

HRESULT PFX::Open(_In_ PCWSTR szPfx, _In_ PCWSTR szPassword)
{
	DATA_BLOB db {}, dbPFX;
	NTSTATUS status = ReadFromFile(szPfx, &dbPFX.pbData, &dbPFX.cbData);

	if (0 <= status)
	{
		status = NTE_NOT_FOUND;

		if (GetShrouedKeyBag(dbPFX.pbData, dbPFX.cbData, &db) && db.pbData)
		{
			ULONG crc = 0, cb;
			BCRYPT_KEY_HANDLE hKey;
			if (S_OK == (status = PkcsImportEncodedKey(&hKey, db.pbData, db.cbData, szPassword, &crc)))
			{
				if (0 <= (status = BCryptGetProperty(hKey, BCRYPT_BLOCK_LENGTH, 
					(PBYTE)&_M_BlockLength, sizeof(_M_BlockLength), &cb, 0)))
				{
					if (HCERTSTORE hStore = HR(status, PFXImportCertStore(&dbPFX, szPassword, 
						g_nt_ver.Major < (_WIN32_WINNT_WIN10 >> 8) ? PKCS12_NO_PERSIST_KEY : PKCS12_ONLY_CERTIFICATES)))
					{
						PCCERT_CONTEXT pCertContext = 0;

						status = CRYPT_E_NOT_FOUND;

						while (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext))
						{
							if (IsCertMatch(pCertContext, crc))
							{
								status = STATUS_NO_MEMORY;

								if (PBYTE pb = new BYTE[crc = pCertContext->cbCertEncoded])
								{
									memcpy(pb, pCertContext->pbCertEncoded, crc);
									_M_cbCertEncoded = crc, _M_pbCertEncoded = pb, _M_hKey = hKey, hKey = 0;
									status = S_OK;
								}
								CertFreeCertificateContext(pCertContext);
								break;
							}
						}

						CertCloseStore(hStore, 0);
					}
				}

				if (hKey) BCryptDestroyKey(hKey);
			}
		}

		LocalFree(dbPFX.pbData);
	}

	return status;
}

_NT_END