#pragma once

NTSTATUS GetSystemToken(_Out_ PHANDLE phToken);

struct PFX 
{
	BCRYPT_KEY_HANDLE _M_hKey = 0;
	PBYTE _M_pbCertEncoded = 0;
	ULONG _M_cbCertEncoded = 0;
	ULONG _M_BlockLength = 0;

	~PFX()
	{
		if (_M_pbCertEncoded) delete [] _M_pbCertEncoded;
		if (_M_hKey) BCryptDestroyKey(_M_hKey);
	}

	HRESULT Open(_In_ PCWSTR szPfx, _In_ PCWSTR szPassword);
};

inline HRESULT GetLastHresult(BOOL fOk)
{
	return fOk ? S_OK : GetLastErrorEx();
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PBYTE pb, _In_ ULONG cb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return GetLastHresult(CryptDecodeObjectEx(X509_ASN_ENCODING, lpszStructType, pb, cb,
		CRYPT_DECODE_ALLOC_FLAG|
		CRYPT_DECODE_NOCOPY_FLAG|
		CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG|
		CRYPT_DECODE_SHARE_OID_STRING_FLAG, 
		0, ppv, pcb ? pcb : &cb));
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_DATA_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_BIT_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}
