#pragma once

#include "../asio/packet.h"
#include "pkt.h"

/*
C S
---> [0][c-k][ 0 ][c-cert]
<--- [0][c-k][s-k][16r][s-cert]
---> [0][c-k][s-k][16r][auth]
<--- [80000000][c-k][s-k]
*/

NTSTATUS CreatePacket(_Out_ CDataPacket** ppacket, 
					  _In_ BCRYPT_KEY_HANDLE hKey,
					  _In_ LONG i,
					  _In_ ULONG ckey,
					  _In_ ULONG64 skey,
					  _In_ const void* pbData = 0, 
					  _In_ ULONG cbData = 0, 
					  _In_ const void* pbExtra = 0,
					  _In_ ULONG cbExtra = 0);

NTSTATUS CreatePacket(_Out_ CDataPacket** ppacket, // i = 0, client only
					  _In_ BCRYPT_KEY_HANDLE hRsaKey,
					  _In_ BCRYPT_KEY_HANDLE hAesKey,
					  _In_ ULONG ckey,
					  _In_ ULONG64 skey,
					  _In_ const void* pbData, 
					  _In_ ULONG cbData, 
					  _In_ const void* pbExtra,
					  _In_ ULONG cbExtra);

NTSTATUS CreateSimplyPacket(_Out_ CDataPacket** ppacket, 
							_In_ LONG i,
							_In_ ULONG ckey,
							_In_ ULONG64 skey,
							_In_ const void* pbExtra = 0,
							_In_ ULONG cbExtra = 0);

NTSTATUS DecryptData(BCRYPT_KEY_HANDLE hKey, PBYTE pb, ULONG cb, PULONG pcb, ULONG dwFlags);

BOOL DecryptPacket(_Inout_ G_PKT* pkt, _In_ ULONG cb, _In_ BCRYPT_KEY_HANDLE hKey, _Out_ PULONG pcb);

BOOL Client_0_1(_Inout_ G_PKT* pkt, 
				_In_ ULONG cb, 
				_In_ BCRYPT_KEY_HANDLE hKey,
				_In_ ULONG BlockLength,
				_In_ PVOID pvAuth,
				_In_ ULONG cbAuth,
				_Out_ CDataPacket** ppacket,
				_Out_ BCRYPT_KEY_HANDLE* phKey);

BOOL Server_1_1(_Inout_ G_PKT* pkt, 
				_In_ ULONG cb, 
				_In_ BCRYPT_KEY_HANDLE hKey,
				_In_ ULONG BlockLength,
				_In_ UCHAR random[],
				_Out_ BCRYPT_KEY_HANDLE* phKey,
				_Out_ PULONG pcb);

BOOL GetPubKeyFromPkt(_In_ G_PKT* pkt, _In_ ULONG cb, _In_ ULONG ofs, _Out_ BCRYPT_KEY_HANDLE *phKey);

struct LGOPT {
	UCHAR LogonType;
	BOOLEAN bElevated;
	char buf[];

	void* operator new(size_t s, ULONG cb)
	{
		return LocalAlloc(LMEM_FIXED, s + cb);
	}

	void operator delete(void* pv)
	{
		LocalFree(pv);
	}
};

PWSTR CreateStringBlock(PCSTR pcsz, PWSTR ppwsz[], ULONG n);//server

LGOPT* CreateAuthBlock(UCHAR LogonType, 
					   BOOLEAN bElevated, 
					   HWND hwnd, 
					   const UINT id[],
					   ULONG n,
					   PULONG pcb);