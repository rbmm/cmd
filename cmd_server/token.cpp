#include "stdafx.h"

_NT_BEGIN

#define BEGIN_PRIVILEGES(name, n) static const union { TOKEN_PRIVILEGES name;\
struct { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[n];} label(_) = { n, {

#define LAA_(se) {{se}, SE_PRIVILEGE_ENABLED_BY_DEFAULT|SE_PRIVILEGE_ENABLED }
#define _LAA(se) {{se}}

#define END_PRIVILEGES }};};

extern const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
};

extern const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };

BEGIN_PRIVILEGES(tp_Debug, 2)
	LAA(SE_DEBUG_PRIVILEGE),
	LAA(SE_IMPERSONATE_PRIVILEGE),
END_PRIVILEGES

BEGIN_PRIVILEGES(tp_Assign, 2)
	LAA(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE),
	LAA(SE_INCREASE_QUOTA_PRIVILEGE),
END_PRIVILEGES

NTSTATUS GetToken(_In_ PVOID buf, _In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	do 
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 
				const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE|TOKEN_QUERY, 
						const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						status = NtAdjustPrivilegesToken(hNewToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0);

						if (STATUS_SUCCESS == status)	
						{
							*phToken = hNewToken;
							return STATUS_SUCCESS;
						}

						NtClose(hNewToken);
					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS GetToken(_In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken)
{
	NTSTATUS status;

	ULONG cb = 0x40000;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				status = GetToken(buf, RequiredSet, phToken);

				if (status == STATUS_INFO_LENGTH_MISMATCH)
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}

			delete [] buf;
		}

	} while(status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

NTSTATUS AdjustPrivileges(_In_ const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)))
	{
		status = NtAdjustPrivilegesToken(hToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0);

		NtClose(hToken);

	}

	return status;
}

NTSTATUS GetSystemToken(_Out_ PHANDLE phToken)
{
	NTSTATUS status = AdjustPrivileges(&tp_Debug);

	if (STATUS_SUCCESS == status)
	{
		return GetToken(&tp_Assign, phToken);
	}

	return STATUS_PRIVILEGE_NOT_HELD;
}

EXTERN_C 
WINADVAPI 
BOOL 
WINAPI 
LogonUserExExW(
			   _In_      PCWSTR lpszUsername,
			   _In_      PCWSTR lpszDomain,
			   _In_      PCWSTR lpszPassword,
			   _In_      DWORD dwLogonType,
			   _In_      DWORD dwLogonProvider,
			   _In_opt_  PTOKEN_GROUPS pTokenGroups,
			   _Out_     PHANDLE phToken,
			   _Out_opt_ PSID* ppLogonSid,
			   _Out_     PVOID* ppProfileBuffer,
			   _Out_     DWORD* pdwProfileLength,
			   _Out_opt_ PQUOTA_LIMITS pQuotaLimits
			   );

EXTERN_C 
DECLSPEC_IMPORT 
BOOL 
WINAPI 
WTSQueryUserToken( ULONG SessionId, PHANDLE phToken );

HRESULT GetLastErrorEx(ULONG dwError = GetLastError());

extern volatile const UCHAR guz = 0;

NTSTATUS GetLogonSid(_In_ ULONG SessionId, _Out_ PSID_AND_ATTRIBUTES LogonSid)
{
	HANDLE hToken;

	if (WTSQueryUserToken(SessionId, &hToken))
	{
		NTSTATUS status;

		union {
			PVOID buf;
			PTOKEN_GROUPS ptg;
		};

		PVOID stack = alloca(guz);
		ULONG cb = 0, rcb = 0x100;
		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}
			status = NtQueryInformationToken(hToken, TokenGroups, buf, cb, &rcb);

		} while (STATUS_BUFFER_TOO_SMALL == status);

		NtClose(hToken);

		if (0 > status)
		{
			return status;
		}

		if (ULONG GroupCount = ptg->GroupCount)
		{
			PSID_AND_ATTRIBUTES Groups = ptg->Groups;
			do 
			{
				if (Groups->Attributes & SE_GROUP_LOGON_ID)
				{
					PSID Sid = Groups->Sid;
					if (SECURITY_LOGON_IDS_RID_COUNT == *RtlSubAuthorityCountSid(Sid) &&
						SECURITY_LOGON_IDS_RID == *RtlSubAuthoritySid(Sid, 0))
					{
						LogonSid->Attributes = Groups->Attributes;
						return RtlCopySid(SECURITY_SID_SIZE(SECURITY_LOGON_IDS_RID_COUNT), LogonSid->Sid, Sid);
					}
				}
			} while (Groups++,--GroupCount);
		}

		return STATUS_NO_SUCH_GROUP;
	}

	return GetLastErrorEx();
}

NTSTATUS GetUserToken(_Out_ HANDLE* phToken, 
					  _In_ SECURITY_LOGON_TYPE LogonType,
					  _In_ PCWSTR LogonDomainName, 
					  _In_ PCWSTR UserName, 
					  _In_ PCWSTR Password)
{
	if (Interactive != LogonType)
	{
		if (LogonUserW(UserName, LogonDomainName, Password, LogonType, 
			LOGON32_PROVIDER_WINNT50, phToken))
		{
			return STATUS_SUCCESS;
		}

		return GetLastErrorEx();
	}

	LONG SessionId = WTSGetActiveConsoleSessionId();

	if (0 >= SessionId)
	{
		return STATUS_NO_SUCH_LOGON_SESSION;
	}

	NTSTATUS status;

	UCHAR Sid[SECURITY_SID_SIZE(SECURITY_LOGON_IDS_RID_COUNT)];

	TOKEN_GROUPS LocalGroups = { 1, { Sid } };

	if (S_OK == (status = GetLogonSid(SessionId, LocalGroups.Groups)))
	{
		ULONG cb;
		PVOID ProfileBuffer = 0;
		if (LogonUserExExW(UserName, LogonDomainName, Password, LogonType, 
			LOGON32_PROVIDER_WINNT50, &LocalGroups, phToken, 0, &ProfileBuffer, &cb, 0))
		{
			LsaFreeReturnBuffer(ProfileBuffer);

			if (SessionId - RtlGetCurrentPeb()->SessionId)
			{
				NtSetInformationToken(*phToken, TokenSessionId, &SessionId, sizeof(SessionId));
			}

			return STATUS_SUCCESS;
		}

		return GetLastErrorEx();
	}

	return status;
}

NTSTATUS Elevate(_Inout_ HANDLE* phToken)
{
	union {
		TOKEN_ELEVATION te;
		TOKEN_ELEVATION_TYPE tet;
	};
	TOKEN_LINKED_TOKEN LinkToken = {*phToken};
	ULONG cb;
	NTSTATUS status = NtQueryInformationToken(LinkToken.LinkedToken, TokenElevationType, &tet, sizeof(tet), &cb);

	if (0 <= status)
	{
		switch (tet)
		{
		default:
			return STATUS_INTERNAL_ERROR;
		case TokenElevationTypeFull:
			return STATUS_SUCCESS;
		case TokenElevationTypeDefault:
			if (0 <= (status = NtQueryInformationToken(LinkToken.LinkedToken, TokenElevation, &te, sizeof(te), &cb)))
			{
				if (te.TokenIsElevated)
				{
					return STATUS_SUCCESS;
				}
				return STATUS_NO_TOKEN;
			}
			break;

		case TokenElevationTypeLimited:
			if (0 <= (status = NtQueryInformationToken(LinkToken.LinkedToken, TokenLinkedToken, &LinkToken, sizeof(LinkToken), &cb)))
			{
				NtClose(*phToken);
				*phToken = LinkToken.LinkedToken;
			}
			break;
		}

	}

	return status;
}

_NT_END