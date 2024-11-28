#include "StdAfx.h"

_NT_BEGIN

#include "../asio/port.h"
#include "../asio/pipe.h"
#include "../winZ/app.h"
#include "../winZ/window.h"
#include "../winZ/ctrl.h"
#include "msgbox.h"
#include "pfx.h"
#define DbgPrint /##/
//
volatile UCHAR guz = 0;

LONG MaxClientCount = 4;

enum { WM_CONNECT = WM_APP, WM_DISCONNECT};

#include "tls.h"

#define RTL_USER_PROC_UTF8_PROCESS 0x08000000

NTSTATUS SetPtocessUtf8(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;
	_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	ULONG Flags;
	NTSTATUS status;

	0 <= (status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0)) &&
		0 <= (status = ZwReadVirtualMemory(hProcess, &reinterpret_cast<_PEB*>(pbi.PebBaseAddress)->ProcessParameters, &ProcessParameters, sizeof(ProcessParameters), 0)) &&
		0 <= (status = ZwReadVirtualMemory(hProcess, &ProcessParameters->Flags, &Flags, sizeof(Flags), 0)) &&
		0 <= (status = ZwWriteVirtualMemory(hProcess, &ProcessParameters->Flags, &(Flags |= RTL_USER_PROC_UTF8_PROCESS), sizeof(Flags), 0));

	return status;
}

ULONG RestrictProcess(HANDLE hProcess)
{
	if (HANDLE hJob = CreateJobObject(0, 0))
	{
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION jbli;
		jbli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

		if (SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jbli, sizeof(jbli)) &&
			AssignProcessToJobObject(hJob, hProcess))
		{
			return BOOL_TO_ERROR(DuplicateHandle(NtCurrentProcess(), hJob, hProcess, 0, 0, FALSE, DUPLICATE_CLOSE_SOURCE));
		}

		NtClose(hJob);
	}

	return GetLastError();
}

struct CmdPipe : public CPipeEnd, public LIST_ENTRY
{
	ULONG64 _M_key, _dwTime = GetTickCount64() + 5000;
	CUdpEndpoint* _pSocket = 0;
	BCRYPT_KEY_HANDLE _M_hKey = 0;
	HANDLE _hProcess = 0;
	ULONG _dwProcessId = 0;
	ULONG _M_rkey;
	LONG _M_nextID = 0;
	union {
		SOCKADDR_IN_EX _addr;
		UCHAR _M_random[16];
	};

	virtual BOOL IsServer()
	{
		return FALSE;
	}

	BOOL PingOrDisconnect(LONG i)
	{
		BOOL fOk = FALSE;
		CDataPacket* packet;
		if (0 <= CreateSimplyPacket(&packet, i, _M_rkey, _M_key))
		{
			fOk = !_pSocket->SendTo(&_addr.saAddress, _addr.dwAddressLength, packet);
			packet->Release();

			DbgPrint("[%u]: --> ping[%d]\r\n", GetTickCount() / 1000, i);
		}

		return fOk;
	}

	virtual BOOL OnRead(PVOID Buffer, ULONG cbTransferred)
	{
		DbgPrint("%hs<%p>(%x)\r\n", __FUNCTION__, this, cbTransferred);

		if (!cbTransferred)
		{
			return FALSE;
		}

		BOOL fOk = FALSE;

		CDataPacket* packet;

		if (0 <= CreatePacket(&packet, _M_hKey, InterlockedIncrement(&_M_nextID), _M_rkey, _M_key, Buffer, cbTransferred))
		{
			fOk = !_pSocket->SendTo(&_addr.saAddress, _addr.dwAddressLength, packet);
			packet->Release();
		}

		return fOk;
	}

	void Notify(UINT msg);

	virtual BOOL OnConnect(NTSTATUS status)
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);

		if (0 > status)
		{
			OnDisconnect();
			return FALSE;
		}

		return TRUE;
	}

	virtual void OnDisconnect()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);

		_M_key = 0;
		PingOrDisconnect(-1);
		Notify(WM_DISCONNECT);
		_pSocket->Release();
		_pSocket = 0;
	}

	virtual ~CmdPipe()
	{
		if (_hProcess)
		{
			TerminateProcess(_hProcess, 0);
			NtClose(_hProcess);
		}

		BCryptDestroyKey(_M_hKey);

		if (_pSocket)
		{
			_pSocket->Release();
		}

		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}
public:

	void SetSocket(SOCKADDR_IN_EX* addr, CUdpEndpoint* pSocket)
	{
		memcpy(&_addr, addr, sizeof(SOCKADDR_IN_EX));
		_pSocket = pSocket;
		pSocket->AddRef();
	}

	CmdPipe(ULONG rkey) : _M_rkey(rkey)
	{
		InitializeListHead(this);
		BCryptGenRandom(0, (PBYTE)&_M_key, sizeof(_M_key), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		BCryptGenRandom(0, _M_random, sizeof(_M_random), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}

	NTSTATUS CreatePipes(PHANDLE phClient)
	{
		HANDLE hPipe;
		NTSTATUS status = SetBuffer(0x600);

		if (0 <= status && (0 <= (status = CreatePipeAnonymousPair(&hPipe, phClient))))
		{
			if (0 <= (status = NT_IRP::BindIoCompletion(this, hPipe)))
			{
				IO_OBJECT::Assign(hPipe);
				SetConnected();
				return Read();
			}

			NtClose(*phClient);
			*phClient = 0;
			NtClose(hPipe);
		}

		return status;
	}

	HRESULT StartCmd(HANDLE hToken)
	{
		WCHAR ApplicationName[MAX_PATH];
		if (!GetEnvironmentVariableW(L"comspec", ApplicationName, _countof(ApplicationName)))
		{
			return GetLastError();
		}

		STARTUPINFOEXW si = { { sizeof(si)} };
		si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;

		HRESULT hr;
		SIZE_T s = 0;
		while (ERROR_INSUFFICIENT_BUFFER == (hr = BOOL_TO_ERROR(InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &s))))
		{
			si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)alloca(s);
		}

		if (NOERROR == hr)
		{
			if (NOERROR == (hr = BOOL_TO_ERROR(UpdateProcThreadAttribute(si.lpAttributeList, 
				0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &si.StartupInfo.hStdError, sizeof(HANDLE), 0, 0))))
			{
				if (0 <= CreatePipes(&si.StartupInfo.hStdError))
				{
					si.StartupInfo.hStdInput = si.StartupInfo.hStdOutput = si.StartupInfo.hStdError;

					PROCESS_INFORMATION pi;

					if (HR(hr, CreateProcessAsUserW(hToken, ApplicationName, 0, 0, 0, TRUE, 
						CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_BREAKAWAY_FROM_JOB, 
						0, 0, &si.StartupInfo, &pi)))
					{
						if (hr = RestrictProcess(pi.hProcess))
						{
							TerminateProcess(pi.hProcess, hr);
							NtClose(pi.hProcess);
						}
						else
						{
							//SetPtocessUtf8(pi.hProcess);
							ResumeThread(pi.hThread);
							_hProcess = pi.hProcess;
							_dwProcessId = pi.dwProcessId;
						}

						NtClose(pi.hThread);
					}

					NtClose(si.StartupInfo.hStdError);
				}
			}

			DeleteProcThreadAttributeList(si.lpAttributeList);
		}

		return hr;
	}

	ULONG64 GetKeyID()
	{
		return _M_key;
	}

	ULONG getPID()
	{
		return _dwProcessId;
	}

	void PrintIP(PWSTR psz, ULONG cch)
	{
		switch (_addr.saAddress.sa_family)
		{
		case AF_INET:
			RtlIpv4AddressToStringExW(&_addr.addr.Ipv4.sin_addr, _addr.addr.Ipv4.sin_port, psz, &cch);
			break;
		case AF_INET6:
			RtlIpv6AddressToStringExW(&_addr.addr.Ipv6.sin6_addr, 
				_addr.addr.Ipv6.sin6_scope_id ,_addr.addr.Ipv6.sin6_port, psz, &cch);
			break;
		}
	}

	void Terminate()
	{
		if (HANDLE hProcess = InterlockedExchangePointer(&_hProcess, 0))
		{
			TerminateProcess(hProcess, 0);
			NtClose(hProcess);
		}
	}
};

class CmdSocketU : public CUdpEndpoint, PFX, public LIST_ENTRY
{
	HWND _M_hwnd;
	HANDLE _M_hToken = 0;
	SRWLOCK _M_lock {};
	LONG _M_nCount = 0;

	void OnAuth(CmdPipe* pipe, SOCKADDR_IN_EX* addr, G_PKT* pkt, ULONG cb)
	{
		// [0][c-k][s-k][16r][auth]
		BCRYPT_KEY_HANDLE hKey;
		if (Server_1_1(pkt, cb, _M_hKey, _M_BlockLength, pipe->_M_random, &hKey, &cb))
		{
			LGOPT* plo = (LGOPT*)(pkt->_M_buf + _M_BlockLength);
			PSTR pb = plo->buf;

			if (sizeof(LGOPT) + 3 < cb && !pb[(cb -= sizeof(LGOPT)) - 2] && !pb[cb - 1])
			{
				PWSTR pwz[3]{};
				if (PWSTR buf = CreateStringBlock(pb, pwz, _countof(pwz)))
				{
					HANDLE hToken = 0;

					HRESULT hr = STATUS_BAD_DATA;
					pipe->SetSocket(addr, this);

					if (pwz[2])
					{
						if (HR(hr, SetThreadToken(0, _M_hToken)))
						{
							if (S_OK == (hr = GetUserToken(&hToken, 
								(SECURITY_LOGON_TYPE)plo->LogonType, pwz[0], pwz[1], pwz[2])))
							{
								if (Interactive == plo->LogonType && plo->bElevated)
								{
									hr = Elevate(&hToken);
								}

								if (S_OK == hr)
								{
									pipe->_M_hKey = hKey, hKey = 0;

									UINT cp = GetOEMCP();
									pipe->OnRead((PSTR)&cp, sizeof(cp));

									hr = pipe->StartCmd(hToken);
								}

								NtClose(hToken);
							}
							SetThreadToken(0, 0);
						}
					}

					delete [] buf;

					if (hr)
					{
						pipe->_M_key = hr;
						pipe->PingOrDisconnect(-1);
						pipe->Close();
						RemoveClient(pipe);
					}
					else
					{
						Notify(WM_CONNECT, (LPARAM)pipe->GetKeyID());
					}
				}
			}

			if (hKey) BCryptDestroyKey(hKey);
		}
	}

	void OnNewClient(SOCKADDR_IN_EX* addr, G_PKT* pkt, ULONG cb)
	{
		// ---> [0][c-k][ 0 ][c-cert]

		BCRYPT_KEY_HANDLE hKey;
		if (GetPubKeyFromPkt(pkt, cb, 0, &hKey))
		{
			if (CmdPipe* pipe = new CmdPipe(pkt->_M_ckey))
			{
				CDataPacket* packet;

				// <--- [0][c-k][s-k][16r][s-cert]

				if (0 <= CreatePacket(&packet, hKey, (LONG)0, pipe->_M_rkey, pipe->_M_key,
					pipe->_M_random, sizeof(pipe->_M_random), _M_pbCertEncoded, _M_cbCertEncoded))
				{
					AcquireSRWLockExclusive(&_M_lock);
					InsertHeadList(this, pipe);
					_M_nCount++;
					ReleaseSRWLockExclusive(&_M_lock);

					pipe = 0;

					SendTo(&addr->saAddress, addr->dwAddressLength, packet);

					packet->Release();
				}

				if (pipe)
				{
					pipe->Release();
				}
			}

			BCryptDestroyKey(hKey);
		}
	}

	void OnRecv(G_PKT* pkt, ULONG cb, SOCKADDR_IN_EX* addr)
	{
		DbgPrint("%hs[%d](%x)\r\n", __FUNCTION__, pkt->_M_i, cb);

		if (!pkt->_M_skey)
		{
			if (!pkt->_M_i)
			{
				OnNewClient(addr, pkt, cb);
			}
			return;
		}

		if (CmdPipe* pipe = get(pkt->_M_skey))
		{
			switch (pkt->_M_i)
			{
			case 0:
				OnAuth(pipe, addr, pkt, cb);
				break;
			case -1:
				pipe->Terminate();
				break;
			case -2:
				pipe->_dwTime = GetTickCount64() + 5000;
				DbgPrint("[%u]: <-- ping\r\n", GetTickCount()/1000);
				break;
			default:
				if (BCRYPT_KEY_HANDLE hKey = pipe->_M_hKey)
				{
					if (DecryptPacket(pkt, cb, hKey, &cb))
					{
						if (cb)
						{
							pipe->Write(pkt->_M_buf, cb);
						}
					}
				}
				break;
			}

			pipe->Release();
		}
	}

	virtual void OnRecv(PSTR buf, ULONG cb, CDataPacket* packet, SOCKADDR_IN_EX* addr)
	{
		if (buf)
		{
			if (sizeof(G_PKT) <= cb)
			{
				OnRecv(reinterpret_cast<G_PKT*>(buf), cb, addr);
			}

			RecvFrom(packet);
		}
	}

	~CmdSocketU()
	{
		if (_M_hToken) NtClose(_M_hToken);
	}

public:

	CmdSocketU()
	{
		InitializeListHead(this);
	}

	void Start(HWND hwnd, ULONG n)
	{
		_M_hwnd = hwnd;
		do 
		{
			if (CDataPacket* packet = new(0x800) CDataPacket)
			{
				RecvFrom(packet);
				packet->Release();
			}
		} while (--n);
	}

	HRESULT Open()
	{
		//*szPfx*szPassword
		if (PWSTR szPfx = wcschr(GetCommandLineW(), '*'))
		{
			if (PWSTR szPassword = wcschr(++szPfx, '*'))
			{
				*szPassword++ = 0;

				return PFX::Open(szPfx, szPassword);
			}
		}

		return PFX::Open(L"0.pfx", L"");
	}

	NTSTATUS SetToken()
	{
		return GetSystemToken(&_M_hToken);
	}

	void RemoveClient(CmdPipe* pipe)
	{
		AcquireSRWLockExclusive(&_M_lock);
		RemoveEntryList(pipe);
		InitializeListHead(pipe);
		_M_nCount--;
		ReleaseSRWLockExclusive(&_M_lock);
		pipe->Release();
	}

	CmdPipe* get(ULONG_PTR Key)
	{
		CmdPipe* pipe = 0;
		PLIST_ENTRY head = this, entry = head;
		AcquireSRWLockShared(&_M_lock);
		while ((entry = entry->Flink) != head)
		{
			if (Key == (ULONG_PTR)static_cast<CmdPipe*>(entry)->GetKeyID())
			{
				pipe = static_cast<CmdPipe*>(entry);
				pipe->AddRef();
				break;
			}
		}
		ReleaseSRWLockShared(&_M_lock);

		return pipe;
	}

	CmdPipe* getI(ULONG i)
	{
		CmdPipe* pipe = 0;
		PLIST_ENTRY head = this, entry = head;
		AcquireSRWLockShared(&_M_lock);
		if (i < (ULONG)_M_nCount)
		{
			do 
			{
				entry = entry->Flink;
			} while (i--);
			pipe = static_cast<CmdPipe*>(entry);
			pipe->AddRef();
		}
		ReleaseSRWLockShared(&_M_lock);

		return pipe;
	}

	void TerminateAll()
	{
		PLIST_ENTRY head = this, entry = head;
		AcquireSRWLockShared(&_M_lock);
		while ((entry = entry->Flink) != head)
		{
			static_cast<CmdPipe*>(entry)->Terminate();
		}
		ReleaseSRWLockShared(&_M_lock);
	}

	void RemoveAll()
	{
		AcquireSRWLockExclusive(&_M_lock);
		PLIST_ENTRY head = this, entry = head->Flink;
		while (entry != head)
		{
			CmdPipe* pipe = static_cast<CmdPipe*>(entry);
			entry = entry->Flink;
			InitializeListHead(pipe);
			pipe->Terminate();
			pipe->Release();
		}
		InitializeListHead(head);
		ReleaseSRWLockExclusive(&_M_lock);
	}

	void Check()
	{
		DbgPrint("*** %u\r\n", GetTickCount() / 1000);

		PLIST_ENTRY head = this, entry = head;
		AcquireSRWLockShared(&_M_lock);
		while ((entry = entry->Flink) != head)
		{
			CmdPipe* pipe = static_cast<CmdPipe*>(entry);
			if (pipe->_dwTime < GetTickCount64())
			{
				DbgPrint("!!!!! %u < %u\r\n", (ULONG)pipe->_dwTime / 1000, (ULONG)GetTickCount64()/1000);
				pipe->Terminate();
			}
			else
			{
				pipe->PingOrDisconnect(-2);
			}
		}
		ReleaseSRWLockShared(&_M_lock);
	}

	void Notify(UINT msg, LPARAM Key)
	{
		PostMessageW(_M_hwnd, msg, 0, Key);
	}
};

void CmdPipe::Notify(UINT msg)
{
	static_cast<CmdSocketU*>(_pSocket)->Notify(msg, _M_key);
}

#include "../inc/initterm.h"
#include "resource.h"

HANDLE _G_hEvent;

void IO_RUNDOWN::RundownCompleted()
{
	SetEvent(_G_hEvent);
}

DWORD s_uTaskbarRestart;

BOOL AddTaskbarIcons(HWND hwnd)
{
	NOTIFYICONDATA ni = { sizeof(ni), hwnd, 1, NIF_MESSAGE|NIF_ICON|NIF_TIP, WM_USER};
	ni.uVersion = NOTIFYICON_VERSION_4;
	ni.hIcon = LoadIcon((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1));
	wcscpy(ni.szTip, L" demo cmd server ");
	ni.cbSize = Shell_NotifyIcon(NIM_ADD, &ni);
	DestroyIcon(ni.hIcon);
	return ni.cbSize;
}

void DelTaskbarIcons(HWND hwnd)
{
	NOTIFYICONDATA ni = { sizeof(ni), hwnd, 1 };
	Shell_NotifyIcon(NIM_DELETE, &ni);
}

class ZTryWnd : public ZDlg, CIcons
{
	CmdSocketU* _pSocket;
	HWND _hwndLV;
	ULONG _nItems = 0;
	int _iLastSelectedItem;

	void ShowTip(HWND hwnd, PCWSTR szInfoTitle, CmdPipe* p)
	{
		NOTIFYICONDATAW nid = { sizeof(nid), hwnd, 1, NIF_INFO };

		p->PrintIP(nid.szInfo, _countof(nid.szInfo));
		wcscpy(nid.szInfoTitle, szInfoTitle);
		nid.dwInfoFlags = NIIF_INFO;
		nid.uTimeout = 4000;

		Shell_NotifyIconW(NIM_MODIFY, &nid); 
	}

	void OnConnect(HWND hwnd, ULONG_PTR Key)
	{
		if (CmdPipe* p = _pSocket->get(Key))
		{
			ShowTip(hwnd, L"Connect", p);
			p->Release();
		}
		ListView_SetItemCountEx(_hwndLV, ++_nItems, 0);
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON3), TRUE);
	}

	void OnDisconnect(HWND hwnd, ULONG_PTR Key)
	{
		if (CmdPipe* p = _pSocket->get(Key))
		{
			_pSocket->RemoveClient(p);
			ShowTip(hwnd, L"Disconnect", p);
			p->Release();
		}
		ListView_SetItemCountEx(_hwndLV, --_nItems, 0);
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON2), FALSE);
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON3), _nItems);
	}

	void Terminate(ULONG i)
	{
		if (CmdPipe* p = _pSocket->getI(i))
		{
			p->Terminate();
			p->Release();
		}
	}

	void OnInitDialog(HWND hwnd)
	{
		_pSocket->Start(hwnd, 8);

		AddTaskbarIcons(hwnd);
		SetIcons(hwnd, (HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1));
		_hwndLV = hwnd = GetDlgItem(hwnd, IDC_LIST1);

		ListView_SetExtendedListViewStyle(hwnd, LVS_EX_BORDERSELECT|LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);

		SIZE size = { 8, 16 };
		if (HDC hdc = GetDC(hwnd))
		{
			HGDIOBJ o = SelectObject(hdc, (HGDIOBJ)SendMessage(hwnd, WM_GETFONT, 0, 0));
			GetTextExtentPoint32(hdc, L"W", 1, &size);
			SelectObject(hdc, o);
			ReleaseDC(hwnd, hdc);
		}

		LVCOLUMN lvc = { LVCF_FMT|LVCF_WIDTH|LVCF_TEXT|LVCF_SUBITEM, LVCFMT_LEFT };

		static PCWSTR headers[] = { L" PID ", L" From " };
		DWORD lens[] = { 10, 24 };

		do 
		{
			lvc.pszText = (PWSTR)headers[lvc.iSubItem], lvc.cx = lens[lvc.iSubItem] * size.cx;
			ListView_InsertColumn(hwnd, lvc.iSubItem, &lvc);
		} while (++lvc.iSubItem < _countof(headers));
	}

	virtual INT_PTR DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		case WM_NOTIFY:
			if (wParam == IDC_LIST1)
			{
				union {
					LPARAM lp;
					NMHDR* ph;
					NMLVDISPINFO* pdi;
					NMLISTVIEW* plv;
				};

				lp = lParam;

				switch (ph->code)
				{
				case LVN_ITEMCHANGED:
					EnableWindow(GetDlgItem(hwnd, IDC_BUTTON2), ListView_GetSelectedCount(_hwndLV) != 0);
					if ((0 <= plv->iItem) && (plv->uNewState & LVIS_SELECTED))
					{
						_iLastSelectedItem = plv->iItem;
					}
					break;
				case LVN_GETDISPINFO:
					int iItem = pdi->item.iItem;

					if (CmdPipe* p = _pSocket->getI(iItem))
					{
						if (pdi->item.mask & LVIF_TEXT)
						{
							switch (pdi->item.iSubItem)
							{
							case 0:
								_snwprintf(pdi->item.pszText, pdi->item.cchTextMax, L"%#x", p->getPID());
								break;
							case 1:
								p->PrintIP(pdi->item.pszText, pdi->item.cchTextMax);
								break;
							}
						}

						p->Release();
					}
					break;
				}
			}
			break;

		case WM_TIMER:
			if ((UINT_PTR)this == wParam)
			{
				_pSocket->Check();
			}
			break;

		case WM_INITDIALOG:
			OnInitDialog(hwnd);
			SetTimer(hwnd, (UINT_PTR)this, 3000, 0);
			break;

		case WM_DESTROY:
			KillTimer(hwnd, (UINT_PTR)this);
			_pSocket->RemoveAll();
			DelTaskbarIcons(hwnd);
			break;

		case WM_COMMAND:
			switch (wParam)
			{
			case IDCANCEL:
				ShowWindow(hwnd, SW_HIDE);
				break;
			case IDC_BUTTON1:
				EndDialog(hwnd, 0);
				break;
			case IDC_BUTTON2:
				{
					int i = ListView_GetSelectionMark(_hwndLV);
					if (0 <= i)
					{
						Terminate(i);
						EnableWindow((HWND)lParam, FALSE);
					}
				}
				break;
			case IDC_BUTTON3:
				_pSocket->TerminateAll();
				break;
			}
			break;

		case WM_CONNECT:
			OnConnect(hwnd, (ULONG_PTR)lParam);
			break;

		case WM_DISCONNECT:
			OnDisconnect(hwnd, (ULONG_PTR)lParam);
			break;

		case WM_USER:
			switch (LOWORD(lParam))
			{
			case WM_RBUTTONDOWN:
			case WM_LBUTTONDOWN:
				ShowWindow(hwnd, SW_SHOW);
				break;
			}
			break;

		default:
			if (s_uTaskbarRestart == uMsg) AddTaskbarIcons(hwnd);
		}
		return ZDlg::DialogProc(hwnd, uMsg, wParam, lParam);
	}

public:

	ZTryWnd(CmdSocketU* pSocket) : _pSocket(pSocket)
	{
	}
};

void WINAPI ep(void*)
{
	STATIC_OBJECT_ATTRIBUTES(oa, "\\BaseNamedObjects\\{B34D6D86-D9E3-4074-8719-257967D353E3}");
	if (0 <= ZwCreateEvent(&_G_hEvent, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE))
	{
		initterm();

		if (CmdSocketU* p = new CmdSocketU)
		{
			if (HRESULT hr = p->Open())
			{
				ShowErrorBox(0, hr, L"PFX");
			}
			else if (hr = p->SetToken())
			{
				ShowErrorBox(0, hr, L"Privileges");
			}
			else
			{
				s_uTaskbarRestart = RegisterWindowMessage(L"TaskbarCreated");

				WSADATA wd;
				if (!WSAStartup(WINSOCK_VERSION, &wd))
				{
					if (hr = p->Create(0x7865))
					{
						ShowErrorBox(0, hr, L"can not open port 25976");
					}
					else 
					{
						ZTryWnd wnd(p);
						wnd.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDD_DIALOG1), HWND_DESKTOP, 0);
					}

					p->Close();

					WSACleanup();
				}
			}

			p->Release();
			IO_RUNDOWN::g_IoRundown.BeginRundown();
			WaitForSingleObject(_G_hEvent, INFINITE);
		}

		destroyterm();
		NtClose(_G_hEvent);
	}

	ExitProcess(0);
}

_NT_END

