#include "StdAfx.h"

_NT_BEGIN

#include "../asio/port.h"
#include "../asio/pipe.h"
#include "../winZ/app.h"
#include "../winZ/window.h"
#include "../winZ/ctrl.h"

#define DbgPrint /##/

volatile UCHAR guz = 0;

LONG MaxClientCount = 4;

BOOL MultiByteToMultiByte(ULONG CodePageFrom, ULONG CodePageTo, const void* lpMultiByteStr, ULONG cbMultiByte, CDataPacket** ppacket)
{
	BOOL fOk = FALSE;

	if (ULONG cchWideChar = MultiByteToWideChar(CodePageFrom, 0, (PCSTR)lpMultiByteStr, cbMultiByte, 0, 0))
	{
		if (PWSTR lpWideCharStr = (PWSTR)_malloca(cchWideChar * sizeof(WCHAR)))
		{
			if (cchWideChar = MultiByteToWideChar(CodePageFrom, 0, (PCSTR)lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar))
			{
				if (cbMultiByte = WideCharToMultiByte(CodePageTo, 0, lpWideCharStr, cchWideChar, 0, 0, 0, 0))
				{
					if (CDataPacket* packet = new(cbMultiByte) CDataPacket)
					{
						if (cbMultiByte = WideCharToMultiByte(CodePageTo, 0, lpWideCharStr, cchWideChar, packet->getData(), cbMultiByte, 0, 0))
						{
							packet->setDataSize(cbMultiByte);
							*ppacket = packet;
							fOk = TRUE;
						}
						else 
						{
							packet->Release();
						}
					}
				}
			}
			_freea(lpWideCharStr);
		}
	}
	return fOk;
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
			return BOOL_TO_ERROR(DuplicateHandle(GetCurrentProcess(), hJob, hProcess, 0, 0, FALSE, DUPLICATE_CLOSE_SOURCE));
		}

		CloseHandle(hJob);
	}

	return GetLastError();
}

class CmdPipe : public CPipeEnd
{
	CTcpEndpoint* _pSocket;

	virtual BOOL IsServer()
	{
		return FALSE;
	}

	virtual BOOL OnRead(PVOID Buffer, ULONG cbTransferred)
	{
		DbgPrint("%s<%p>\r\n%.*s\r\n", __FUNCTION__, this, cbTransferred, Buffer);

		BOOL fOk = FALSE;

		CDataPacket* packet;
		if (MultiByteToMultiByte(CP_OEMCP, CP_UTF8, Buffer, cbTransferred, &packet))
		{
			fOk = !_pSocket->Send(packet);
			packet->Release();
		}
		return fOk;
	}

	virtual BOOL OnConnect(NTSTATUS status)
	{
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
		if (0 > status)
		{
			OnDisconnect();
			return FALSE;
		}

		return TRUE;
	}

	virtual void OnDisconnect()
	{
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
		_pSocket->Disconnect();
		_pSocket->Release();
		_pSocket = 0;
	}

	virtual ~CmdPipe()
	{
		if (_pSocket)
		{
			_pSocket->Disconnect();
			_pSocket->Release();
		}
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
	}
public:

	CmdPipe(CTcpEndpoint* pSocket) : _pSocket(pSocket)
	{
		pSocket->AddRef();
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
	}
};

class WndRundown : public RUNDOWN_REF
{
	HWND _hDlg;

	virtual void RundownCompleted()
	{
		EndDialog(_hDlg, 0);
	}

public:

	_NODISCARD BOOL Acquire(HWND& hwnd)
	{
		BOOL f = RundownProtection::Acquire();
		hwnd = _hDlg;
		return f;
	}

	void Init(HWND hDlg)
	{
		_hDlg = hDlg;
	}

} g_MainHwnd;

enum { WM_CONNECT = WM_APP, WM_DISCONNECT};

struct ConnectedEntry : LIST_ENTRY, sockaddr_in
{
	HANDLE _hProcess;
	ULONG _UniqueId;
	ULONG _dwProcessId;

	ConnectedEntry(HANDLE hProcess, ULONG dwProcessId, ULONG UniqueId, sockaddr_in* addr) 
		: _dwProcessId(dwProcessId), _hProcess(0), _UniqueId(UniqueId)
	{
		InitializeListHead(this);

		memcpy(static_cast<sockaddr_in*>(this), addr, sizeof(sockaddr_in));

		DuplicateHandle(NtCurrentProcess(), hProcess, 
			NtCurrentProcess(), &_hProcess, 0, 0, DUPLICATE_SAME_ACCESS);
	}

	~ConnectedEntry()
	{
		if (_hProcess)
		{
			CloseHandle(_hProcess);
			_hProcess = 0;
		}
		RemoveEntryList(this);
	}

	void Terminate()
	{
		if (_hProcess)
		{
			TerminateProcess(_hProcess, STATUS_ABANDONED);
			CloseHandle(_hProcess);
			_hProcess = 0;
		}
	}
};

class CmdSocket : public CTcpEndpoint, public ENDPOINT_ENTRY
{
	CmdPipe* _pipe;
	HANDLE _hProcess;
	LONG _UniqueId;

	inline static LONG s_nCount, s_UniqueId;

	virtual void LogError(DWORD opCode, DWORD dwError)
	{
		DbgPrint("%s<%p>(%.4s: %u)\r\n", __FUNCTION__, this, &opCode, dwError);
	}

	BOOL PostNotify(UINT uMsg, LPARAM lParam)
	{
		BOOL fOk = FALSE;
		HWND hwnd;
		if (g_MainHwnd.Acquire(hwnd))
		{
			fOk = PostMessageW(hwnd, uMsg, 0, lParam);
			g_MainHwnd.Release();
		}
		return fOk;
	}

	virtual BOOL OnConnect(ULONG dwError)
	{
		_Port->OnConnect(dwError);

		if (dwError)
		{
			return FALSE;
		}

		_UniqueId = InterlockedIncrementNoFence(&s_UniqueId);

		WCHAR ApplicationName[MAX_PATH];
		if (!GetEnvironmentVariableW(L"comspec", ApplicationName, RTL_NUMBER_OF(ApplicationName)))
		{
			return FALSE;
		}

		BOOL fOk = FALSE;

		if (CmdPipe* pipe = new CmdPipe(this))
		{
			STARTUPINFOEXW si = { { sizeof(si)} };

			HANDLE hPipe;

			if (0 <= pipe->SetBuffer(0x4000) && 0 <= CreatePipeAnonymousPair(&hPipe, &si.StartupInfo.hStdError))
			{
				if (0 <= pipe->Assign(hPipe))
				{
					si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
					si.StartupInfo.hStdInput = si.StartupInfo.hStdOutput = si.StartupInfo.hStdError;

					PVOID stack = alloca(guz);
					SIZE_T cb = 0, rcb = 0x40;
					do 
					{
						if (cb < rcb)
						{
							cb = RtlPointerToOffset(si.lpAttributeList = 
								(PPROC_THREAD_ATTRIBUTE_LIST)alloca(rcb - cb), stack);
						}

						dwError = BOOL_TO_ERROR(InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &(rcb = cb)));

					} while (dwError == ERROR_INSUFFICIENT_BUFFER);

					if (!dwError)
					{				
						if (UpdateProcThreadAttribute(si.lpAttributeList, 0, 
							PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &si.StartupInfo.hStdError, sizeof(HANDLE), 0, 0))
						{
							PROCESS_INFORMATION pi;

							if (CreateProcessW(ApplicationName, 0, 0, 0, TRUE, 
								CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_BREAKAWAY_FROM_JOB, 
								0, 0, &si.StartupInfo, &pi))
							{
								if (dwError = RestrictProcess(pi.hProcess))
								{
									TerminateProcess(pi.hProcess, dwError);
									CloseHandle(pi.hProcess);
								}
								else
								{
									_hProcess = pi.hProcess;
									_pipe = pipe, pipe->AddRef();

									if (ConnectedEntry* p = new ConnectedEntry(pi.hProcess, 
										pi.dwProcessId, _UniqueId, &m_RemoteSockaddr))
									{
										if (!PostNotify(WM_CONNECT, (LPARAM)p))
										{
											delete p;
										}
									}

									fOk = TRUE;
									ResumeThread(pi.hThread);
								}

								CloseHandle(pi.hThread);
							}
						}

						DeleteProcThreadAttributeList(si.lpAttributeList);
					}
				}
				NtClose(si.StartupInfo.hStdError);
			}

			pipe->Release();
		}

		return fOk;
	}

	void Cleanup()
	{
		if (_hProcess)
		{
			TerminateProcess(_hProcess, STATUS_ABANDONED);
			CloseHandle(_hProcess);
			_hProcess = 0;
		}

		if (_pipe)
		{
			_pipe->Close();
			_pipe->Release();
			_pipe = 0;
		}
	}

	virtual void OnDisconnect()
	{
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
		_Port->OnDisconnect(this);
		Cleanup();
		PostNotify(WM_DISCONNECT, _UniqueId);
	}

	virtual BOOL OnRecv(PSTR Buffer, ULONG cbTransferred)
	{
		DbgPrint("%s<%p>\r\n%.*s\r\n", __FUNCTION__, this, cbTransferred, Buffer);

		BOOL fOk = FALSE;

		CDataPacket* packet;
		if (MultiByteToMultiByte(CP_UTF8, CP_OEMCP, Buffer, cbTransferred, &packet))
		{
			fOk = 0 <= _pipe->Write(packet);
			packet->Release();
		}

		return fOk;
	}

	~CmdSocket()
	{
		Cleanup();
		InterlockedDecrementNoFence(&s_nCount);
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
	}

public:

	CmdSocket(CSocketObject* pAddress) : CTcpEndpoint(pAddress), _hProcess(0), _pipe(0)
	{
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
	}

	class PCtx : public PortContext
	{
		virtual CTcpEndpoint* getEndpoint(ENDPOINT_ENTRY* entry)
		{
			return static_cast<CmdSocket*>(entry);
		}

		virtual ENDPOINT_ENTRY* CreateEntry(CSocketObject* pAddress)
		{
			LONG Count, NewCount;

			for(Count = s_nCount; Count < MaxClientCount; Count = NewCount) 
			{
				NewCount = InterlockedCompareExchangeNoFence(&s_nCount, Count + 1, Count);

				if (NewCount == Count)
				{
					if (CmdSocket* socket = new CmdSocket(pAddress))
					{
						if (!socket->Create(0x4000))
						{
							return socket;
						}

						socket->Release();
					}
					else
					{
						InterlockedDecrementNoFence(&s_nCount);
					}

					break;
				}
			}

			return 0;
		}
		
		virtual ULONG GetReceiveDataLength()
		{
			return 0;
		}
	};

	inline static PCtx ctx;

	friend PCtx;
};

#include "../inc/initterm.h"
#include "resource.h"

PortList gpl;

struct MyRundown : public RUNDOWN_REF 
{
	HANDLE _hEvent;

	ULONG Create()
	{
		return (_hEvent = CreateEvent(0, 0, 0, 0)) ? NOERROR : GetLastError();
	}

	void Wait()
	{
		WaitForSingleObject(_hEvent, INFINITE);
	}

	virtual void RundownCompleted()
	{
		SetEvent(_hEvent);
	}

	~MyRundown()
	{
		if (_hEvent)
		{
			CloseHandle(_hEvent);
		}
	}

	MyRundown()
	{
		_hEvent = 0;
	}
} grr;

RUNDOWN_REF * g_IoRundown = &grr;

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

class ZTryWnd : public ZDlg, CIcons, LIST_ENTRY
{
	Port* _port;
	HWND _hwndLV;
	ULONG _nConnected;
	int _iLastSelectedItem;

	void OnConnect(HWND hwnd, ConnectedEntry* p)
	{
		InsertTailList(this, p);

		NOTIFYICONDATAW nid = { sizeof(nid), hwnd, 1, NIF_INFO };

		ULONG n = RTL_NUMBER_OF(nid.szInfo);
		RtlIpv4AddressToStringExW(p->sin_addr.S_un.S_addr, p->sin_port, nid.szInfo, n);
		wcscpy(nid.szInfoTitle, L"Connect");
		nid.dwInfoFlags = NIIF_INFO;
		nid.uTimeout = 4000;

		Shell_NotifyIconW(NIM_MODIFY, &nid); 
		ListView_SetItemCountEx(_hwndLV, ++_nConnected, 0);
	}

	void OnDisconnect(HWND hwnd, ULONG UniqueId)
	{
		PLIST_ENTRY head = this, entry = head;
		
		while ((entry = entry->Flink) != head)
		{
			ConnectedEntry* p = static_cast<ConnectedEntry*>(entry);

			if (p->_UniqueId == UniqueId)
			{
				NOTIFYICONDATAW nid = { sizeof(nid), hwnd, 1, NIF_INFO };

				ULONG n = RTL_NUMBER_OF(nid.szInfo);
				RtlIpv4AddressToStringExW(p->sin_addr.S_un.S_addr, p->sin_port, nid.szInfo, n);
				wcscpy(nid.szInfoTitle, L"Disconnect");
				nid.dwInfoFlags = NIIF_INFO;
				nid.uTimeout = 4000;

				Shell_NotifyIconW(NIM_MODIFY, &nid); 
				delete p;
				ListView_SetItemCountEx(_hwndLV, --_nConnected, 0);
				return;
			}
		}
	}

	ConnectedEntry* get(int iItem)
	{
		PLIST_ENTRY head = this, entry = head;
		while ((entry = entry->Flink) != head)
		{
			if (!iItem--)
			{
				return static_cast<ConnectedEntry*>(entry);
			}
		}
		return 0;
	}

	void Terminate(int i, int n)
	{
		PLIST_ENTRY head = this, entry = head;
		while ((entry = entry->Flink) != head)
		{
			if (0 > --i)
			{
				static_cast<ConnectedEntry*>(entry)->Terminate();
				if (!--n)
				{
					return;
				}
			}
		}
	}

	void OnInitDialog(HWND hwnd)
	{
		g_MainHwnd.Init(hwnd);
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
		} while (++lvc.iSubItem < RTL_NUMBER_OF(headers));
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

					if (ConnectedEntry* p = get(iItem))
					{
						if (pdi->item.mask & LVIF_TEXT)
						{
							switch (pdi->item.iSubItem)
							{
							case 0:
								_snwprintf(pdi->item.pszText, pdi->item.cchTextMax, L"%#x", p->_dwProcessId);
								break;
							case 1:
								RtlIpv4AddressToStringExW(
									p->sin_addr.S_un.S_addr, p->sin_port, 
									pdi->item.pszText, (ULONG&)pdi->item.cchTextMax);
								break;
							}
						}
					}
					break;
				}
			}
			break;

		case WM_INITDIALOG:
			OnInitDialog(hwnd);
			break;

		case WM_DESTROY:
			DelTaskbarIcons(hwnd);
			break;

		case WM_COMMAND:
			switch (wParam)
			{
			case IDCANCEL:
				ShowWindow(hwnd, SW_HIDE);
				break;
			case IDC_BUTTON1:
				g_MainHwnd.BeginRundown();
				break;
			case IDC_BUTTON2:
				if (int n = ListView_GetSelectedCount(_hwndLV))
				{
					int i = ListView_GetSelectionMark(_hwndLV);
					if (0 <= i)
					{
						Terminate(min(i, _iLastSelectedItem), n);
						EnableWindow(GetDlgItem(hwnd, IDC_BUTTON2), FALSE);
					}
				}
				break;
			}
			break;

		case WM_CONNECT:
			OnConnect(hwnd, (ConnectedEntry*)lParam);
			break;
		case WM_DISCONNECT:
			OnDisconnect(hwnd, (ULONG)lParam);
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

	virtual ~ZTryWnd()
	{
		_port->Release();
	}

public:

	ZTryWnd(Port* port) : _port(port), _nConnected(0)
	{
		port->AddRef();
		InitializeListHead(this);
	}
};

void WINAPI ep(void*)
{
	STATIC_OBJECT_ATTRIBUTES(oa, "\\BaseNamedObjects\\{B34D6D86-D9E3-4074-8719-257967D353E3}");
	HANDLE hEvent;
	if (0 <= ZwCreateEvent(&hEvent, SYNCHRONIZE, &oa, SynchronizationEvent, FALSE))
	{
		initterm();

		if (!grr.Create())
		{
			s_uTaskbarRestart = RegisterWindowMessage(L"TaskbarCreated");

			WSADATA wd;
			if (!WSAStartup(WINSOCK_VERSION, &wd))
			{
				Port* port;
				if (ULONG dwError = gpl.CreatePort(&port, 0x7865))
				{
					PWSTR sz;
					if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 
						0, dwError, 0, (PWSTR)&sz, 0, 0))
					{
						MessageBoxW(0, sz, L"can not open port 25976", MB_ICONHAND);
						LocalFree(sz);
					}
				}
				else
				{
					port->Start(4, 4, &CmdSocket::ctx);

					if (ZTryWnd* p = new ZTryWnd(port))
					{
						p->DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDD_DIALOG1), HWND_DESKTOP, 0);
						p->Release();
					}

					port->Release();
				}

				gpl.Stop();

				grr.BeginRundown();

				grr.Wait();

				WSACleanup();
			}
		}

		destroyterm();

		NtClose(hEvent);
	}

	ExitProcess(0);
}

_NT_END

