// cmd_server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

_NT_BEGIN

#include "../inc/initterm.h"
#include "../asio/socket.h"
#include "../winz/Frame.h"
#include "resource.h"
#include "msgbox.h"
#include "pfx.h"
#include "tls.h"
#include "UdpHelper.h"
#define DbgPrint /##/
//
enum {
	WM_CONNECT = WM_APP, WM_DISCONNECT, WM_DATA, WM_ERROR
};

class CPDlg : public ZDlg
{
	UINT _M_CP;

	void OnInitDialog(HWND hwndCB)
	{
		union {
			KEY_VALUE_BASIC_INFORMATION kvbi;
			UCHAR buf[sizeof(KEY_VALUE_BASIC_INFORMATION) + 15*sizeof(WCHAR)];
		};

		swprintf_s(kvbi.Name, 15, L"CP_%u", _M_CP);
		SendMessageW(hwndCB, CB_SETITEMDATA, SendMessageW(hwndCB, CB_ADDSTRING, 0, (LPARAM)kvbi.Name), _M_CP);
		SendMessageW(hwndCB, CB_SETITEMDATA, SendMessageW(hwndCB, CB_ADDSTRING, 0, (LPARAM)L"UTF8"), CP_UTF8);
		SendMessageW(hwndCB, CB_SETCURSEL, 0, 0);

		HANDLE hKey;
		STATIC_OBJECT_ATTRIBUTES(oa, "\\registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage");
		if (0 <= ZwOpenKey(&hKey, KEY_READ, &oa))
		{
			ULONG i = 0;
			NTSTATUS status;
			do 
			{
				if (0 <= (status = ZwEnumerateValueKey(hKey, i++, 
					KeyValueBasicInformation, buf, sizeof(buf) - sizeof(WCHAR), &kvbi.TitleIndex)))
				{
					*(WCHAR*)RtlOffsetToPointer(kvbi.Name, kvbi.NameLength) = 0;
					PWSTR psz;
					
					switch (ULONG cp = wcstoul(kvbi.Name, &psz, 10))
					{
					case 0:
					case CP_UTF8:
						break;
					default:
						if (!*psz)
						{
							SendMessageW(hwndCB, CB_SETITEMDATA, SendMessageW(hwndCB, CB_ADDSTRING, 0, (LPARAM)kvbi.Name), cp);
						}
					}

				}
			} while (STATUS_NO_MORE_ENTRIES != status);

			NtClose(hKey);
		}
	}

	virtual INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		case WM_NCDESTROY:
			return ZDlg::DialogProc(hwndDlg, uMsg, wParam, lParam);
		case WM_INITDIALOG:
			OnInitDialog(GetDlgItem(hwndDlg, IDC_COMBO1));
			break;
		case WM_COMMAND:
			switch (wParam)
			{
			case IDOK:
				if (0 <= (lParam = SendDlgItemMessageW(hwndDlg, IDC_COMBO1, CB_GETCURSEL, 0, 0)))
				{
					if (lParam = SendDlgItemMessageW(hwndDlg, IDC_COMBO1, CB_GETITEMDATA, lParam, 0))
					{
						_M_CP = (UINT)lParam;
					}
				}
			case IDCANCEL:
				EndDialog(hwndDlg, wParam);
				break;
			}
			break;
		case WM_CLOSE:
			EndDialog(hwndDlg, IDCANCEL);
			break;
		}

		return 0;
	}
public:

	CPDlg(UINT CP) : _M_CP(CP){}

	UINT GetCP()
	{
		return _M_CP;
	}
};

class ZConnectDlg : public ZDlg
{
	PULONG _pip, _pcb;
	LGOPT** _pplo;
	LONG _mask = 7;
	WCHAR _M_c;
	UCHAR LogonType = Interactive; 
	BOOLEAN bElevated = FALSE;

	virtual INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		static const PCWSTR Names[] = { L"Batch", L"Network", L"Interactive" };
		static const SECURITY_LOGON_TYPE LT[] = { Interactive, Network, Batch };
		static const UINT s_id[] = { IDC_EDIT3, IDC_EDIT2, IDC_EDIT1 };

		switch (uMsg)
		{
		case WM_INITDIALOG:
			SendDlgItemMessageW(hwndDlg, IDC_IPADDRESS1, IPM_SETADDRESS, 0, IP(1,0,0,127));

			_M_c = (WCHAR)SendDlgItemMessageW(hwndDlg, IDC_EDIT3, EM_GETPASSWORDCHAR, 0, 0);
			uMsg = _countof(Names) - 1;
			do 
			{
				SendDlgItemMessageW(hwndDlg, IDC_COMBO1, CB_ADDSTRING, 0, (LPARAM)Names[uMsg]);

			} while (uMsg--);

			SendDlgItemMessageW(hwndDlg, IDC_COMBO1, CB_SETCURSEL, 0, 0);
			SetWindowTextW(GetDlgItem(hwndDlg, IDC_EDIT1), L".");
			SendDlgItemMessageW(hwndDlg, IDC_EDIT3, CB_SETCURSEL, 0, 0);

			break;
		case WM_COMMAND:
			switch (wParam)
			{
			case IDOK:
				if (LGOPT* plo = CreateAuthBlock(LogonType, bElevated, hwndDlg, s_id, _countof(s_id), _pcb))
				{
					SendDlgItemMessageW(hwndDlg, IDC_IPADDRESS1, IPM_GETADDRESS, 0, (LPARAM)_pip);
					*_pplo = plo;
					EndDialog(hwndDlg, 1);
				}
				break;
			case IDCANCEL:
				EndDialog(hwndDlg, 0);
				break;

			case IDC_CHECK2:
				bElevated = (SendMessageW((HWND)lParam, BM_GETCHECK, 0, 0) == BST_CHECKED);
				break;

			case IDC_CHECK3:
				SendDlgItemMessageW(hwndDlg, IDC_EDIT3, EM_SETPASSWORDCHAR, 
					SendMessageW((HWND)lParam, BM_GETCHECK, 0, 0) == BST_CHECKED ? 0 : _M_c, 0);
				InvalidateRect(GetDlgItem(hwndDlg, IDC_EDIT3), 0, FALSE);
				break;

			case MAKEWPARAM(IDC_COMBO1, CBN_SELCHANGE):
				if (0 <= (lParam = SendMessageW((HWND)lParam, CB_GETCURSEL, 0, 0)))
				{
					LogonType = (UCHAR)LT[lParam];
					EnableWindow(GetDlgItem(hwndDlg, IDC_CHECK2), !lParam);
				}
				break;

			case MAKEWPARAM(IDC_EDIT1, EN_CHANGE):
			case MAKEWPARAM(IDC_EDIT2, EN_CHANGE):
			case MAKEWPARAM(IDC_EDIT3, EN_CHANGE):
				uMsg = LOWORD(wParam) - IDC_EDIT1;
				if (GetWindowTextLengthW((HWND)lParam))
				{
					_bittestandreset(&_mask, uMsg);
				}
				else
				{
					_bittestandset(&_mask, uMsg);
				}
				EnableWindow(GetDlgItem(hwndDlg, IDOK), !_mask);
				break;
			}
			break;
		}
		return ZDlg::DialogProc(hwndDlg, uMsg, wParam, lParam);
	}
public:
	ZConnectDlg(PULONG pip, LGOPT** pplo, PULONG pcb) : _pip(pip), _pplo(pplo), _pcb(pcb) {}
};

class CmdSocket : public CUdpEndpoint, UdpHelper
{
	ULONG64 _M_rkey = 0, _dwTime = GetTickCount64() + 5000;
	BCRYPT_KEY_HANDLE _M_hKey = 0;
	PVOID _M_pvAuth = 0;
	HWND _M_hwnd;
	PFX_REF* _M_pfx;
	SOCKADDR_IN_EX _addr {};
	ULONG _M_cbAuth = 0;
	ULONG _M_key = 0;
	LONG _M_nextID = 0;
	LONG _M_flags = 0;
	UINT _M_CP = GetOEMCP(), _M_CPs = 0;

	enum { f_error, f_connected };

	void PostError(HRESULT hr)
	{
		if (!_interlockedbittestandset(&_M_flags, f_error))
		{
			PostMessageW(_M_hwnd, WM_ERROR, hr, 0);
		}
	}

	BOOL OnConnect(G_PKT* pkt, ULONG cb)
	{
		// <-- [0][c-k][s-k][16r][s-cert]
		// --> [0][c-k][s-k][16r][auth]

		if (_M_rkey = pkt->_M_skey)
		{
			CDataPacket* packet;

			if (Client_0_1(pkt, cb, _M_pfx->_M_hKey, _M_pfx->_M_BlockLength, _M_pvAuth, _M_cbAuth, &packet, &_M_hKey))
			{
				ULONG hr = SendTo(&_addr.saAddress, _addr.dwAddressLength, packet);
				if (hr)
				{
					PostError(hr);
				}
				packet->Release();

				return !hr;
			}
		}

		return FALSE;
	}

	virtual void OnRecv(PSTR buf, ULONG cb, CDataPacket* packet, SOCKADDR_IN_EX* /*addr*/)
	{
		if (buf)
		{
			if (sizeof(G_PKT) <= cb)
			{
				switch (OnRecv(reinterpret_cast<G_PKT*>(buf), cb, packet))
				{
				case 0: // error
					PingOrDisconnect(-1);
					PostError(STATUS_BAD_DATA);
					Close();
					return;

				case -1: // wrong order,queued
					DbgPrint("###### %x\n", reinterpret_cast<G_PKT*>(buf)->_M_i);
					Listen();
					return ;
				}
			}

			RecvFrom(packet);
		}
		else
		{
			PostError(cb);
		}
	}

	BOOL OnRecv(G_PKT* pkt, ULONG cb, CDataPacket* packet)
	{
		if (pkt->_M_ckey != _M_key)
		{
			return TRUE;
		}

		switch (pkt->_M_i)
		{
		case 0: // connect
			if (!_M_rkey)
			{
				return OnConnect(pkt, cb);
			}
			return FALSE;

		case -1: // disconnect
			_interlockedbittestandset(&_M_flags, f_error);
			PostMessageW(_M_hwnd, WM_DISCONNECT, 0, (ULONG)pkt->_M_skey);
			return TRUE;

		case -2: // ping
			_dwTime = GetTickCount64() + 5000;
			DbgPrint("[%u]: <-- ping\r\n", GetTickCount()/1000);
			return TRUE;
		}

		return UdpHelper::OnRecv(pkt, cb, packet);
	}

	virtual bool OnPacket(G_PKT* pkt, ULONG cb)
	{
		DbgPrint("OnPacket<%p>[%x](%x)\n", pkt, pkt->_M_i, cb);

		if (BCRYPT_KEY_HANDLE hKey = _M_hKey)
		{
			if (DecryptPacket(pkt, cb, hKey, &cb))
			{
				if (!cb)
				{
					return FALSE;
				}

				if (1 == pkt->_M_i)
				{
					if (sizeof(UINT) != cb)
					{
						return FALSE;
					}

					_M_CPs = _M_CP = *(UINT*)pkt->_M_buf;

					PostMessageW(_M_hwnd, WM_CONNECT, _M_CP, 0);

					return TRUE;
				}

				PWSTR psz = 0;
				ULONG cch = 0;
				while (cch = MultiByteToWideChar(_M_CP, 0, (PSTR)pkt->_M_buf, cb, psz, cch))
				{
					if (psz)
					{
						psz[cch] = 0;
						if (PostMessageW(_M_hwnd, WM_DATA, 0, (LPARAM)psz))
						{
							return TRUE;
						}
						break;
					}

					if (!(psz = new WCHAR[cch + 1]))
					{
						break;
					}
				}

				if (psz)
				{
					delete [] psz;
				}

				return FALSE;
			}
		}

		return FALSE;
	}

	~CmdSocket()
	{
		if (_M_hKey)
		{
			BCryptDestroyKey(_M_hKey);
		}

		if (_M_pvAuth)
		{
			delete [] _M_pvAuth;
		}

		_M_pfx->Release();
	}

public:

	CmdSocket(HWND hwnd, PFX_REF* pfx) : _M_hwnd(hwnd), _M_pfx(pfx)
	{
		pfx->AddRef();
	}

	ULONG GetKey()
	{
		return _M_key;
	}

	BOOL Send(PVOID pv, ULONG cb)
	{
		BOOL fOk = FALSE;
		CDataPacket* packet;
		if (0 <= CreatePacket(&packet, _M_hKey, InterlockedIncrementNoFence(&_M_nextID), _M_key, _M_rkey, pv, cb))
		{
			fOk = !SendTo(&_addr.saAddress, _addr.dwAddressLength, packet);
			packet->Release();
		}

		return fOk;
	}

	BOOL PingOrDisconnect(LONG i)
	{
		BOOL fOk = FALSE;
		CDataPacket* packet;
		if (0 <= CreateSimplyPacket(&packet, i, _M_key, _M_rkey))
		{
			fOk = !SendTo(&_addr.saAddress, _addr.dwAddressLength, packet);
			packet->Release();
			DbgPrint("%u:--> ping [%d]\r\n", GetTickCount()/1000, i);
		}

		return fOk;
	}

	void SetAuth(PVOID pvAuth, ULONG cbAuth)
	{
		_M_pvAuth = pvAuth, _M_cbAuth = cbAuth;
	}

	HRESULT Listen()
	{
		if (CDataPacket* packet = new(0x800) CDataPacket)
		{
			HRESULT hr = RecvFrom(packet);
			packet->Release();
			return hr;
		}

		return E_OUTOFMEMORY;
	}

	HRESULT Start(_Inout_ SOCKADDR_IN_EX* addr)
	{
		SOCKADDR_INET si{addr->saAddress.sa_family};
		HRESULT hr = BCryptGenRandom(0, (PBYTE)&_M_key, sizeof(_M_key), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (0 <= hr && NOERROR == (hr = Create((SOCKADDR*)&si, addr->dwAddressLength)))
		{
			addr->addr.Ipv4.sin_port = 0x7865;
			memcpy(&_addr, addr, sizeof(SOCKADDR_IN_EX));

			return Listen();
		}

		return hr;
	}

	UINT getCP()
	{
		return _M_CPs;
	}

	void setCP(ULONG cp)
	{
		_M_CP = cp;
	}

	ULONG64 GetTime()
	{
		return _dwTime;
	}
};

class ZCmdWnd : public ZSDIFrameWnd, ZTranslateMsg
{
	PFX_REF* _M_pfx = 0;
	CmdSocket* _m_pSocket = 0;
	HWND _hwndEdit[2];
	PWSTR _cmdStrings[16];
	ULONG _iCmd, _iPrev;
	enum { s_disconnected, s_handshake, s_connected } _M_state = s_disconnected;

	void _print(PCWSTR buf)
	{
		SendMessage(_hwndEdit[0], EM_SETSEL, MAXLONG, MAXLONG);
		SendMessage(_hwndEdit[0], EM_REPLACESEL, 0, (LPARAM)buf);	
	}

	void SetCmdPtr(ULONG iPrev)
	{
		ULONG iCmd;
		if (iPrev < _iCmd && (iCmd = (iPrev & (RTL_NUMBER_OF(_cmdStrings) - 1))) != _iCmd)
		{
			if (PWSTR sz = _cmdStrings[iCmd])
			{
				SetWindowTextW(_hwndEdit[1], sz);
				_iPrev = iPrev;
			}
		}
	}

	void SaveCmd(PWSTR lpWideCharStr)
	{
		PWSTR* psz = _cmdStrings + ((_iCmd - 1) & (RTL_NUMBER_OF(_cmdStrings) - 1)), sz = *psz;

		if (sz && !wcscmp(sz, lpWideCharStr))
		{
			_iPrev = _iCmd;
			return;
		}
		if (sz = *(psz = _cmdStrings + (_iCmd & (RTL_NUMBER_OF(_cmdStrings) - 1))))
		{
			free(sz);
		}
		*psz = _wcsdup(lpWideCharStr);
		_iPrev = ++_iCmd;
	}

	BOOL PreTranslateMessage(PMSG lpMsg)
	{
		if (lpMsg->hwnd == _hwndEdit[1])
		{
			switch (lpMsg->message)
			{
			case WM_KEYDOWN:
				switch (lpMsg->wParam)
				{
				case VK_ESCAPE:
					SetWindowTextW(_hwndEdit[1], 0);
					break;
				case VK_DOWN:
					SetCmdPtr(_iPrev + 1);
					break;
				case VK_UP:
					SetCmdPtr(_iPrev - 1);
					break;
				case VK_RETURN:
					if (s_connected == _M_state)
					{
						if (ULONG cchWideChar = GetWindowTextLength(_hwndEdit[1]))
						{
							union {
								PVOID buf;
								PWSTR lpWideCharStr;
								PSTR lpMultiByteStr;
							};

							if (buf = _malloca((cchWideChar + 3) * sizeof(WCHAR)))
							{
								if (cchWideChar = GetWindowText(_hwndEdit[1], lpWideCharStr + 1, cchWideChar + 1))
								{
									SaveCmd(lpWideCharStr + 1);

									if (ULONG cbMultiByte = WideCharToMultiByte(CP_UTF8, 0, 
										lpWideCharStr + 1, cchWideChar, lpMultiByteStr, cchWideChar * sizeof(WCHAR), 0, 0))
									{
										lpMultiByteStr[cbMultiByte++] = '\r';
										lpMultiByteStr[cbMultiByte++] = '\n';

										_m_pSocket->Send(lpMultiByteStr, cbMultiByte);
									}
								}

								_freea(lpWideCharStr);
							}
						}
					}
					break;
				default:return FALSE;
				}
				return TRUE;
			}
		}
		return FALSE;
	}

	virtual BOOL CreateClient(HWND hwnd, int x, int y, int nWidth, int nHeight)
	{
		ZFont* font = ZGLOBALS::getFont();

		HFONT hfont = font->getFont();

		SIZE s;
		font->getSIZE(&s);
		int cy = s.cy + 2;

		if (nHeight < 2 * cy)
		{
			return FALSE;
		}

		_hwndEdit[0] = CreateWindowEx(0, WC_EDIT, 0, 
			WS_VISIBLE|WS_CHILD|ES_AUTOVSCROLL|ES_MULTILINE|ES_READONLY|WS_VSCROLL,//|WS_HSCROLL, 
			x, y, nWidth, nHeight - cy, hwnd, (HMENU)1, NULL, NULL);

		_hwndEdit[1] = CreateWindowEx(0, WC_EDIT, 0, 
			WS_VISIBLE|WS_CHILD|ES_AUTOHSCROLL, 
			x, y + nHeight - cy, nWidth, cy, hwnd, (HMENU)2, NULL, NULL);

		SendMessage(_hwndEdit[0], EM_LIMITTEXT, 0x800000, 0);
		SendMessage(_hwndEdit[0], WM_SETFONT, (WPARAM)hfont, 0);
		SendMessage(_hwndEdit[1], WM_SETFONT, (WPARAM)hfont, 0);

		ED(hwnd, FALSE);
		SetWindowTextW(_hwndEdit[1], L"disconnected");
		return TRUE;
	}

	void DestroySocket(BOOL bSend)
	{
		if (_m_pSocket)
		{
			if (bSend) _m_pSocket->PingOrDisconnect(-1);
			_m_pSocket->Close();
			_m_pSocket->Release();
			_m_pSocket = 0;
		}

		_M_state = s_disconnected;
	}

	void SetCP(HMENU hmenu, UINT CP)
	{
		if (CP)
		{
			WCHAR sz[32];
			MENUITEMINFO mii = { sizeof(mii), MIIM_STRING};
			mii.dwTypeData = sz;
			swprintf_s(sz, _countof(sz), L"CP-%u", CP);
			SetMenuItemInfoW(hmenu, ID_CP, FALSE, &mii);
		}

	}

	void ED(HWND hwnd, BOOL bConnected, UINT CP = 0)
	{
		EnableWindow(_hwndEdit[1], 0 < bConnected);
		if (HMENU hmenu = GetMenu(hwnd))
		{
			static const UINT _s_id[] = { ID_CP, ID_DISCONNECT, ID_CONNECT };
			static const UINT _s_ie[] = { 0, 0, 1 };
			static const UINT _s_s[] = { MF_ENABLED, MF_GRAYED|MF_DISABLED  };
			ULONG i = _countof(_s_id);
			bConnected = !bConnected;
			do 
			{
				BOOL bEnabled = _s_ie[--i];
				EnableMenuItem(hmenu, _s_id[i], bEnabled ^ bConnected);
			} while (i);

			SetCP(hmenu, CP);

			DrawMenuBar(hwnd);
		}
	}

	void SetError(HRESULT dwError)
	{
		LPCVOID lpSource = 0;
		ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
		{
			dwError &= ~FACILITY_NT_BIT;
__nt:
			dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

			lpSource = GetNtMod();
		}

		PWSTR lpText;
		if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
		{
			SetWindowTextW(_hwndEdit[1], lpText);
			LocalFree(lpText);
		}
		else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
		{
			goto __nt;
		}
	}

	virtual LRESULT WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		case WM_ERASEBKGND:
			return TRUE;

		case WM_CTLCOLORSTATIC:
			if ((HWND)lParam == _hwndEdit[0])
			{
				SetTextColor((HDC)wParam, RGB(0,255,0));
				SetBkColor((HDC)wParam, RGB(0,0,0));
				return (LPARAM)GetStockObject(BLACK_BRUSH);
			}
			SetTextColor((HDC)wParam, GetSysColor(COLOR_WINDOW));
			SetBkColor((HDC)wParam, GetSysColor(COLOR_BACKGROUND));
			return (LPARAM)GetSysColorBrush(COLOR_BACKGROUND);

		case WM_CTLCOLOREDIT:
			SetTextColor((HDC)wParam, GetSysColor(COLOR_HIGHLIGHTTEXT));
			SetBkColor((HDC)wParam, GetSysColor(COLOR_HIGHLIGHT));
			return (LPARAM)GetSysColorBrush(COLOR_HIGHLIGHT);

		case WM_CREATE:
			ZTranslateMsg::Insert();
			break;

		case WM_DATA:
			_print((PCWSTR)lParam);
			delete [] (PWSTR)lParam;
			return 0;

		case WM_TIMER:
			if (_m_pSocket && (UINT_PTR)this == wParam)
			{
				DbgPrint("*** %u\r\n", GetTickCount() / 1000);

				if (_m_pSocket->GetTime() < GetTickCount64())
				{
					DbgPrint("!!!!! %u < %u\r\n", (ULONG)_m_pSocket->GetTime() / 1000, (ULONG)GetTickCount64()/1000);
					KillTimer(hwnd, 1);
					DestroySocket(TRUE);
				}
				else
				{
					_m_pSocket->PingOrDisconnect(-2);
				}
			}
			break;

		case WM_CONNECT:
			ED(hwnd, TRUE, (UINT)wParam);
			SetWindowTextW(_hwndEdit[1], 0);
			_M_state = s_connected;
			SetTimer(hwnd, (UINT_PTR)this, 3000, 0);
			break;

		case WM_DISCONNECT:
			KillTimer(hwnd, (UINT_PTR)this);
			ED(hwnd, FALSE);
			if (NOERROR == (ULONG)lParam) 
			{
				SetWindowTextW(_hwndEdit[1], L"disconnected");
			}
			else
			{
				SetError((ULONG)lParam);
			}
			DestroySocket(FALSE);
			return 0;

		case WM_ERROR:
			ED(hwnd, FALSE);
			SetError((ULONG)wParam);
			DestroySocket(TRUE);
			break;

		case WM_DESTROY:
			DestroySocket(TRUE);
			ZTranslateMsg::Remove();
			break;

		case WM_COMMAND:
			switch (wParam)
			{
			case ID_EXIT:
				DestroyWindow(hwnd);
				break;

			case ID_DISCONNECT:
				DestroySocket(TRUE);
				break;

			case ID_CLS:
				SetWindowTextW(_hwndEdit[0], 0);	
				break;

			case ID_CP:
				if (_m_pSocket && s_connected == _M_state)
				{
					CPDlg dlg(_m_pSocket->getCP());
					if (IDOK == dlg.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDD_DIALOG2), hwnd, 0))
					{
						_m_pSocket->setCP(dlg.GetCP());
						if (HMENU hmenu = GetMenu(hwnd))
						{
							SetCP(hmenu, dlg.GetCP());

							DrawMenuBar(hwnd);
						}
					}
				}
				break;

			case ID_CONNECT:
				if (s_disconnected == _M_state)
				{
					HRESULT dwError = ERROR_CANCELLED;

					SOCKADDR_IN_EX addr = {};
					addr.addr.Ipv4.sin_family = AF_INET;
					addr.dwAddressLength = sizeof(SOCKADDR_IN);

					LGOPT* plo = 0;
					ULONG cb = 0;

					{
						ZConnectDlg dlg(&addr.addr.Ipv4.sin_addr.S_un.S_addr, &plo, &cb);
						dlg.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDD_DIALOG1), hwnd, 0);
					}

					if (addr.addr.Ipv4.sin_addr.S_un.S_addr = _byteswap_ulong(addr.addr.Ipv4.sin_addr.S_un.S_addr))
					{
						dwError = ERROR_NO_SYSTEM_RESOURCES;

						if (CmdSocket* pSocket = new CmdSocket(hwnd, _M_pfx))
						{
							if (NOERROR == (dwError = pSocket->Start(&addr)))
							{
								pSocket->SetAuth(plo, cb), plo = 0;

								CDataPacket* packet;
								if (0 <= (dwError = CreateSimplyPacket(&packet, 0, pSocket->GetKey(), 0,
									_M_pfx->_M_pbCertEncoded, _M_pfx->_M_cbCertEncoded)))
								{
									dwError = pSocket->SendTo(&addr.saAddress, addr.dwAddressLength, packet);
									packet->Release();

									if (!dwError)
									{
										_M_state = s_handshake;
										_m_pSocket = pSocket;
										ED(hwnd, -1);
										SetError(ERROR_IO_PENDING);
										return 0;
									}
								}
							}

							pSocket->Close();
							pSocket->Release();
						}

						delete plo;
					}

					SetError(dwError);
				}
				return 0;
			}
			break;
		}

		return ZSDIFrameWnd::WindowProc(hwnd, uMsg, wParam, lParam);
	}

public:

	virtual ~ZCmdWnd()
	{
		int i = RTL_NUMBER_OF(_cmdStrings);
		PWSTR sz, *psz = _cmdStrings;
		do 
		{
			if (sz = *psz++)
			{
				free(sz);
			}
		} while (--i);

		if (_M_pfx)
		{
			_M_pfx->Release();
		}
	}

	ZCmdWnd()
	{
		RtlZeroMemory(_cmdStrings, sizeof(_cmdStrings));
		_iCmd = 0, _iPrev = 0;
	}

	HRESULT Open()
	{
		//*szPfx*szPassword
		PWSTR szPfx, szPassword;
		if (szPfx = wcschr(GetCommandLineW(), '*'))
		{
			if (szPassword = wcschr(++szPfx, '*'))
			{
				*szPassword++ = 0;
__0:
				if (_M_pfx = new PFX_REF)
				{
					return _M_pfx->Open(szPfx, szPassword);
				}

				return E_OUTOFMEMORY;
			}
		}

		szPfx = const_cast<PWSTR>(L"0.pfx"), szPassword = const_cast<PWSTR>(L"");
		goto __0;
	}
};

HANDLE _G_hEvent;

void IO_RUNDOWN::RundownCompleted()
{
	SetEvent(_G_hEvent);
}

void WINAPI ep(void*)
{
	initterm();

	if (_G_hEvent = CreateEvent(0, 0, 0, 0))
	{
		WSADATA wd;
		if (!WSAStartup(WINSOCK_VERSION, &wd))
		{
			ZGLOBALS globals;
			ZFont font(TRUE);
			ZApp app;
			if (font.Init())
			{
				ZCmdWnd cmd;

				if (HRESULT hr = cmd.Open())
				{
					ShowErrorBox(0, hr, L"PFX");
				}
				else
				{
					if (HWND hwnd = cmd.Create(L"Demo cmd client", (HINSTANCE)&__ImageBase, (PCWSTR)IDR_MENU1, FALSE))
					{
						ShowWindow(hwnd, SW_SHOW);
						app.Run();
					}
				}
			}
		}

		IO_RUNDOWN::g_IoRundown.BeginRundown();
		WaitForSingleObject(_G_hEvent, INFINITE);
		NtClose(_G_hEvent);
	}

	destroyterm();
}

_NT_END

