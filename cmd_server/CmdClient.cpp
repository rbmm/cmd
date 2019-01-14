// cmd_server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

_NT_BEGIN

#include "../inc/initterm.h"
#include "../asio/socket.h"
#include "../winz/Frame.h"
#include "resource.h"

#define DbgPrint /##/

enum {
	WM_CONNECT = WM_APP, WM_DISCONNECT, WM_DATA
};

class CmdSocket : public CTcpEndpoint
{
	HWND _hwnd;

	virtual void LogError(DWORD /*opCode*/, DWORD /*dwError*/)
	{
	}

	virtual BOOL OnConnect(ULONG dwError)
	{
		PostMessage(_hwnd, WM_CONNECT, dwError, 0);

		return TRUE;
	}

	virtual void OnDisconnect()
	{
		PostMessage(_hwnd, WM_DISCONNECT, 0, 0);
	}

	virtual BOOL OnRecv(PSTR Buffer, ULONG cbTransferred)
	{
		if (ULONG cchWideChar = MultiByteToWideChar(CP_UTF8, 0, Buffer, cbTransferred, 0, 0))
		{
			if (PWSTR lpWideCharStr = (PWSTR)LocalAlloc(0, (cchWideChar + 1) * sizeof(WCHAR)))
			{
				if (cchWideChar = MultiByteToWideChar(CP_UTF8, 0, Buffer, cbTransferred, lpWideCharStr, cchWideChar))
				{
					lpWideCharStr[cchWideChar] = 0;

					if (PostMessage(_hwnd, WM_DATA, cchWideChar, (LPARAM)lpWideCharStr))
					{
						return TRUE;
					}
				}
				LocalFree(lpWideCharStr);
			}
		}

		return FALSE;
	}

public:
	CmdSocket(HWND hwnd) : _hwnd(hwnd)
	{
	}
};

class ZConnectDlg : public ZDlg
{
	PULONG _pip;

	virtual INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		case WM_INITDIALOG:
			SendMessageW(GetDlgItem(hwndDlg, IDC_IPADDRESS1), IPM_SETADDRESS, 0, IP(1,0,0,127));
			break;
		case WM_COMMAND:
			switch (wParam)
			{
			case IDOK:
				SendMessageW(GetDlgItem(hwndDlg, IDC_IPADDRESS1), IPM_GETADDRESS, 0, (LPARAM)_pip);
				[[fallthrough]];
			case IDCANCEL:
				EndDialog(hwndDlg, 0);
				break;
			}
			break;
		}
		return ZDlg::DialogProc(hwndDlg, uMsg, wParam, lParam);
	}
public:
	ZConnectDlg(PULONG pip) : _pip(pip) {}
};

class ZCmdWnd : public ZSDIFrameWnd, ZTranslateMsg
{
	HWND _hwndEdit[2];
	CmdSocket* _socket;
	PWSTR _cmdStrings[16];
	ULONG _iCmd, _iPrev;

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
					if (_socket)
					{
						if (ULONG cchWideChar = GetWindowTextLength(_hwndEdit[1]))
						{
							if (PWSTR lpWideCharStr = (PWSTR)_malloca((cchWideChar + 1)*sizeof(WCHAR)))
							{
								if (cchWideChar = GetWindowText(_hwndEdit[1], lpWideCharStr, cchWideChar + 1))
								{
									if (ULONG cbMultiByte = WideCharToMultiByte(CP_UTF8, 0, lpWideCharStr, cchWideChar, 0, 0, 0, 0))
									{
										if (CDataPacket* packet = new(cbMultiByte + 2) CDataPacket)
										{
											PSTR lpMultiByteStr = packet->getData();

											if (cbMultiByte = WideCharToMultiByte(CP_UTF8, 0, 
												lpWideCharStr, cchWideChar, 
												lpMultiByteStr, cbMultiByte, 0, 0))
											{
												lpMultiByteStr += cbMultiByte;
												*lpMultiByteStr++ = '\r';
												*lpMultiByteStr++ = '\n';
												packet->setDataSize(cbMultiByte + 2);
												if (!_socket->Send(packet))
												{
													SaveCmd(lpWideCharStr);
													SetWindowTextW(_hwndEdit[1], 0);
												}
												packet->Release();
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

		SendMessage(_hwndEdit[0], WM_SETFONT, (WPARAM)hfont, 0);
		SendMessage(_hwndEdit[1], WM_SETFONT, (WPARAM)hfont, 0);

		ED(hwnd, FALSE);
		SetWindowTextW(_hwndEdit[1], L"disconnected");
		return TRUE;
	}

	void DestroySocket()
	{
		if (_socket)
		{
			_socket->Close();
			_socket->Release();
			_socket = 0;
		}
	}

	void ED(HWND hwnd, BOOL bConnected)
	{
		EnableWindow(_hwndEdit[1], 0 < bConnected);
		if (HMENU hmenu = GetMenu(hwnd))
		{
			EnableMenuItem(hmenu, ID_CONNECT, bConnected ? MF_GRAYED|MF_DISABLED : MF_ENABLED);
			EnableMenuItem(hmenu, ID_DISCONNECT, bConnected ? MF_ENABLED : MF_GRAYED|MF_DISABLED);
			DrawMenuBar(hwnd);
		}
	}

	void SetError(ULONG dwError)
	{
		PWSTR sz;
		if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 
			0, dwError, 0, (PWSTR)&sz, 0, 0))
		{
			SetWindowTextW(_hwndEdit[1], sz);
			LocalFree(sz);
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
			_socket = 0;
			ZTranslateMsg::Insert();
			break;

		case WM_DATA:
			_print((PCWSTR)lParam);
			LocalFree((PVOID)lParam);
			return 0;

		case WM_CONNECT:
			if ((ULONG)wParam == NOERROR)
			{
				ED(hwnd, TRUE);
				SetWindowTextW(_hwndEdit[1], 0);
				return 0;
			}
			SetError((ULONG)wParam);
			[[fallthrough]];
		case WM_DISCONNECT:
			ED(hwnd, FALSE);
			if ((ULONG)wParam == NOERROR) SetWindowTextW(_hwndEdit[1], L"disconnected");
			DestroySocket();
			return 0;

		case WM_DESTROY:
			DestroySocket();
			ZTranslateMsg::Remove();
			break;

		case WM_COMMAND:
			switch (wParam)
			{
			case ID_EXIT:
				DestroyWindow(hwnd);
				break;
			case ID_DISCONNECT:
				DestroySocket();
				break;
			case ID_CONNECT:
				if (!_socket)
				{
					ULONG dwError = ERROR_CANCELLED;

					ULONG ip = 0;
					if (ZConnectDlg* p = new ZConnectDlg(&ip))
					{
						p->DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDD_DIALOG1), hwnd, 0);
						p->Release();
					}

					if (ip = _byteswap_ulong(ip))
					{
						dwError = ERROR_NO_SYSTEM_RESOURCES;

						if (CmdSocket* socket = new CmdSocket(hwnd))
						{
							if (!(dwError = socket->Create(0x4000)) && !(dwError = socket->Connect(ip, 0x7865)))
							{
								_socket = socket;
								ED(hwnd, -1);
								SetError(ERROR_IO_PENDING);
								return 0;
							}
							socket->Release();
						}
					}

					SetError(dwError);

				}
				return 0;
			}
			break;
		}
		return ZSDIFrameWnd::WindowProc(hwnd, uMsg, wParam, lParam);
	}
	
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
	}
public:

	ZCmdWnd()
	{
		RtlZeroMemory(_cmdStrings, sizeof(_cmdStrings));
		_iCmd = 0, _iPrev = 0;
	}
};

struct MyRundown : public RUNDOWN_REF 
{
	virtual void RundownCompleted()
	{
		WSACleanup();
		destroyterm();
		ExitProcess(0);
	}
} grr;

RUNDOWN_REF * g_IoRundown = &grr;

void WINAPI ep(void*)
{
	initterm();

	WSADATA wd;
	if (!WSAStartup(WINSOCK_VERSION, &wd))
	{
		ZGLOBALS globals;
		ZFont font(TRUE);
		ZApp app;
		if (font.Init())
		{
			HWND hwnd = 0;

			if (ZCmdWnd* p = new ZCmdWnd)
			{
				hwnd = p->Create(L"Demo cmd client", (HINSTANCE)&__ImageBase, (PCWSTR)IDR_MENU1, FALSE);
				p->Release();
			}

			if (hwnd)
			{
				ShowWindow(hwnd, SW_SHOW);
				app.Run();
			}
		}
	}

	grr.BeginRundown();
}
_NT_END

