#pragma once

int CustomMessageBox(HWND hWnd, PCWSTR lpText, PCWSTR lpszCaption, UINT uType);
int ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR lpCaption);
HMODULE GetNtMod();

HRESULT GetLastErrorEx(ULONG dwError = GetLastError());

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastErrorEx();
	return t;
}