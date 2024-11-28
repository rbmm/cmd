#pragma once

struct G_PKT 
{
	LONG _M_i; // -1 disconnect, 80000000+i ping
	ULONG _M_ckey;
	ULONG64 _M_skey;
	UCHAR _M_buf[];
};

C_ASSERT(sizeof(G_PKT)==offsetof(G_PKT, _M_buf));