#pragma once

struct __declspec(novtable) UdpHelper 
{
	CDataPacket* _M_queue[8] = {};
	LONG _M_mask = 0;
	LONG _M_waitId = 1;

	~UdpHelper();
	virtual bool OnPacket(G_PKT* pkt, ULONG cb) = 0;


	BOOL OnRecv(G_PKT* p, ULONG cb, CDataPacket* packet);
};
