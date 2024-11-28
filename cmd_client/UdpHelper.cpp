#include "stdafx.h"

_NT_BEGIN

#include "../asio/socket.h"
#include "pkt.h"
#include "UdpHelper.h"

UdpHelper::~UdpHelper()
{
	CDataPacket** queue = _M_queue;
	ULONG i = _countof(_M_queue);
	do 
	{
		if (CDataPacket* packet = *queue++)
		{
			packet->Release();
		}
	} while (--i);
}

BOOL UdpHelper::OnRecv(G_PKT* p, ULONG cb, CDataPacket* packet)
{
	LONG i = p->_M_i & MAXLONG;

	if (_M_waitId == i && !_M_mask)
	{
		_M_waitId++;
		return OnPacket(p, cb);
	}

	if (i < _M_waitId)
	{
		return TRUE;
	}

	if ((i -= _M_waitId) >= _countof(_M_queue))
	{
		return FALSE;
	}

	if (_bittestandset(&_M_mask, i))
	{
		return TRUE;
	}

	packet->setDataSize(cb);
	packet->AddRef();
	_M_queue[i] = packet;

	if (_M_mask & (1 + _M_mask) )
	{
		return -1;
	}

	_M_mask = 0;
	CDataPacket** queue = _M_queue;
	i = _countof(_M_queue);
	do 
	{
		if (!(packet = *queue))
		{
			break;
		}
		*queue++ = 0;
		_M_waitId++;

		p = (G_PKT*)(packet->getData() + sizeof(SOCKADDR_IN_EX));
		cb = packet->getDataSize();
		packet->setDataSize(0);

		bool b = OnPacket(p, cb);

		packet->Release();

		if (!b)
		{
			return FALSE;
		}
	} while (--i);

	return TRUE;
}

_NT_END