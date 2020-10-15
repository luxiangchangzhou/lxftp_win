#pragma once
#include <Winsock2.h>
#include <MSWSOCK.h> 
#include <Ws2tcpip.h>
#include <windows.h>
#include <vector>
#include <string>
class LX_IOSCP
{
public:
	LX_IOSCP();
	~LX_IOSCP();
	BOOL Create();
	void Close();
	BOOL AssociateDevice(HANDLE hDevice, ULONG_PTR CompKey);
	BOOL AssociateSocket(SOCKET hSocket, ULONG_PTR CompKey);
	BOOL PostStatus(ULONG_PTR CompKey, DWORD dwNumBytes = 0, OVERLAPPED* po = NULL);
	BOOL GetStatus(ULONG_PTR* pCompKey, PDWORD pdwNumBytes, OVERLAPPED** ppo, DWORD dwMilliseconds = INFINITE);
	HANDLE m_hIOCP = 0;
};

void get_local_addr(std::vector<in_addr> *ips);
void get_domain_ip(std::string domain_name, std::vector<in_addr> *ips);
unsigned short CheckSum(unsigned short *buffer, int size);

void LoadALLWinsockFun_TCP();

void init_network();
void clear_network();


extern	LPFN_ACCEPTEX pfnAcceptEx;
extern	LPFN_CONNECTEX pfnConnectEx;
extern	LPFN_DISCONNECTEX pfnDisconnectEx;
extern	LPFN_GETACCEPTEXSOCKADDRS pfnGetAcceptExSockaddrs;
extern	LPFN_TRANSMITFILE pfnTransmitfile;
extern	LPFN_TRANSMITPACKETS pfnTransmitPackets;
extern	LPFN_WSARECVMSG pfnWSARecvMsg;
extern	LPFN_WSASENDMSG pfnWSASendMsg;



