
#include <iostream>
#include "LX_IOSCP.h"
#pragma comment( lib, "Ws2_32.lib" )
#pragma comment( lib, "Mswsock.lib" )

using namespace std;

unsigned short CheckSum(unsigned short *buffer, int size)
{//����У��͵ķ���
	unsigned long cksum = 0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned short*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}

void get_domain_ip(string domain_name, std::vector<in_addr> *ips)
{
	addrinfo hints, *result, *temp;
	memset(&hints, 0, sizeof(hints));
	//hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_INET;
	if (getaddrinfo(domain_name.c_str(), NULL, &hints, &result) == 0)
	{
		printf("����%s�õ���ip����:\n",domain_name.c_str());
		temp = result;
		for (; temp != 0; temp = temp->ai_next)
		{
			printf("ip: %s\n", inet_ntoa(((SOCKADDR_IN*)(temp->ai_addr))->sin_addr));
			ips->push_back(((SOCKADDR_IN*)(temp->ai_addr))->sin_addr);
		}
	}
	else
	{
		printf("��ȡip��ַʧ��\n");
		return;
	}
	freeaddrinfo(result);
}

void get_local_addr(std::vector<in_addr> *ips)
{
	char		name[255];
	gethostname(name, sizeof(name));
	//��ȡ�����������󣬵���getaddrinfo�����������������ɻ�ñ���IP��ַ
	addrinfo hints, *result, *temp;
	memset(&hints, 0, sizeof(hints));
	//hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_INET;
	if (getaddrinfo(name, NULL, &hints, &result) == 0)
	{
		printf("����ip����:\n");
		temp = result;
		for (int i = 0; temp != 0; temp = temp->ai_next,i++)
		{
			printf("index: %d ip: %s\n", i,inet_ntoa(((SOCKADDR_IN*)(temp->ai_addr))->sin_addr));
			ips->push_back(((SOCKADDR_IN*)(temp->ai_addr))->sin_addr);
		}
	}
	else
	{
		printf("��ȡip��ַʧ��\n");
		return;
	}
	freeaddrinfo(result);
}


void init_network()
{
	WSADATA wsaData;
	//MAKEWORD(2, 2)ָ��׼�����ص�winsock��汾
	if (0 == WSAStartup(MAKEWORD(2, 2), &wsaData))//WSAStartup�����ÿ�������Ϣ���ṹ��
	{
		//�������ֵ��0,��ôwinsock��ʼ���ɹ�
		printf("winsock��ʼ���ɹ�\n");
		printf("��ǰʹ�ð汾 %d ,��ƽ̨������߰汾 %d\n", LOBYTE(wsaData.wVersion), LOBYTE(wsaData.wHighVersion));
	}
}
void clear_network()
{
	if (WSACleanup() == 0)
	{
		//cleanup�ɹ�
		printf("winsock Clean Up�ɹ�\n");
	}
}

LX_IOSCP::LX_IOSCP()
{
}


LX_IOSCP::~LX_IOSCP()
{
}

BOOL LX_IOSCP::Create()
{
	m_hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	return(m_hIOCP != NULL);
}
void LX_IOSCP::Close()
{
	CloseHandle(m_hIOCP);
}
BOOL LX_IOSCP::AssociateDevice(HANDLE hDevice, ULONG_PTR CompKey)
{
	BOOL fOk = (CreateIoCompletionPort(hDevice, m_hIOCP, CompKey, 0)== m_hIOCP);
	return(fOk);
}
BOOL LX_IOSCP::AssociateSocket(SOCKET hSocket, ULONG_PTR CompKey)
{
	BOOL fOk = (CreateIoCompletionPort((HANDLE)hSocket, m_hIOCP, CompKey, 0) == m_hIOCP);
	return(fOk);
}
BOOL LX_IOSCP::PostStatus(ULONG_PTR CompKey, DWORD dwNumBytes, OVERLAPPED* po)
{
	BOOL fOk = PostQueuedCompletionStatus(m_hIOCP, dwNumBytes, CompKey, po);
	return(fOk);
}
BOOL LX_IOSCP::GetStatus(ULONG_PTR* pCompKey, PDWORD pdwNumBytes, OVERLAPPED** ppo, DWORD dwMilliseconds)
{
	return(GetQueuedCompletionStatus(m_hIOCP, pdwNumBytes,pCompKey, ppo, dwMilliseconds));
}



LPFN_ACCEPTEX pfnAcceptEx = 0;
LPFN_CONNECTEX pfnConnectEx = 0;
LPFN_DISCONNECTEX pfnDisconnectEx = 0;
LPFN_GETACCEPTEXSOCKADDRS pfnGetAcceptExSockaddrs = 0;
LPFN_TRANSMITFILE pfnTransmitfile = 0;
LPFN_TRANSMITPACKETS pfnTransmitPackets = 0;
LPFN_WSARECVMSG pfnWSARecvMsg = 0;
LPFN_WSASENDMSG pfnWSASendMsg = 0;

void LoadALLWinsockFun_TCP()
{
	SOCKET skTemp = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	GUID funGuid;
	DWORD dwOutBufferSize = 0;
	int Ret = 0;

	funGuid = WSAID_ACCEPTEX;
	Ret = ::WSAIoctl(skTemp, SIO_GET_EXTENSION_FUNCTION_POINTER, &funGuid, sizeof(funGuid), &pfnAcceptEx, sizeof(pfnAcceptEx), &dwOutBufferSize, NULL, NULL);
	if (Ret == SOCKET_ERROR) cout << "AcceptEx ����ʧ��!\n";
	else cout << "AcceptEx ���سɹ�!\n";

	funGuid = WSAID_CONNECTEX;
	Ret = ::WSAIoctl(skTemp, SIO_GET_EXTENSION_FUNCTION_POINTER, &funGuid, sizeof(funGuid), &pfnConnectEx, sizeof(pfnConnectEx), &dwOutBufferSize, NULL, NULL);
	if (Ret == SOCKET_ERROR) cout << "ConnectEx ����ʧ��!\n";
	else cout << "ConnectEx ���سɹ�!\n";

	funGuid = WSAID_DISCONNECTEX;
	Ret = ::WSAIoctl(skTemp, SIO_GET_EXTENSION_FUNCTION_POINTER, &funGuid, sizeof(funGuid), &pfnDisconnectEx, sizeof(pfnDisconnectEx), &dwOutBufferSize, NULL, NULL);
	if (Ret == SOCKET_ERROR) cout << "DisconnectEx ����ʧ��!\n";
	else cout << "DisconnectEx ���سɹ�!\n";

	funGuid = WSAID_GETACCEPTEXSOCKADDRS;
	Ret = ::WSAIoctl(skTemp, SIO_GET_EXTENSION_FUNCTION_POINTER, &funGuid, sizeof(funGuid), &pfnGetAcceptExSockaddrs, sizeof(pfnGetAcceptExSockaddrs), &dwOutBufferSize, NULL, NULL);
	if (Ret == SOCKET_ERROR) cout << "GetAcceptExSockaddrs ����ʧ��!\n";
	else cout << "GetAcceptExSockaddrs ���سɹ�!\n";

	funGuid = WSAID_TRANSMITFILE;
	Ret = ::WSAIoctl(skTemp, SIO_GET_EXTENSION_FUNCTION_POINTER, &funGuid, sizeof(funGuid), &pfnTransmitfile, sizeof(pfnTransmitfile), &dwOutBufferSize, NULL, NULL);
	if (Ret == SOCKET_ERROR) cout << "TransmitFile ����ʧ��!\n";
	else cout << "TransmitFile ���سɹ�!\n";

	funGuid = WSAID_TRANSMITPACKETS;
	Ret = ::WSAIoctl(skTemp, SIO_GET_EXTENSION_FUNCTION_POINTER, &funGuid, sizeof(funGuid), &pfnTransmitPackets, sizeof(pfnTransmitPackets), &dwOutBufferSize, NULL, NULL);
	if (Ret == SOCKET_ERROR) cout << "TransmitPackets ����ʧ��!\n";
	else cout << "TransmitPackets ���سɹ�!\n";

	funGuid = WSAID_WSARECVMSG;
	Ret = ::WSAIoctl(skTemp, SIO_GET_EXTENSION_FUNCTION_POINTER, &funGuid, sizeof(funGuid), &pfnWSARecvMsg, sizeof(pfnWSARecvMsg), &dwOutBufferSize, NULL, NULL);
	if (Ret == SOCKET_ERROR) cout << "WSARecvMsg ����ʧ��!\n";
	else cout << "WSARecvMsg ���سɹ�!\n";

	funGuid = WSAID_WSASENDMSG;
	Ret = ::WSAIoctl(skTemp, SIO_GET_EXTENSION_FUNCTION_POINTER, &funGuid, sizeof(funGuid), &pfnWSASendMsg, sizeof(pfnWSASendMsg), &dwOutBufferSize, NULL, NULL);
	if (Ret == SOCKET_ERROR) cout << "WSASendMsg ����ʧ��!\n";
	else cout << "WSASendMsg ���سɹ�!\n";

	closesocket(skTemp);

}