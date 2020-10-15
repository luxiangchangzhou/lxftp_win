#include <Winsock2.h>
#include "LX_IOSCP.h"
#include <iostream> 
#include <list>
#include <thread>
#include <vector>
#include <stdio.h>
using namespace std;

#define BUFFER_SIZE             64*1024
#define HEADER_SIZE             136 //128���ֽڵ��ļ������� + 8���ֽ�����ʾ���ļ���С
#define SERVER_REPORT_SIZE      8//��������Ӧ���ļ���С���ݰ��Ĵ�С ��sizeof(long long)

void thread_func(LX_IOSCP*iocp);



enum IOCPEvents
{
    sock_event_read,
    sock_event_accept,
    sock_event_write,
    sock_event_disconnect,
    file_event_read,
    file_event_accept,
    file_event_write,
};



struct LX_OVERLAPPED
{
    WSAOVERLAPPED m_wsaol;         //�ļ�io��socket io����
    SOCKET        m_skListen;      //�����׽��־��
    long          m_lNetworkEvents;//Ͷ�ݵĲ�������(sock_event_read/FD_WRITE��)
    SOCKET        m_socket;        //Ͷ�ݲ�����SOCKET���
    void*         m_pBuf;          //Ͷ�ݲ���ʱ�Ļ���
    size_t        m_szBufLen;      //���峤��
    sockaddr_in   localaddr;       //���ص�ַ
    sockaddr_in   remoteaddr;      //�Զ˵�ַ
    long long     total_trans_num; //������ֽ���(recv��send���ܺ�)
    char          filename[128];   //�ļ���
    long long     filesize;        //�ļ�����
    /////////�޴������//////////////
    HANDLE        hfile;           //�ļ����
    long long     localfilesize;    //�����ļ���С
    FILE * fp;
    long long     transfilesize;   //�Ѿ�����(д��)���ļ���С
};


int main()
{
    init_network();
    //����winsock�����ܺ���
    LoadALLWinsockFun_TCP();

    int max_num_of_connections = 1000;
    int index = 0;
    LX_IOSCP iocp;
    iocp.Create();
    SOCKET ListenSocket, AcceptSocket;
    SOCKET* pskAcceptArray = NULL;
    LX_OVERLAPPED** pMyOLArray = NULL;
    vector<thread*> iocp_threads;

    //Ԥ������socket�صĿռ�
    pskAcceptArray = new SOCKET[max_num_of_connections];
    pMyOLArray = new LX_OVERLAPPED*[max_num_of_connections];//ע�����Ǹ�ָ������ ʵ�ʵĿռ俪�ٷ���AcceptExѭ���н���

    //����CPU�������߳�
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    for (int i = 0; i < si.dwNumberOfProcessors; i++)
    {
        iocp_threads.push_back(new thread(thread_func, &iocp));
    }

    ListenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);

    //��SOCKET�������ɶ˿ڶ����,���ҵ��������ģʽ��,��ɼ���ȫû���õ�~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    iocp.AssociateSocket(ListenSocket, 0);

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5050);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    ::bind(ListenSocket, (SOCKADDR *)&server_addr, sizeof(SOCKADDR));
    ::listen(ListenSocket, SOMAXCONN);
    cout << "listening" << endl;


    for (int i = 0; i < max_num_of_connections; i++)
    {
        AcceptSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        //��SOCKET�������ɶ˿ڶ����
        iocp.AssociateSocket(AcceptSocket, 0);

        LX_OVERLAPPED *pOLAcceptEx = NULL;
        pOLAcceptEx = new LX_OVERLAPPED;
        ZeroMemory(pOLAcceptEx, sizeof(LX_OVERLAPPED));
        pOLAcceptEx->m_skListen = ListenSocket;
        pOLAcceptEx->m_socket = AcceptSocket;
        pOLAcceptEx->m_lNetworkEvents = sock_event_accept;
        pOLAcceptEx->m_pBuf = new char[2 * (sizeof(SOCKADDR_IN) + 16)]; //����new������bufferֻ���������ַ�õ�,��accept֮��ᱻdelete��
        pOLAcceptEx->m_szBufLen = 2 * (sizeof(SOCKADDR_IN) + 16);


        if (FALSE == pfnAcceptEx(ListenSocket, AcceptSocket
            , pOLAcceptEx->m_pBuf, 0, sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16
            , /*&pOLAcceptEx->m_dwFlags*/ 0, &pOLAcceptEx->m_wsaol))
        {
            int iError = WSAGetLastError();
            if (ERROR_IO_PENDING != iError)
            {
                exit(0);
            }

        }

        pskAcceptArray[index] = AcceptSocket;
        pMyOLArray[index] = pOLAcceptEx;
        ++index;
        cout << "AcceptEx(" << i << ")..." << endl;


    }

    cin.get();

    //������������Դ
    LX_OVERLAPPED Close_OverLapped = { 0 };
    Close_OverLapped.m_socket = INVALID_SOCKET;
    for (int i = 0; i < si.dwNumberOfProcessors; i++)
    {
        iocp.PostStatus(0, 0, (LPOVERLAPPED)&Close_OverLapped);
    }

    for (int i = 0; i < si.dwNumberOfProcessors; i++)
    {
        iocp_threads[i]->join();
        delete iocp_threads[i];
    }

    iocp.Close();

    closesocket(ListenSocket);

    for (int i = 0; i < index; i++)
    {
        closesocket(pskAcceptArray[i]);
    }
    delete pskAcceptArray;
    delete pMyOLArray;


    clear_network();

    return 0;
}

void thread_func(LX_IOSCP*iocp)
{
    ULONG_PTR       Key = NULL;//���ҵ������,������û��
    LX_OVERLAPPED*  lx_olapped = NULL;
    DWORD           dwBytesTransfered = 0;
    DWORD           dwFlags = 0;
    BOOL            bRet = TRUE;

    BOOL bLoop = TRUE;

    while (bLoop)
    {
        bRet = iocp->GetStatus(&Key, &dwBytesTransfered, (LPOVERLAPPED*)&lx_olapped, INFINITE);

        if (FALSE == bRet)
        {
            cout << "IOCPThread: GetQueuedCompletionStatus ����ʧ��,������: " << GetLastError() << endl;
            ////������Դ
            //////////////////////////////////////////////////////////
            ////Ϊ�˱����ظ��ͷ���Դ
            //if (lx_olapped->transfilesize == (lx_olapped->filesize + HEADER_SIZE + SERVER_REPORT_SIZE))
            //{
            //}
            //CloseHandle(lx_olapped->hfile);
            //printf("�ļ�����ɹ�\n");
            //delete lx_olapped->m_pBuf;
            //lx_olapped->m_lNetworkEvents = sock_event_disconnect;
            ////����SOCKET
            //pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
            /////////////////////////////////////////////////////////////////
            continue;
        }


        switch (lx_olapped->m_lNetworkEvents)
        {
        case sock_event_write:
        {
            if (dwBytesTransfered == 0)
            {
                //��ζ�����ӷ�������,��ʱ��Ϳ��Ի����׽�����
                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                printf("�յ�0�ֽ�\n");
                //������Դ
                ////////////////////////////////////////////////////////
                CloseHandle(lx_olapped->hfile);
                printf("�ļ�����ɹ�\n");
                delete lx_olapped->m_pBuf;
                lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                //����SOCKET
                pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                ///////////////////////////////////////////////////////////////



            }
            lx_olapped->total_trans_num += dwBytesTransfered;

            //���������ζ�ŷ�������8�ֽڻ�Ӧ��û����,���Ȼ�Ǽ��ٷ��������
            if (lx_olapped->total_trans_num < (HEADER_SIZE + SERVER_REPORT_SIZE))
            {
                //����ǰ�ļ���С���͸��ͻ���
                WSABUF wsabuf{ sizeof(long long)- (lx_olapped->total_trans_num - HEADER_SIZE),
                    (char*)(&lx_olapped->localfilesize)+ (lx_olapped->total_trans_num - HEADER_SIZE) };
                lx_olapped->m_lNetworkEvents = sock_event_write;
                if (WSASend(lx_olapped->m_socket, &wsabuf, 1, 0, 0, (WSAOVERLAPPED*)lx_olapped, 0) == SOCKET_ERROR)
                {
                    int iErrorCode = WSAGetLastError();
                    if (iErrorCode != WSA_IO_PENDING)
                    {
                        cout << "Error occurred at WSASend " << iErrorCode << endl;
                        //������Դ
                        ////////////////////////////////////////////////////////
                        CloseHandle(lx_olapped->hfile);
                        printf("�ļ�����ɹ�\n");
                        delete lx_olapped->m_pBuf;
                        lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                        //����SOCKET
                        pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                        ///////////////////////////////////////////////////////////////
                    }
                }
            }//��ʱ��ζ��8�ֽڻ�Ӧ���������
            else if(lx_olapped->total_trans_num == (HEADER_SIZE + SERVER_REPORT_SIZE))
            {
                if (lx_olapped->filesize <= lx_olapped->localfilesize)
                {
                    ///////////////////////////////////////////////////////////////////////////////////////
                    //ֱ�Ӷ���
                    CloseHandle(lx_olapped->hfile);
                    printf("---------------������ͬ�ļ�,�Ͽ�����-----------------\n");
                    delete lx_olapped->m_pBuf;
                    lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                    //����SOCKET
                    pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                }
                else//�����ļ���СС�ڿͻ��˵��ļ���С,��ô����ζ�ſ����ϵ�����ģʽ,�ͻ��˽��ӷ����ָ�����ļ�λ�÷����ļ�
                {
                    if (lx_olapped->localfilesize != 0)
                    {
                        printf("********************�����ϵ�����ģʽ\n");
                    }
                    lx_olapped->transfilesize = lx_olapped->localfilesize;

                    WSABUF wsabuf = { lx_olapped->m_szBufLen ,(char*)lx_olapped->m_pBuf };
                    lx_olapped->m_lNetworkEvents = sock_event_read;
                    DWORD Flags = 0;//��������ò���,���Ǳ�����
                    if (WSARecv(lx_olapped->m_socket, &wsabuf, 1, 0
                        , &Flags, (WSAOVERLAPPED*)lx_olapped, NULL) == SOCKET_ERROR)
                    {
                        int iErrorCode = WSAGetLastError();
                        if (iErrorCode != WSA_IO_PENDING)
                        {
                            cout << "Error occurred at WSARecv " << iErrorCode << endl;
                            //������Դ
                            ////////////////////////////////////////////////////////
                            CloseHandle(lx_olapped->hfile);
                            printf("�ļ�����ɹ�\n");
                            delete lx_olapped->m_pBuf;
                            lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                            //����SOCKET
                            pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                            ///////////////////////////////////////////////////////////////
                        }
                    }
                }
            }

        }
        break;
        case sock_event_accept:
        {
            printf("�߳�[0x%x]��ɲ���(AcceptEx),����(0x%08x)����(%ubytes)\n",
                GetCurrentThreadId(), lx_olapped->m_pBuf, lx_olapped->m_szBufLen);

            SOCKADDR_IN* psaLocal = NULL;
            int         iLocalLen = sizeof(SOCKADDR_IN);
            SOCKADDR_IN* psaRemote = NULL;
            int         iRemoteLen = sizeof(SOCKADDR_IN);

            pfnGetAcceptExSockaddrs(lx_olapped->m_pBuf, 0
                , sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16
                , (SOCKADDR**)&psaLocal, &iLocalLen, (SOCKADDR**)&psaRemote, &iRemoteLen);

            //����ȡ�ĵ�ַ��������
            lx_olapped->localaddr = *psaLocal;
            lx_olapped->remoteaddr = *psaRemote;


            cout << "�ͻ���[" << inet_ntoa(lx_olapped->remoteaddr.sin_addr) << ":" << ntohs(lx_olapped->remoteaddr.sin_port)
                << "]���ӽ���,����ͨѶ��ַ[" << inet_ntoa(lx_olapped->localaddr.sin_addr) << ":" << ntohs(lx_olapped->localaddr.sin_port)
                << "]" << endl;

            delete []lx_olapped->m_pBuf;


            //�������������Ϳ��Խ���������
            lx_olapped->m_pBuf = new char[BUFFER_SIZE];
            lx_olapped->m_szBufLen = BUFFER_SIZE;
            WSABUF wsabuf = { HEADER_SIZE ,(char*)lx_olapped->m_pBuf};
            lx_olapped->m_lNetworkEvents = sock_event_read;
            DWORD Flags = 0;//��������ò���,���Ǳ�����
            if (WSARecv(lx_olapped->m_socket, &wsabuf, 1, 0
                , &Flags, (WSAOVERLAPPED*)lx_olapped, NULL) == SOCKET_ERROR)
            {
                int iErrorCode = WSAGetLastError();
                if (iErrorCode != WSA_IO_PENDING)
                {
                    cout << "Error occurred at WSARecv " << iErrorCode << endl;
                    //������Դ
                    ////////////////////////////////////////////////////////
                    CloseHandle(lx_olapped->hfile);
                    printf("�ļ�����ɹ�\n");
                    delete lx_olapped->m_pBuf;
                    lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                    //����SOCKET
                    pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                    ///////////////////////////////////////////////////////////////



                }
            }
        }
        break;
        case file_event_write:
        {
            //printf("�ɹ�д�� %d ���ֽ�\n",dwBytesTransfered);
            memset(&lx_olapped->m_wsaol, 0, sizeof(WSAOVERLAPPED));

            lx_olapped->transfilesize += dwBytesTransfered;
            if (lx_olapped->filesize > lx_olapped->transfilesize)
            {
                WSABUF wsabuf = { lx_olapped->m_szBufLen ,(char*)lx_olapped->m_pBuf };
                lx_olapped->m_lNetworkEvents = sock_event_read;
                DWORD Flags = 0;//��������ò���,���Ǳ�����
                if (WSARecv(lx_olapped->m_socket, &wsabuf, 1, 0
                    , &Flags, (WSAOVERLAPPED*)lx_olapped, NULL) == SOCKET_ERROR)
                {
                    int iErrorCode = WSAGetLastError();
                    if (iErrorCode != WSA_IO_PENDING)
                    {
                        cout << "Error occurred at WSARecv " << iErrorCode << endl;
                        //������Դ
                        ////////////////////////////////////////////////////////
                        CloseHandle(lx_olapped->hfile);
                        printf("�ļ�����ɹ�\n");
                        delete lx_olapped->m_pBuf;
                        lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                        //����SOCKET
                        pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                        ///////////////////////////////////////////////////////////////
                    }
                }
            }
            else
            {
                //������Դ
                ////////////////////////////////////////////////////////
                CloseHandle(lx_olapped->hfile);
                printf("�ļ�����ɹ�\n");
                delete lx_olapped->m_pBuf;
                lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                //����SOCKET
                pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                ///////////////////////////////////////////////////////////////
            }
        }

          
        break;
        case sock_event_read:
        {
            if (dwBytesTransfered == 0)
            {
                //��ζ�����ӷ�������,��ʱ��Ϳ��Ի����׽�����
                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                printf("�յ�0�ֽ�\n");
                //������Դ
                ////////////////////////////////////////////////////////
                CloseHandle(lx_olapped->hfile);
                printf("�ļ�����ɹ�\n");
                delete lx_olapped->m_pBuf;
                lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                //����SOCKET
                pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                ///////////////////////////////////////////////////////////////
            }


            lx_olapped->total_trans_num += dwBytesTransfered;


            if (lx_olapped->total_trans_num < HEADER_SIZE)
            {
                WSABUF wsabuf = { HEADER_SIZE - lx_olapped->total_trans_num ,(char*)lx_olapped->m_pBuf+ lx_olapped->total_trans_num };
                lx_olapped->m_lNetworkEvents = sock_event_read;
                DWORD Flags = 0;//��������ò���,���Ǳ�����
                if (WSARecv(lx_olapped->m_socket, &wsabuf, 1, 0
                    , &Flags, (WSAOVERLAPPED*)lx_olapped, NULL) == SOCKET_ERROR)
                {
                    int iErrorCode = WSAGetLastError();
                    if (iErrorCode != WSA_IO_PENDING)
                    {
                        cout << "Error occurred at WSARecv " << iErrorCode << endl;
                        //������Դ
                        ////////////////////////////////////////////////////////
                        CloseHandle(lx_olapped->hfile);
                        printf("�ļ�����ɹ�\n");
                        delete lx_olapped->m_pBuf;
                        lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                        //����SOCKET
                        pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                        ///////////////////////////////////////////////////////////////
                    }
                }

            }//��ʱ��ζ�ſ��Ի�ȡ�ļ������Ⱥ��ļ������ֶ���
            else if(lx_olapped->total_trans_num == HEADER_SIZE)
            {
                memcpy(lx_olapped->filename, lx_olapped->m_pBuf, 128);
                lx_olapped->filesize = *((long long*)((char*)lx_olapped->m_pBuf+128));
                printf("����ͷ�ֶγɹ�\n");

                //�����ļ�
                //lx_olapped->fp = fopen(lx_olapped->filename, "wb+");

                //����Ŀ���ļ�(��windows��,�Զ�ռ��ʽ���ļ�)
                lx_olapped->hfile = CreateFileA(lx_olapped->filename, GENERIC_WRITE,0, NULL, OPEN_ALWAYS,
                    FILE_FLAG_OVERLAPPED, NULL);
                if (lx_olapped->hfile == INVALID_HANDLE_VALUE)
                {
                    printf("create file failed\n");
                    //������Դ
                    ////////////////////////////////////////////////////////
                    CloseHandle(lx_olapped->hfile);
                    printf("�ļ�����ɹ�\n");
                    delete lx_olapped->m_pBuf;
                    lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                    //����SOCKET
                    pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                    ///////////////////////////////////////////////////////////////
                }
                else//��ʱ���ļ��ɹ�
                {
                    //���ļ������ӵ�iocp���豸����
                    iocp->AssociateDevice(lx_olapped->hfile, 0);
                    //��ȡ�ļ���С
                    GetFileSizeEx(lx_olapped->hfile, (LARGE_INTEGER*)(&lx_olapped->localfilesize));
                    //����������ǰ�ļ���С���͸��ͻ���
                    WSABUF wsabuf{ sizeof(long long),(char*)(&lx_olapped->localfilesize) };
                    lx_olapped->m_lNetworkEvents = sock_event_write;
                    if (WSASend(lx_olapped->m_socket, &wsabuf, 1, 0, 0, (WSAOVERLAPPED*)lx_olapped, 0) == SOCKET_ERROR)
                    {
                        int iErrorCode = WSAGetLastError();
                        if (iErrorCode != WSA_IO_PENDING)
                        {
                            cout << "Error occurred at WSASend " << iErrorCode << endl;
                            //������Դ
                            ////////////////////////////////////////////////////////
                            CloseHandle(lx_olapped->hfile);
                            printf("�ļ�����ɹ�\n");
                            delete lx_olapped->m_pBuf;
                            lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                            //����SOCKET
                            pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                            ///////////////////////////////////////////////////////////////
                        }
                    }
                }
            }
            else if(lx_olapped->total_trans_num > (HEADER_SIZE + SERVER_REPORT_SIZE))
            {
                
                //����lxftpͷ�������,�յ������ݾ����ļ�����
                //������Ͷ���ļ�io����
                lx_olapped->m_wsaol.Offset = lx_olapped->transfilesize;
                lx_olapped->m_wsaol.OffsetHigh = (lx_olapped->transfilesize)>>(sizeof(DWORD)*8);


                lx_olapped->m_lNetworkEvents = file_event_write;
                //�����ļ�io�Ĳ���,���ҵľ���,����󵨵���Ϊʵ��д����ֽ������Լ�Ͷ�ݵ�������һ�µ�
                BOOL wret = WriteFile(lx_olapped->hfile, lx_olapped->m_pBuf, dwBytesTransfered, 0, &lx_olapped->m_wsaol);
                if (wret == FALSE)
                {
                    if (ERROR_IO_PENDING != GetLastError())
                    {
                        printf("something wrong...................");
                        exit(0);
                    }
                }
            }

        }
        break;
        case sock_event_disconnect:
        {
            printf(("����SOCKET�ɹ�,����AcceptEx......\n"));
            lx_olapped->m_lNetworkEvents = sock_event_accept;
            lx_olapped->m_pBuf = new char[2 * (sizeof(SOCKADDR_IN) + 16)];
            lx_olapped->m_szBufLen = 2 * (sizeof(SOCKADDR_IN) + 16);
            lx_olapped->filesize = 0;
            lx_olapped->total_trans_num = 0;
            lx_olapped->transfilesize = 0;
            //���ճɹ�,���¶������ӳ�
            pfnAcceptEx(lx_olapped->m_skListen, lx_olapped->m_socket
                , lx_olapped->m_pBuf, 0, sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16
                , 0, (LPOVERLAPPED)lx_olapped);
        }
        break;
        default:
        {
            bLoop = FALSE;
        }
        break;
        }

    }


}