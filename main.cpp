#include <Winsock2.h>
#include "LX_IOSCP.h"
#include <iostream> 
#include <list>
#include <thread>
#include <vector>
#include <stdio.h>
using namespace std;

#define BUFFER_SIZE             64*1024
#define HEADER_SIZE             136 //128个字节的文件名长度 + 8个字节所表示的文件大小
#define SERVER_REPORT_SIZE      8//服务器回应的文件大小数据包的大小 即sizeof(long long)

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
    WSAOVERLAPPED m_wsaol;         //文件io与socket io共用
    SOCKET        m_skListen;      //监听套接字句柄
    long          m_lNetworkEvents;//投递的操作类型(sock_event_read/FD_WRITE等)
    SOCKET        m_socket;        //投递操作的SOCKET句柄
    void*         m_pBuf;          //投递操作时的缓冲
    size_t        m_szBufLen;      //缓冲长度
    sockaddr_in   localaddr;       //本地地址
    sockaddr_in   remoteaddr;      //对端地址
    long long     total_trans_num; //传输的字节数(recv和send的总和)
    char          filename[128];   //文件名
    long long     filesize;        //文件长度
    /////////愚蠢的设计//////////////
    HANDLE        hfile;           //文件句柄
    long long     localfilesize;    //本地文件大小
    FILE * fp;
    long long     transfilesize;   //已经传输(写入)的文件大小
};


int main()
{
    init_network();
    //加载winsock高性能函数
    LoadALLWinsockFun_TCP();

    int max_num_of_connections = 1000;
    int index = 0;
    LX_IOSCP iocp;
    iocp.Create();
    SOCKET ListenSocket, AcceptSocket;
    SOCKET* pskAcceptArray = NULL;
    LX_OVERLAPPED** pMyOLArray = NULL;
    vector<thread*> iocp_threads;

    //预先设置socket池的空间
    pskAcceptArray = new SOCKET[max_num_of_connections];
    pMyOLArray = new LX_OVERLAPPED*[max_num_of_connections];//注意这是个指针数组 实际的空间开辟放在AcceptEx循环中进行

    //创建CPU数量的线程
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    for (int i = 0; i < si.dwNumberOfProcessors; i++)
    {
        iocp_threads.push_back(new thread(thread_func, &iocp));
    }

    ListenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);

    //将SOCKET句柄与完成端口对象绑定,在我的这种设计模式里,完成键完全没有用到~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
        //将SOCKET句柄与完成端口对象绑定
        iocp.AssociateSocket(AcceptSocket, 0);

        LX_OVERLAPPED *pOLAcceptEx = NULL;
        pOLAcceptEx = new LX_OVERLAPPED;
        ZeroMemory(pOLAcceptEx, sizeof(LX_OVERLAPPED));
        pOLAcceptEx->m_skListen = ListenSocket;
        pOLAcceptEx->m_socket = AcceptSocket;
        pOLAcceptEx->m_lNetworkEvents = sock_event_accept;
        pOLAcceptEx->m_pBuf = new char[2 * (sizeof(SOCKADDR_IN) + 16)]; //这里new出来的buffer只是用来存地址用的,在accept之后会被delete掉
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

    //接下来回收资源
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
    ULONG_PTR       Key = NULL;//在我的设计里,这玩意没用
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
            cout << "IOCPThread: GetQueuedCompletionStatus 调用失败,错误码: " << GetLastError() << endl;
            ////回收资源
            //////////////////////////////////////////////////////////
            ////为了避免重复释放资源
            //if (lx_olapped->transfilesize == (lx_olapped->filesize + HEADER_SIZE + SERVER_REPORT_SIZE))
            //{
            //}
            //CloseHandle(lx_olapped->hfile);
            //printf("文件保存成功\n");
            //delete lx_olapped->m_pBuf;
            //lx_olapped->m_lNetworkEvents = sock_event_disconnect;
            ////回收SOCKET
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
                //意味着连接发生错误,这时候就可以回收套接字了
                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                printf("收到0字节\n");
                //回收资源
                ////////////////////////////////////////////////////////
                CloseHandle(lx_olapped->hfile);
                printf("文件保存成功\n");
                delete lx_olapped->m_pBuf;
                lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                //回收SOCKET
                pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                ///////////////////////////////////////////////////////////////



            }
            lx_olapped->total_trans_num += dwBytesTransfered;

            //这种情况意味着服务器的8字节回应包没法完,这必然是极少发生的情况
            if (lx_olapped->total_trans_num < (HEADER_SIZE + SERVER_REPORT_SIZE))
            {
                //将当前文件大小发送给客户端
                WSABUF wsabuf{ sizeof(long long)- (lx_olapped->total_trans_num - HEADER_SIZE),
                    (char*)(&lx_olapped->localfilesize)+ (lx_olapped->total_trans_num - HEADER_SIZE) };
                lx_olapped->m_lNetworkEvents = sock_event_write;
                if (WSASend(lx_olapped->m_socket, &wsabuf, 1, 0, 0, (WSAOVERLAPPED*)lx_olapped, 0) == SOCKET_ERROR)
                {
                    int iErrorCode = WSAGetLastError();
                    if (iErrorCode != WSA_IO_PENDING)
                    {
                        cout << "Error occurred at WSASend " << iErrorCode << endl;
                        //回收资源
                        ////////////////////////////////////////////////////////
                        CloseHandle(lx_olapped->hfile);
                        printf("文件保存成功\n");
                        delete lx_olapped->m_pBuf;
                        lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                        //回收SOCKET
                        pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                        ///////////////////////////////////////////////////////////////
                    }
                }
            }//此时意味着8字节回应包发送完毕
            else if(lx_olapped->total_trans_num == (HEADER_SIZE + SERVER_REPORT_SIZE))
            {
                if (lx_olapped->filesize <= lx_olapped->localfilesize)
                {
                    ///////////////////////////////////////////////////////////////////////////////////////
                    //直接断了
                    CloseHandle(lx_olapped->hfile);
                    printf("---------------存在相同文件,断开连接-----------------\n");
                    delete lx_olapped->m_pBuf;
                    lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                    //回收SOCKET
                    pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                }
                else//本地文件大小小于客户端的文件大小,那么这意味着开启断点续传模式,客户端将从服务端指定的文件位置发送文件
                {
                    if (lx_olapped->localfilesize != 0)
                    {
                        printf("********************开启断点续传模式\n");
                    }
                    lx_olapped->transfilesize = lx_olapped->localfilesize;

                    WSABUF wsabuf = { lx_olapped->m_szBufLen ,(char*)lx_olapped->m_pBuf };
                    lx_olapped->m_lNetworkEvents = sock_event_read;
                    DWORD Flags = 0;//这个变量用不上,但是必须有
                    if (WSARecv(lx_olapped->m_socket, &wsabuf, 1, 0
                        , &Flags, (WSAOVERLAPPED*)lx_olapped, NULL) == SOCKET_ERROR)
                    {
                        int iErrorCode = WSAGetLastError();
                        if (iErrorCode != WSA_IO_PENDING)
                        {
                            cout << "Error occurred at WSARecv " << iErrorCode << endl;
                            //回收资源
                            ////////////////////////////////////////////////////////
                            CloseHandle(lx_olapped->hfile);
                            printf("文件保存成功\n");
                            delete lx_olapped->m_pBuf;
                            lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                            //回收SOCKET
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
            printf("线程[0x%x]完成操作(AcceptEx),缓冲(0x%08x)长度(%ubytes)\n",
                GetCurrentThreadId(), lx_olapped->m_pBuf, lx_olapped->m_szBufLen);

            SOCKADDR_IN* psaLocal = NULL;
            int         iLocalLen = sizeof(SOCKADDR_IN);
            SOCKADDR_IN* psaRemote = NULL;
            int         iRemoteLen = sizeof(SOCKADDR_IN);

            pfnGetAcceptExSockaddrs(lx_olapped->m_pBuf, 0
                , sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16
                , (SOCKADDR**)&psaLocal, &iLocalLen, (SOCKADDR**)&psaRemote, &iRemoteLen);

            //将获取的地址保存下来
            lx_olapped->localaddr = *psaLocal;
            lx_olapped->remoteaddr = *psaRemote;


            cout << "客户端[" << inet_ntoa(lx_olapped->remoteaddr.sin_addr) << ":" << ntohs(lx_olapped->remoteaddr.sin_port)
                << "]连接进入,本地通讯地址[" << inet_ntoa(lx_olapped->localaddr.sin_addr) << ":" << ntohs(lx_olapped->localaddr.sin_port)
                << "]" << endl;

            delete []lx_olapped->m_pBuf;


            //接下来服务器就可以接收数据了
            lx_olapped->m_pBuf = new char[BUFFER_SIZE];
            lx_olapped->m_szBufLen = BUFFER_SIZE;
            WSABUF wsabuf = { HEADER_SIZE ,(char*)lx_olapped->m_pBuf};
            lx_olapped->m_lNetworkEvents = sock_event_read;
            DWORD Flags = 0;//这个变量用不上,但是必须有
            if (WSARecv(lx_olapped->m_socket, &wsabuf, 1, 0
                , &Flags, (WSAOVERLAPPED*)lx_olapped, NULL) == SOCKET_ERROR)
            {
                int iErrorCode = WSAGetLastError();
                if (iErrorCode != WSA_IO_PENDING)
                {
                    cout << "Error occurred at WSARecv " << iErrorCode << endl;
                    //回收资源
                    ////////////////////////////////////////////////////////
                    CloseHandle(lx_olapped->hfile);
                    printf("文件保存成功\n");
                    delete lx_olapped->m_pBuf;
                    lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                    //回收SOCKET
                    pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                    ///////////////////////////////////////////////////////////////



                }
            }
        }
        break;
        case file_event_write:
        {
            //printf("成功写入 %d 个字节\n",dwBytesTransfered);
            memset(&lx_olapped->m_wsaol, 0, sizeof(WSAOVERLAPPED));

            lx_olapped->transfilesize += dwBytesTransfered;
            if (lx_olapped->filesize > lx_olapped->transfilesize)
            {
                WSABUF wsabuf = { lx_olapped->m_szBufLen ,(char*)lx_olapped->m_pBuf };
                lx_olapped->m_lNetworkEvents = sock_event_read;
                DWORD Flags = 0;//这个变量用不上,但是必须有
                if (WSARecv(lx_olapped->m_socket, &wsabuf, 1, 0
                    , &Flags, (WSAOVERLAPPED*)lx_olapped, NULL) == SOCKET_ERROR)
                {
                    int iErrorCode = WSAGetLastError();
                    if (iErrorCode != WSA_IO_PENDING)
                    {
                        cout << "Error occurred at WSARecv " << iErrorCode << endl;
                        //回收资源
                        ////////////////////////////////////////////////////////
                        CloseHandle(lx_olapped->hfile);
                        printf("文件保存成功\n");
                        delete lx_olapped->m_pBuf;
                        lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                        //回收SOCKET
                        pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                        ///////////////////////////////////////////////////////////////
                    }
                }
            }
            else
            {
                //回收资源
                ////////////////////////////////////////////////////////
                CloseHandle(lx_olapped->hfile);
                printf("文件保存成功\n");
                delete lx_olapped->m_pBuf;
                lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                //回收SOCKET
                pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                ///////////////////////////////////////////////////////////////
            }
        }

          
        break;
        case sock_event_read:
        {
            if (dwBytesTransfered == 0)
            {
                //意味着连接发生错误,这时候就可以回收套接字了
                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                printf("收到0字节\n");
                //回收资源
                ////////////////////////////////////////////////////////
                CloseHandle(lx_olapped->hfile);
                printf("文件保存成功\n");
                delete lx_olapped->m_pBuf;
                lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                //回收SOCKET
                pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                ///////////////////////////////////////////////////////////////
            }


            lx_olapped->total_trans_num += dwBytesTransfered;


            if (lx_olapped->total_trans_num < HEADER_SIZE)
            {
                WSABUF wsabuf = { HEADER_SIZE - lx_olapped->total_trans_num ,(char*)lx_olapped->m_pBuf+ lx_olapped->total_trans_num };
                lx_olapped->m_lNetworkEvents = sock_event_read;
                DWORD Flags = 0;//这个变量用不上,但是必须有
                if (WSARecv(lx_olapped->m_socket, &wsabuf, 1, 0
                    , &Flags, (WSAOVERLAPPED*)lx_olapped, NULL) == SOCKET_ERROR)
                {
                    int iErrorCode = WSAGetLastError();
                    if (iErrorCode != WSA_IO_PENDING)
                    {
                        cout << "Error occurred at WSARecv " << iErrorCode << endl;
                        //回收资源
                        ////////////////////////////////////////////////////////
                        CloseHandle(lx_olapped->hfile);
                        printf("文件保存成功\n");
                        delete lx_olapped->m_pBuf;
                        lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                        //回收SOCKET
                        pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                        ///////////////////////////////////////////////////////////////
                    }
                }

            }//此时意味着可以获取文件名长度和文件长度字段了
            else if(lx_olapped->total_trans_num == HEADER_SIZE)
            {
                memcpy(lx_olapped->filename, lx_olapped->m_pBuf, 128);
                lx_olapped->filesize = *((long long*)((char*)lx_olapped->m_pBuf+128));
                printf("解析头字段成功\n");

                //创建文件
                //lx_olapped->fp = fopen(lx_olapped->filename, "wb+");

                //创建目标文件(在windows下,以独占方式打开文件)
                lx_olapped->hfile = CreateFileA(lx_olapped->filename, GENERIC_WRITE,0, NULL, OPEN_ALWAYS,
                    FILE_FLAG_OVERLAPPED, NULL);
                if (lx_olapped->hfile == INVALID_HANDLE_VALUE)
                {
                    printf("create file failed\n");
                    //回收资源
                    ////////////////////////////////////////////////////////
                    CloseHandle(lx_olapped->hfile);
                    printf("文件保存成功\n");
                    delete lx_olapped->m_pBuf;
                    lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                    //回收SOCKET
                    pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                    ///////////////////////////////////////////////////////////////
                }
                else//此时打开文件成功
                {
                    //将文件句柄添加到iocp的设备表中
                    iocp->AssociateDevice(lx_olapped->hfile, 0);
                    //获取文件大小
                    GetFileSizeEx(lx_olapped->hfile, (LARGE_INTEGER*)(&lx_olapped->localfilesize));
                    //接下来将当前文件大小发送给客户端
                    WSABUF wsabuf{ sizeof(long long),(char*)(&lx_olapped->localfilesize) };
                    lx_olapped->m_lNetworkEvents = sock_event_write;
                    if (WSASend(lx_olapped->m_socket, &wsabuf, 1, 0, 0, (WSAOVERLAPPED*)lx_olapped, 0) == SOCKET_ERROR)
                    {
                        int iErrorCode = WSAGetLastError();
                        if (iErrorCode != WSA_IO_PENDING)
                        {
                            cout << "Error occurred at WSASend " << iErrorCode << endl;
                            //回收资源
                            ////////////////////////////////////////////////////////
                            CloseHandle(lx_olapped->hfile);
                            printf("文件保存成功\n");
                            delete lx_olapped->m_pBuf;
                            lx_olapped->m_lNetworkEvents = sock_event_disconnect;
                            //回收SOCKET
                            pfnDisconnectEx(lx_olapped->m_socket, (LPOVERLAPPED)lx_olapped, TF_REUSE_SOCKET, 0);
                            ///////////////////////////////////////////////////////////////
                        }
                    }
                }
            }
            else if(lx_olapped->total_trans_num > (HEADER_SIZE + SERVER_REPORT_SIZE))
            {
                
                //现在lxftp头解析完毕,收到的数据就是文件数据
                //接下来投递文件io请求
                lx_olapped->m_wsaol.Offset = lx_olapped->transfilesize;
                lx_olapped->m_wsaol.OffsetHigh = (lx_olapped->transfilesize)>>(sizeof(DWORD)*8);


                lx_olapped->m_lNetworkEvents = file_event_write;
                //关于文件io的部分,以我的经验,这里大胆的认为实际写入的字节数和自己投递的申请是一致的
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
            printf(("回收SOCKET成功,重新AcceptEx......\n"));
            lx_olapped->m_lNetworkEvents = sock_event_accept;
            lx_olapped->m_pBuf = new char[2 * (sizeof(SOCKADDR_IN) + 16)];
            lx_olapped->m_szBufLen = 2 * (sizeof(SOCKADDR_IN) + 16);
            lx_olapped->filesize = 0;
            lx_olapped->total_trans_num = 0;
            lx_olapped->transfilesize = 0;
            //回收成功,重新丢入连接池
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