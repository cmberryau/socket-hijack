#include "pch.h"
#include <sstream>

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

static int (WINAPI* TrueRecv)(
    SOCKET s,
    char*  buf,
    int    len,
    int    flags
) = recv;

int WINAPI HijackedRecv(
    SOCKET s,
    char*  buf,
    int    len,
    int    flags
)
{
    std::wostringstream output;
    output << L"HijackedRecv: " << len << " bytes: ";

    for (auto i = 0; i < len; ++i)
        output << buf[i];

    OutputDebugString(output.str().c_str());

    auto ret = TrueRecv(s, buf, len, flags);

    return ret;
}

static int (WSAAPI* TrueSend)(
    SOCKET      s,
    const char* buf,
    int         len,
    int         flags
    ) = send;

int WSAAPI HijackedSend(
    SOCKET      s,
    const char* buf,
    int         len,
    int         flags
)
{
    std::wostringstream output;
    output << L"HijackedSend: " << len << " bytes: " << buf;
    OutputDebugString(output.str().c_str());

    auto ret = TrueSend(s, buf, len, flags);

    return ret;
}

static int (WINAPI* TrueRecvFrom)(
    SOCKET    s,
    char*     buf,
    int       len,
    int       flags,
    sockaddr* from,
    int*      fromlen
) = recvfrom;

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    std::wostringstream output;
    auto error = NO_ERROR;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        output << L"DLL_PROCESS_ATTACH";

        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)TrueRecv, HijackedRecv);
        DetourAttach(&(PVOID&)TrueSend, HijackedSend);

        error = DetourTransactionCommit();
        if (error != NO_ERROR) {
            std::wostringstream output;
            output << L"Error detouring: " << error;
            OutputDebugString(output.str().c_str());
        }
        break;

    case DLL_THREAD_ATTACH:
        output << L"DLL_THREAD_ATTACH";
        break;

    case DLL_THREAD_DETACH:
        output << L"DLL_THREAD_DETACH";
        break;

    case DLL_PROCESS_DETACH:
        output << L"DLL_PROCESS_DETACH";
        break;
    }
    OutputDebugString(output.str().c_str());

    return TRUE;
}
