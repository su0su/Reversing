#include "windows.h"
#include "tchar.h"
#include "TlHelp32.h"

#define DEF_PROC_NAME (L"notepad.exe")
#define DEF_DLL_NAME (L"myhack.dll")

//notepad.exe를 입력받아 notepad.exe의 ProcessID를 얻어냄
DWORD FindProcessID(LPCTSTR szProcessName) {
    DWORD dwPID = 0xFFFFFFFF;   //dwPID -1로 초기화
    HANDLE hSnapShot = INVALID_HANDLE_VALUE; //핸들값. 빈공간
    PROCESSENTRY32 pe; //프로세스 구조체

    pe.dwSize = sizeof(PROCESSENTRY32);
    //프로세스에 로딩된 DLL 정보 구하기
    //snapshot시, hSnapShot에 저장
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL); 
    

    //프로세스 찾기
    Process32First(hSnapShot, &pe);
    do
    {
        if(!_tcsicmp(szProcessName, (LPCTSTR)pe.szExeFile)) //pe.szExeFile 속 프로세스와 szProcessName 비교
        {
            dwPID=pe.th32ProcessID;
            break;
        }
    }
    while(Process32Next(hSnapShot,&pe));
    CloseHandle(hSnapShot); //snapshot close
    return dwPID;
}

//권한 활성화
BOOL SetPrivilege(LPCTSTR lpszPrivilege,BOOL bEnablePrivilege){
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    //현재 process의 handle에 관련된 tocken 가져옴
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        _tprintf(L"OpenProcessToken error: %u\n",GetLastError());
        return FALSE;
    }

    //명시된 권한을 표현할 luid 검색
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))       
    {
        _tprintf(L"LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else tp.Privileges[0].Attributes = 0;

    //권한 조정
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        _tprintf(L"AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        _tprintf(L"The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName)
{
    BOOL bMore = FALSE, bFound = FALSE;
    HANDLE hSnapshot, hProcess, hThread;
    HMODULE hModule = NULL;
    MODULEENTRY32 me = { sizeof(me) };
    LPTHREAD_START_ROUTINE pThreadProc;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID); //32bit process 정보 가져옴

    bMore = Module32First(hSnapshot, &me);
    for (; bMore; bMore = Module32Next(hSnapshot, &me))
    {
        if (!_tcsicmp((LPCTSTR)me.szModule, szDllName) || !_tcsicmp((LPCTSTR)me.szExePath, szDllName))
        {
            bFound = TRUE;
            break;
        }
    }

    if (!bFound)
    {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        _tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
        return FALSE;
    }

    hModule = GetModuleHandle(L"kernel32.dll");
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
    hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0 , NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hSnapshot);

    return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
    DWORD dwPID = 0xFFFFFFFF;

    dwPID = FindProcessID(DEF_PROC_NAME);
    if (dwPID == 0xFFFFFFFF)
    {
        _tprintf(L"There is no <%s> process!\n", DEF_PROC_NAME);
        return 1;
    }

    _tprintf(L"PID of \"%s\" is %d\n", DEF_PROC_NAME, dwPID);

    if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
        return 1;

    if (EjectDll(dwPID, DEF_DLL_NAME)) _tprintf(L"EjectDll(%d, \"%s\") success!!!\n", dwPID, DEF_DLL_NAME);
    else _tprintf(L"EjectDll(%d, \"%s\") failed!!!\n", dwPID, DEF_DLL_NAME);

    return 0;
}