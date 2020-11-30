#include "windows.h"
#include "tchar.h"

BOOL InjectionDll(DWORD dwPID, LPCTSTR szDllPath) {
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

    //notepad.exe의 handle 구하기
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {  //제어권 얻기
		_tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}

    //notepad.exe 메모리에 szDllPath 크기만큼 메모리 할당
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE); //dll 경로를 process에 기록
    
    //할당 받은 메모리에 myhack.dll 경로
    WriteProcessMemory(hProcess,pRemoteBuf,(LPVOID)szDllPath,dwBufSize,NULL);
    
    //LoadLibraryW() API 주소 구하기
	hMod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

    //notepad.exe 프로세스에 스레드 실행
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0,NULL);    //원격 스레드 생성을 통한 process에서 로드        
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

int _tmain(int argc, TCHAR* argv[]) {
	if (argc != 3) {
		_tprintf(L"USAGE : %s pid dll_path\n", argv[0]);
		return 1;
	}

	// injection dll
	if (InjectionDll((DWORD)_tstol(argv[0]), argv[2])) _tprintf(L"InjectDll(\"%s\") success!!!\n", argv[2]);
	else _tprintf(L"InjectDll(\"%s\") failed!!!\n", argv[2]);

	return 0;
}
