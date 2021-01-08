#include <stdio.h>
#include <windows.h>

//호출할 API와 인젝션할 데이터 저장 공간
typedef struct _THREAD_PARAM
{
	FARPROC pFunc[2];
	char szBuf[4][128];
} THREAD_PARAM, *PTHREAD_PARAM;

//LoadLibraryA 함수의 포인터
typedef HMODULE(WINAPI *PFLOADLIBRARYA)
(
	LPCSTR lpLibFileName
);

//GetProcAddress 함수의 포인터
typedef FARPROC(WINAPI *PFGETPROCADDRESS)
(
	HMODULE hModule,
	LPCSTR lpProcName
);

//MessageBoxA 함수의 포인터
typedef int(WINAPI *PFMESSAGEBOXA)
(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCation,
	UINT uType
);

//상대 프로세스에 삽입할코드
DWORD WINAPI ThreadProc(LPVOID lParam)
{
	PTHREAD_PARAM pParam = (PTHREAD_PARAM)lParam;
	HMODULE hMod = NULL;
	FARPROC pFunc = NULL;

	//LoadLibrary 호출
	hMod = ((PFLOADLIBRARYA)pParam->pFunc[0])(pParam->szBuf[0]);

	//GetProcAddress 호출
	pFunc = (FARPROC)((PFGETPROCADDRESS)pParam->pFunc[1])(hMod, pParam->szBuf[1]);

	//MessageBoxA 호출
	((PFMESSAGEBOXA)pFunc)(NULL, pParam->szBuf[2], pParam->szBuf[3], MB_OK);

	return 0;
}

//ThreadProc 함수 부분을 프로세스에 삽입
BOOL InjectCode(DWORD dwPID)
{
	HMODULE hMod = NULL;
	THREAD_PARAM param = { 0, };
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pRemoteBuf[2] = { 0, };
	DWORD dwSize = 0;

	//인젝션 할 데이터
	hMod = GetModuleHandleA("kernel32.dll");

	//set THREAD_PARAM
	param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
	param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");
	printf("%x", param.pFunc);
	strcpy(param.szBuf[0], "user32.dll");
	strcpy(param.szBuf[1], "MessageBoxA");
	strcpy(param.szBuf[2], "www.reversecore.com");
	strcpy(param.szBuf[3], "ReverseCore");

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

	dwSize = sizeof(THREAD_PARAM); //저장할 데이터 크기 읽어오기
	pRemoteBuf[0] = VirtualAllocEx(hProcess, //읽어온만큼의 영역 할당
		NULL,
		dwSize,
		MEM_COMMIT,
		PAGE_READWRITE);

	WriteProcessMemory(hProcess,		//할당한 공간에 값 삽입
		pRemoteBuf[0],
		(LPVOID)&param,
		dwSize,
		NULL);


	dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;	//사이즈 측정
	pRemoteBuf[1] = VirtualAllocEx(hProcess,	//프로세스 메모리 내 할당
		NULL,
		dwSize, MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess,		//코드 삽입
		pRemoteBuf[1],
		(LPVOID)ThreadProc,
		dwSize,
		NULL);

	hThread = CreateRemoteThread(hProcess,	//프로세스 안에서 코드 실행
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pRemoteBuf[1],
		pRemoteBuf[0],
		0,
		NULL);

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

//사용자에게 PID 입력받아 코드인젝션 실행
int main(int argc, char *argv[]) {
	DWORD dwPID = 0;

	int getPID = 0;

	printf("PID :");
	scanf("%d", &getPID);
	dwPID = (DWORD)getPID;
	InjectCode(dwPID);

	return 0;

}