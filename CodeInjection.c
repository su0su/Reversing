#include <stdio.h>
#include <windows.h>

//ȣ���� API�� �������� ������ ���� ����
typedef struct _THREAD_PARAM
{
	FARPROC pFunc[2];
	char szBuf[4][128];
} THREAD_PARAM, *PTHREAD_PARAM;

//LoadLibraryA �Լ��� ������
typedef HMODULE(WINAPI *PFLOADLIBRARYA)
(
	LPCSTR lpLibFileName
);

//GetProcAddress �Լ��� ������
typedef FARPROC(WINAPI *PFGETPROCADDRESS)
(
	HMODULE hModule,
	LPCSTR lpProcName
);

//MessageBoxA �Լ��� ������
typedef int(WINAPI *PFMESSAGEBOXA)
(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCation,
	UINT uType
);

//��� ���μ����� �������ڵ�
DWORD WINAPI ThreadProc(LPVOID lParam)
{
	PTHREAD_PARAM pParam = (PTHREAD_PARAM)lParam;
	HMODULE hMod = NULL;
	FARPROC pFunc = NULL;

	//LoadLibrary ȣ��
	hMod = ((PFLOADLIBRARYA)pParam->pFunc[0])(pParam->szBuf[0]);

	//GetProcAddress ȣ��
	pFunc = (FARPROC)((PFGETPROCADDRESS)pParam->pFunc[1])(hMod, pParam->szBuf[1]);

	//MessageBoxA ȣ��
	((PFMESSAGEBOXA)pFunc)(NULL, pParam->szBuf[2], pParam->szBuf[3], MB_OK);

	return 0;
}

//ThreadProc �Լ� �κ��� ���μ����� ����
BOOL InjectCode(DWORD dwPID)
{
	HMODULE hMod = NULL;
	THREAD_PARAM param = { 0, };
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pRemoteBuf[2] = { 0, };
	DWORD dwSize = 0;

	//������ �� ������
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

	dwSize = sizeof(THREAD_PARAM); //������ ������ ũ�� �о����
	pRemoteBuf[0] = VirtualAllocEx(hProcess, //�о�¸�ŭ�� ���� �Ҵ�
		NULL,
		dwSize,
		MEM_COMMIT,
		PAGE_READWRITE);

	WriteProcessMemory(hProcess,		//�Ҵ��� ������ �� ����
		pRemoteBuf[0],
		(LPVOID)&param,
		dwSize,
		NULL);


	dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;	//������ ����
	pRemoteBuf[1] = VirtualAllocEx(hProcess,	//���μ��� �޸� �� �Ҵ�
		NULL,
		dwSize, MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess,		//�ڵ� ����
		pRemoteBuf[1],
		(LPVOID)ThreadProc,
		dwSize,
		NULL);

	hThread = CreateRemoteThread(hProcess,	//���μ��� �ȿ��� �ڵ� ����
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

//����ڿ��� PID �Է¹޾� �ڵ������� ����
int main(int argc, char *argv[]) {
	DWORD dwPID = 0;

	int getPID = 0;

	printf("PID :");
	scanf("%d", &getPID);
	dwPID = (DWORD)getPID;
	InjectCode(dwPID);

	return 0;

}