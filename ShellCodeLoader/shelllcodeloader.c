#include <windows.h>
#include <stdio.h>

typedef void(*FUNCPTR)();

void ErrorExit(LPTSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPSTR lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPSTR)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPSTR)lpMsgBuf) + lstrlen((LPSTR)lpszFunction) + 80) * sizeof(TCHAR)); 

    sprintf_s((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        "%s failed with error %d: %s", 
        lpszFunction, dw, lpMsgBuf); 

    printf((LPSTR)lpDisplayBuf); 

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw); 
}
void usage(char* prog)
{
	printf("Usage: %s <shellcode.bin>\n", prog);
	exit(1);
}
int main(int argc, char **argv)
{
	FUNCPTR func;
	void* buf;
	DWORD len;
	DWORD readLen=0;
	int debug;
	char* shellcodebin;
	char fullpath[MAX_PATH];
	HANDLE hFile;
	DWORD oldProtect;

	if (argc !=2)
	{
		usage(argv[0]);
	}
	else
	{
		shellcodebin = argv[1];
	}
	printf("[+]	Opening: %s\n", shellcodebin);
	GetFullPathName(shellcodebin, sizeof(fullpath), fullpath, NULL);
	hFile = CreateFile(fullpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0 , 0);
	if ((HANDLE)INVALID_HANDLE_VALUE == hFile)
	{
		printf("[!] Could not open file\n");
		ErrorExit("CreateFile");
	}

	len = GetFileSize(hFile, NULL);
	buf = malloc(len + 1);
	if (VirtualProtect(buf, len + 1, PAGE_EXECUTE_READWRITE, &oldProtect) == 0)
	{
		printf("[!] Error creating memory buffer with shellcode data.\n");
		ErrorExit("VirtualProtect");
	}
	if (!ReadFile(hFile, (void*)((char*)buf + 1), len, readLen, NULL))
	{
		printf("[!] Failed to read shellcode file.\n");
		ErrorExit("ReadFile");
	}
	

	// Set the CC byte at the start
	memset(buf, 204, 1);
	func = (FUNCPTR)buf;
	func();
	CloseHandle(hFile);

}

