#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
DWORD FindProcessId(const wchar_t* processname)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD result = 0;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap){
        printf("Invalid Handle!");
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        printf("!!! Failed to gather information on system processes! \n");
        return(0);
    }

    do
    {
        if (0 == _wcsicmp(processname, pe32.szExeFile))
        {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return result;
}
char dll[] = "C:\\DllInjection.dll";
unsigned int len = sizeof(dll) + 1;
int main(int argc, char **argv)
{
    const wchar_t* processname = L"urprocess.exe"; //ur process here
    DWORD pID = FindProcessId(processname);
    if (pID == NULL) {
        printf("Can't find process!");
        exit(-1);
    }
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, pID);
    LPVOID buffer = VirtualAllocEx(processHandle, NULL, len, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processHandle, buffer, dll, len, NULL);
    HANDLE remoteHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), buffer, 0, NULL);
    CloseHandle(processHandle);
    printf("Injected at:0x%X", buffer);
    return 0;
}
