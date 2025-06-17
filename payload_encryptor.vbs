' payload_encryptor.vbs
If WScript.Arguments.Count < 2 Then
    WScript.Echo "Usage: cscript payload_encryptor.vbs INPUT_FILE OUTPUT_FILE"
    WScript.Quit(1)
End If

inputFile = WScript.Arguments(0)
outputFile = WScript.Arguments(1)
key = "CmdKey"

' Read file as text with binary preservation
Set fso = CreateObject("Scripting.FileSystemObject")
Set stream = CreateObject("ADODB.Stream")

stream.Type = 2  ' Text
stream.Charset = "iso-8859-1"
stream.Open
stream.LoadFromFile inputFile
plaintext = stream.ReadText
stream.Close

' XOR Encryption
encrypted = ""
For i = 1 To Len(plaintext)
    keyIndex = ((i-1) Mod Len(key)) + 1
    keyChar = Asc(Mid(key, keyIndex, 1))
    plainChar = Asc(Mid(plaintext, i, 1))
    encrypted = encrypted & Chr(plainChar Xor keyChar)
Next

' Write encrypted output
Set streamOut = CreateObject("ADODB.Stream")
streamOut.Type = 2  ' Text
streamOut.Charset = "iso-8859-1"
streamOut.Open
streamOut.WriteText encrypted
streamOut.Position = 0
streamOut.Type = 1  ' Binary
streamOut.SaveToFile outputFile, 2
streamOut.Close

WScript.Echo "Payload encrypted successfully: " & outputFile
WScript.Echo "Key used: " & key