key = "CmdKey"
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1  ' Binary
stream.Open
stream.LoadFromFile "payload.bin"
encryptedBytes = stream.Read
stream.Close

' Convert bytes to string with ISO-8859-1 encoding
Set streamText = CreateObject("ADODB.Stream")
streamText.Type = 1  ' Binary
streamText.Open
streamText.Write encryptedBytes
streamText.Position = 0
streamText.Type = 2  ' Text
streamText.Charset = "iso-8859-1"
encryptedText = streamText.ReadText
streamText.Close

' XOR Decryption
decrypted = ""
For i = 1 To Len(encryptedText)
    keyIndex = ((i-1) Mod Len(key)) + 1
    keyChar = Asc(Mid(key, keyIndex, 1))
    cipherChar = Asc(Mid(encryptedText, i, 1))
    decrypted = decrypted & Chr(cipherChar Xor keyChar)
Next

' Save decrypted content
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.CreateTextFile("decrypted.cmd", True)
file.Write decrypted
file.Close

WScript.Echo "Decrypted payload saved as decrypted.cmd"
WScript.Echo "Verification: Compare l3.cmd and decrypted.cmd"