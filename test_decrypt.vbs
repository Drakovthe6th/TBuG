key = "CmdKey"
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1
stream.Open
stream.LoadFromFile "payload.bin"
bytes = stream.Read
stream.Close

stream.Type = 2
stream.Charset = "iso-8859-1"
stream.Open
stream.WriteText bytes
stream.Position = 0
encrypted = stream.ReadText
stream.Close

decrypted = ""
For i = 1 To Len(encrypted)
    keyIndex = ((i-1) Mod Len(key)) + 1
    keyChar = Asc(Mid(key, keyIndex, 1))
    cipherChar = Asc(Mid(encrypted, i, 1))
    decrypted = decrypted & Chr(cipherChar Xor keyChar)
Next

Set fso = CreateObject("Scripting.FileSystemObject")
fso.CreateTextFile("decrypted.cmd", True).Write decrypted
WScript.Echo "Decrypted payload saved as decrypted.cmd"