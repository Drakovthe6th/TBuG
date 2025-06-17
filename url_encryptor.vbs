' encrypt_url.vbs
If WScript.Arguments.Count < 1 Then
    WScript.Echo "Usage: cscript encrypt_url.vbs ""URL"""
    WScript.Quit(1)
End If

plainUrl = WScript.Arguments(0)
key = "Shadow"

' XOR Encryption
encrypted = ""
For i = 1 To Len(plainUrl)
    keyIndex = ((i-1) Mod Len(key)) + 1
    keyChar = Asc(Mid(key, keyIndex, 1))
    plainChar = Asc(Mid(plainUrl, i, 1))
    encrypted = encrypted & Chr(plainChar Xor keyChar)
Next

' Convert to hexadecimal
hexResult = ""
For i = 1 To Len(encrypted)
    hexByte = Hex(Asc(Mid(encrypted, i, 1)))
    If Len(hexByte) = 1 Then hexByte = "0" & hexByte
    hexResult = hexResult & hexByte
Next

WScript.Echo "Encrypted URL: " & hexResult