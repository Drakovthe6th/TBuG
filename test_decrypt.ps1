$file1 = Get-Content "l3.cmd" -Encoding Byte
$file2 = Get-Content "decrypted.cmd" -Encoding Byte
$hash1 = [System.BitConverter]::ToString($file1)
$hash2 = [System.BitConverter]::ToString($file2)

if ($hash1 -eq $hash2) {
    "Files are identical!"
} else {
    "Files differ! Check the encryption process."
}