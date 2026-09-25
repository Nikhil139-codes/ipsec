$msiPath = "C:\Users\mansi\AppData\Local\Temp\WinGet\WiresharkFoundation.Wireshark.4.6.8\Wireshark-4.6.8-x64.msi"
$dir = "c:\Users\mansi\OneDrive\Desktop\ip-sec-security-analyzer\backend\bin\wireshark"

$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.OpenDatabase($msiPath, 0)
$view = $db.OpenView("SELECT File, FileName FROM File")
$view.Execute()

$renamed = 0
while ($record = $view.Fetch()) {
    $fileId = $record.StringData(1)
    $fileName = $record.StringData(2)
    if ($fileName -match "\|") {
        $fileName = $fileName.Split("|")[1]
    }
    $oldPath = Join-Path $dir $fileId
    $newPath = Join-Path $dir $fileName
    if (Test-Path $oldPath) {
        Move-Item -Path $oldPath -Destination $newPath -Force
        $renamed++
    }
}
Write-Host "Successfully renamed $renamed files."
