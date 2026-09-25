$msiPath = "C:\Users\mansi\AppData\Local\Temp\WinGet\WiresharkFoundation.Wireshark.4.6.8\Wireshark-4.6.8-x64.msi"
$baseDir = "c:\Users\mansi\OneDrive\Desktop\ip-sec-security-analyzer\backend\bin\wireshark"

$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.OpenDatabase($msiPath, 0)

# 1. Map Directories
$dirMap = @{}
$parentMap = @{}

$viewDir = $db.OpenView("SELECT Directory, Directory_Parent, DefaultDir FROM Directory")
$viewDir.Execute()
while ($rec = $viewDir.Fetch()) {
    $dId = $rec.StringData(1)
    $dParent = $rec.StringData(2)
    $dName = $rec.StringData(3)
    if ($dName -match ":") {
        $dName = $dName.Split(":")[1]
    }
    if ($dName -match "\|") {
        $dName = $dName.Split("|")[1]
    }
    if ($dName -eq ".") {
        $dName = ""
    }
    $dirMap[$dId] = $dName
    $parentMap[$dId] = $dParent
}

function Get-FullPath($dId) {
    if (-not $dId -or $dId -eq "TARGETDIR" -or $dId -eq "SourceDir") { return "" }
    $name = $dirMap[$dId]
    $parent = $parentMap[$dId]
    if ($parent -and $parent -ne $dId) {
        $parentPath = Get-FullPath $parent
        if ($parentPath -and $name) {
            return Join-Path $parentPath $name
        } elseif ($name) {
            return $name
        } else {
            return $parentPath
        }
    }
    return $name
}

# 2. Map Components to Directories
$compMap = @{}
$viewComp = $db.OpenView("SELECT Component, Directory_ FROM Component")
$viewComp.Execute()
while ($rec = $viewComp.Fetch()) {
    $cId = $rec.StringData(1)
    $dId = $rec.StringData(2)
    $compMap[$cId] = $dId
}

# 3. Map Files and place them in their proper directories
$viewFile = $db.OpenView("SELECT File, Component_, FileName FROM File")
$viewFile.Execute()
$moved = 0
while ($rec = $viewFile.Fetch()) {
    $fId = $rec.StringData(1)
    $cId = $rec.StringData(2)
    $fName = $rec.StringData(3)
    if ($fName -match "\|") {
        $fName = $fName.Split("|")[1]
    }
    
    $dId = $compMap[$cId]
    $relDir = Get-FullPath $dId
    
    # Target path
    $destFolder = if ($relDir) { Join-Path $baseDir $relDir } else { $baseDir }
    if (-not (Test-Path $destFolder)) {
        New-Item -ItemType Directory -Path $destFolder -Force | Out-Null
    }
    $destFile = Join-Path $destFolder $fName
    
    # Check if file is currently at $baseDir\$fName or $baseDir\$fId
    $source1 = Join-Path $baseDir $fName
    $source2 = Join-Path $baseDir $fId
    if ((Test-Path $source1) -and ($source1 -ne $destFile)) {
        Move-Item -Path $source1 -Destination $destFile -Force
        $moved++
    } elseif ((Test-Path $source2) -and ($source2 -ne $destFile)) {
        Move-Item -Path $source2 -Destination $destFile -Force
        $moved++
    }
}


Write-Host "Organized $moved files into proper Wireshark directories."
