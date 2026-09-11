Clear-Host

# ============================================================
# Banner
# ============================================================
$banner = @"
    _    ____    ____  _____ ____ ___  ____  ____ ___ _   _  ____
   / \  / ___|  |  _ \| ____/ ___/ _ \|  _ \|  _ \_ _| \ | |/ ___|
  / _ \| |      | |_) |  _|| |  | | | | |_) | | | | ||  \| | |  _
 / ___ \ |___   |  _ <| |__| |__| |_| |  _ <| |_| | || |\  | |_| |
/_/   \_\____|  |_| \_\_____\____\___/|_| \_\____/___|_| \_|\____|

              R  U  L  E  S
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host ""
Write-Host "  System Findings Collector" -ForegroundColor DarkGray
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

# ============================================================
# Elevation check - several artifacts (Prefetch, Event Logs,
# full Program Files scan) need admin rights to read completely
# ============================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "  WARNING: Not running as Administrator." -ForegroundColor Yellow
    Write-Host "  Prefetch, Event Logs, and some other artifacts may come back empty or partial." -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================
# Collector script block (runs in background job)
# ============================================================
$collector = {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $stamp   = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $temp    = Join-Path $env:TEMP "findings_$stamp"
    New-Item -ItemType Directory -Path $temp -Force | Out-Null

    function Save($name, $scriptblock) {
        $path = Join-Path $temp "$name.txt"
        try {
            (& $scriptblock) | Out-String -Width 300 | Set-Content -Path $path -Encoding UTF8
        } catch {
            "ERROR: $_" | Set-Content -Path $path -Encoding UTF8
        }
    }

    # 1. Process list with parentage + file size
    Save "01_process_parentage" {
        # Build PID -> Name map once instead of calling Get-Process per row
        $parentMap = @{}
        Get-Process | ForEach-Object { $parentMap[$_.Id] = $_.Name }

        Get-CimInstance Win32_Process | Select-Object Name, ProcessId,
            @{n='ParentName';e={
                if ($parentMap.ContainsKey([int]$_.ParentProcessId)) { $parentMap[[int]$_.ParentProcessId] } else { $null }
            }},
            @{n='SizeMB';e={
                if ($_.ExecutablePath -and (Test-Path $_.ExecutablePath)) {
                    [math]::Round((Get-Item $_.ExecutablePath -ErrorAction SilentlyContinue).Length / 1MB, 2)
                } else { $null }
            }},
            CommandLine
    }

    # 2. Virtualization / systeminfo
    Save "02_systeminfo_virtualization" {
        systeminfo | findstr /i "hyper os version page virtualization"
    }

    # 3. Scheduled tasks
    Save "03_scheduled_tasks" { Get-ScheduledTask }

    # 4. Tasklist
    Save "04_tasklist" { tasklist }

    # 5. Process start times
    Save "05_process_starttimes" {
        Get-Process | Select-Object Name, StartTime -ErrorAction SilentlyContinue
    }

    # 6. Running services
    Save "06_running_services" {
        Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, Status
    }

    # 7. Unsigned exes in Program Files (with size + hash)
    $pfPaths = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    $pfFiles = Get-ChildItem -Path $pfPaths -Recurse -Include *.exe -ErrorAction SilentlyContinue

    # Size map built up front so we don't hit disk again per file later
    $sizeMap = @{}
    foreach ($f in $pfFiles) { $sizeMap[$f.FullName] = $f.Length }

    $unsigned = $pfFiles | Get-AuthenticodeSignature |
        Where-Object { $_.Status -ne 'Valid' } |
        Select-Object Path, Status,
            @{n='SizeMB';e={ if ($sizeMap.ContainsKey($_.Path)) { [math]::Round($sizeMap[$_.Path] / 1MB, 2) } else { $null } }}

    Save "07_unsigned_program_files_exes" { $unsigned }

    Save "07b_unsigned_exe_hashes" {
        foreach ($i in $unsigned) {
            "-- $($i.Path) (Size: $($i.SizeMB) MB) --"
            try { certutil -hashfile "$($i.Path)" SHA256 } catch { "Could not hash: $_" }
            ""
        }
        "NOTE: VirusTotal check is manual — upload each flagged file at virustotal.com"
        "and record the detection ratio (e.g. 3/71) and detection names here."
    }

    # 8. Root certificates
    Save "08_root_certificates" {
        Get-ChildItem Cert:\LocalMachine\Root | Select-Object Subject, Thumbprint, NotBefore | Sort-Object NotBefore -Descending
    }

    # 9. collect_report.ps1 notice
    Save "09_collect_report_notice" {
        "This step calls an external script (.\collect_report.ps1) whose contents were not provided,"
        "so it has not been bundled or run here. Read any unknown script before running it."
    }

    # 10. Prefetch files (summary, sizes included)
    Save "10_prefetch_files" {
        Get-ChildItem "$env:WINDIR\Prefetch" -Filter *.pf -ErrorAction SilentlyContinue |
            Select-Object Name,
                @{n='SizeKB';e={[math]::Round($_.Length / 1KB, 2)}},
                CreationTime, LastWriteTime, LastAccessTime |
            Sort-Object LastWriteTime -Descending
    }

    # 11. Recent items (shell:recent), sizes included
    Save "11_recent_items" {
        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        Get-ChildItem $recentPath -ErrorAction SilentlyContinue |
            Select-Object Name,
                @{n='SizeKB';e={[math]::Round($_.Length / 1KB, 2)}},
                CreationTime, LastWriteTime |
            Sort-Object LastWriteTime -Descending
    }

    # 12. Recent items resolved targets (lnk size + target size)
    Save "12_recent_items_targets" {
        $sh = New-Object -ComObject WScript.Shell
        Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Filter *.lnk -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    $lnk = $sh.CreateShortcut($_.FullName)
                    $targetSizeKB = $null
                    if ($lnk.TargetPath -and (Test-Path $lnk.TargetPath)) {
                        $targetSizeKB = [math]::Round((Get-Item $lnk.TargetPath -ErrorAction SilentlyContinue).Length / 1KB, 2)
                    }
                    [PSCustomObject]@{
                        Name          = $_.Name
                        Target        = $lnk.TargetPath
                        Arguments     = $lnk.Arguments
                        LnkSizeKB     = [math]::Round($_.Length / 1KB, 2)
                        TargetSizeKB  = $targetSizeKB
                        LastWriteTime = $_.LastWriteTime
                    }
                } catch {
                    [PSCustomObject]@{
                        Name = $_.Name; Target = "ERROR"; Arguments = ""
                        LnkSizeKB = $null; TargetSizeKB = $null; LastWriteTime = $_.LastWriteTime
                    }
                }
            }
    }

    # ------------------------------------------------------------
    # Raw artifact copies -> logs\Prefetch, logs\Recent, logs\EventLogs
    # ------------------------------------------------------------
    $logsRoot = Join-Path $temp "logs"
    New-Item -ItemType Directory -Path $logsRoot -Force | Out-Null

    function Copy-Artifact($label, $source, $destSubfolder) {
        $dest = Join-Path $logsRoot $destSubfolder
        try {
            if (Test-Path $source) {
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                Copy-Item -Path (Join-Path $source '*') -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
                $copied  = Get-ChildItem $dest -Recurse -File -ErrorAction SilentlyContinue
                $count   = $copied.Count
                $sizeMB  = [math]::Round((($copied | Measure-Object Length -Sum).Sum) / 1MB, 2)
                "OK   [$label] $count files, $sizeMB MB copied from '$source' -> logs\$destSubfolder"
            } else {
                "SKIP [$label] source not found: $source"
            }
        } catch {
            "FAIL [$label] error copying from '$source': $_"
        }
    }

    $copyLog = @()
    $copyLog += Copy-Artifact "Prefetch"          "$env:WINDIR\Prefetch"                     "Prefetch"
    $copyLog += Copy-Artifact "Recent items"      "$env:APPDATA\Microsoft\Windows\Recent"     "Recent"
    $copyLog += Copy-Artifact "Windows Event Logs" "$env:WINDIR\System32\winevt\Logs"         "EventLogs"
    $copyLog | Set-Content -Path (Join-Path $temp "13_raw_artifact_copy_log.txt") -Encoding UTF8

    # ------------------------------------------------------------
    # Zip everything up into Desktop\AC-FINDINGS\FINDINGS-<stamp>.zip
    # Using System.IO.Compression directly - noticeably faster than
    # Compress-Archive once Prefetch + Event Logs are in the mix.
    # ------------------------------------------------------------
    $acFolder = Join-Path $desktop "AC-FINDINGS"
    New-Item -ItemType Directory -Path $acFolder -Force | Out-Null

    $zipPath = Join-Path $acFolder "FINDINGS-$stamp.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $temp, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

    Remove-Item $temp -Recurse -Force

    return $zipPath
}

# ============================================================
# Run collector as background job, animate spinner while waiting
# ============================================================
$job = Start-Job -ScriptBlock $collector

$spinner = @('|','/','-','\')
$i = 0
while ($job.State -eq 'Running') {
    Write-Host -NoNewline ("`r  Loading findings... $($spinner[$i % $spinner.Length])  ")
    Start-Sleep -Milliseconds 150
    $i++
}

Write-Host -NoNewline "`r"

if ($job.State -eq 'Failed') {
    Write-Host "  Collection FAILED.                  " -ForegroundColor Red
    Write-Host ""
    Receive-Job -Job $job -ErrorAction SilentlyContinue 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    Remove-Job -Job $job
    return
}

$zipPath = Receive-Job -Job $job
Remove-Job -Job $job

$zipSizeMB = if (Test-Path $zipPath) { [math]::Round((Get-Item $zipPath).Length / 1MB, 2) } else { $null }

Write-Host "  Loading findings... done!          " -ForegroundColor Green
Write-Host ""
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Output saved to:" -ForegroundColor White
Write-Host "  $zipPath" -ForegroundColor Yellow
if ($zipSizeMB) {
    Write-Host "  Size: $zipSizeMB MB" -ForegroundColor Yellow
}
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
