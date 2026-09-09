# ============================================================
# Diagnostic collection script
# Produces one .txt file per section, zipped as findings.zip on the Desktop
# ============================================================

$desktop = [Environment]::GetFolderPath('Desktop')
$stamp   = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$temp    = Join-Path $env:TEMP "findings_$stamp"
New-Item -ItemType Directory -Path $temp -Force | Out-Null

function Save($name, $scriptblock) {
    $path = Join-Path $temp "$name.txt"
    Write-Host "Collecting: $name..." -ForegroundColor Cyan
    try {
        (& $scriptblock) | Out-String -Width 300 | Set-Content -Path $path -Encoding UTF8
    } catch {
        "ERROR: $_" | Set-Content -Path $path -Encoding UTF8
    }
}

# 1. Process list with parentage + file size
Save "01_process_parentage" {
    Get-CimInstance Win32_Process | Select-Object Name, ProcessId,
        @{n='ParentName';e={(Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue).Name}},
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
Save "03_scheduled_tasks" {
    Get-ScheduledTask
}

# 4. Tasklist
Save "04_tasklist" {
    tasklist
}

# 5. Process start times
Save "05_process_starttimes" {
    Get-Process | Select-Object Name, StartTime -ErrorAction SilentlyContinue
}

# 6. Running services
Save "06_running_services" {
    Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, Status
}

# 7. Unsigned exes in Program Files (with size + hash)
$unsigned = Get-ChildItem -Path 'C:\Program Files','C:\Program Files (x86)' -Recurse -Include *.exe -ErrorAction SilentlyContinue |
    Get-AuthenticodeSignature |
    Where-Object { $_.Status -ne 'Valid' } |
    Select-Object Path, Status,
        @{n='SizeMB';e={ [math]::Round((Get-Item $_.Path -ErrorAction SilentlyContinue).Length / 1MB, 2) }}

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

# 9. Virtualization / systeminfo (repeat, as listed)
Save "09_systeminfo_virtualization_repeat" {
    systeminfo | findstr /i "hyper os version page virtualization"
}

# 10. collect_report.ps1 — NOT included automatically
Save "10_collect_report_notice" {
    "This step calls an external script (.\collect_report.ps1) whose contents were not provided,"
    "so it has not been bundled or run here. Before running any script you did not write yourself,"
    "open it in a text editor and read what it does line by line — especially if someone else told"
    "you to run it and send them the output."
}

# ------------------------------------------------------------
# Zip everything up
# ------------------------------------------------------------
$zipPath = Join-Path $desktop "findings.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$temp\*" -DestinationPath $zipPath -Force

Remove-Item $temp -Recurse -Force

Write-Host ""
Write-Host "Done. Zip created at: $zipPath" -ForegroundColor Green
