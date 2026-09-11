Clear-Host

# ============================================================
# w vibe code
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

    # 9. Virtualization / systeminfo (repeat)
    Save "09_systeminfo_virtualization_repeat" {
        systeminfo | findstr /i "hyper os version page virtualization"
    }

    # 10. collect_report.ps1 notice
    Save "10_collect_report_notice" {
        "This step calls an external script (.\collect_report.ps1) whose contents were not provided,"
        "so it has not been bundled or run here. Read any unknown script before running it."
    }

    # 11. Prefetch files
    Save "11_prefetch_files" {
        Get-ChildItem "$env:WINDIR\Prefetch" -Filter *.pf -ErrorAction SilentlyContinue |
            Select-Object Name, CreationTime, LastWriteTime, LastAccessTime |
            Sort-Object LastWriteTime -Descending
    }

    # 12. Recent items (shell:recent)
    Save "12_recent_items" {
        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        Get-ChildItem $recentPath -ErrorAction SilentlyContinue |
            Select-Object Name, CreationTime, LastWriteTime |
            Sort-Object LastWriteTime -Descending
    }

    # 13. Recent items resolved targets
    Save "13_recent_items_targets" {
        $sh = New-Object -ComObject WScript.Shell
        Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Filter *.lnk -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    $lnk = $sh.CreateShortcut($_.FullName)
                    [PSCustomObject]@{
                        Name          = $_.Name
                        Target        = $lnk.TargetPath
                        Arguments     = $lnk.Arguments
                        LastWriteTime = $_.LastWriteTime
                    }
                } catch {
                    [PSCustomObject]@{ Name = $_.Name; Target = "ERROR"; Arguments = ""; LastWriteTime = $_.LastWriteTime }
                }
            }
    }

    # 14. Processes currently running alongside Roblox (context for injector detection)
    Save "14_processes_running_with_roblox" {
        $robloxRunning = Get-Process | Where-Object { $_.ProcessName -match 'Roblox' }
        if ($robloxRunning) {
            "Roblox process(es) found:"
            $robloxRunning | Select-Object ProcessName, Id, StartTime, Path
            ""
            "All other running processes at time of scan (review for anything unfamiliar):"
            Get-Process | Where-Object { $_.ProcessName -notmatch 'Roblox' } |
                Select-Object ProcessName, Id, StartTime,
                    @{n='Path';e={ $_.Path }} |
                Sort-Object ProcessName
        } else {
            "Roblox does not appear to be running right now. Run this while Roblox is open for useful results."
        }
    }

    # 15. Unsigned / suspicious DLLs loaded into any running process
    Save "15_suspicious_loaded_modules" {
        "Scanning loaded modules of all accessible processes for unsigned DLLs outside system folders."
        "This can take a minute. Access-denied processes (protected/system) are skipped automatically."
        ""
        $sysPaths = @("$env:WINDIR\System32", "$env:WINDIR\SysWOW64")
        foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
            try {
                foreach ($mod in $proc.Modules) {
                    $inSystemPath = $sysPaths | Where-Object { $mod.FileName -like "$_*" }
                    if (-not $inSystemPath) {
                        $sig = Get-AuthenticodeSignature -FilePath $mod.FileName -ErrorAction SilentlyContinue
                        if ($sig.Status -ne 'Valid') {
                            [PSCustomObject]@{
                                Process    = $proc.ProcessName
                                PID        = $proc.Id
                                Module     = $mod.ModuleName
                                ModulePath = $mod.FileName
                                SigStatus  = $sig.Status
                            }
                        }
                    }
                }
            } catch {
                # Access denied on protected processes — expected and skipped
            }
        }
    }

    # ------------------------------------------------------------
    # Zip everything up
    # ------------------------------------------------------------
    $zipPath = Join-Path $desktop "findings.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$temp\*" -DestinationPath $zipPath -Force
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

$zipPath = Receive-Job -Job $job
Remove-Job -Job $job

Write-Host -NoNewline "`r"
Write-Host "  Loading findings... done!          " -ForegroundColor Green
Write-Host ""
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Output saved to:" -ForegroundColor White
Write-Host "  $zipPath" -ForegroundColor Yellow
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
