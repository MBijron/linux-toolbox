param(
    [int]$CountdownSeconds = 20,
    [string]$ProcessName = 'SmallToolsBox.Cli'
)

function Clear-PendingInput {
    while ([Console]::KeyAvailable) {
        [void][Console]::ReadKey($true)
    }
}

function Wait-ForCountdownOrReset {
    param(
        [Parameter(Mandatory = $true)][int]$Seconds
    )

    $remaining = $Seconds

    while ($remaining -gt 0) {
        $wasReset = $false
        Write-Host ("`rPress Enter to reset. Ctrl+C to stop. Killing SmallToolsBox.Cli.exe in {0,2}s..." -f $remaining) -NoNewline

        $deadline = [DateTime]::UtcNow.AddSeconds(1)
        while ([DateTime]::UtcNow -lt $deadline) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Enter) {
                    Clear-PendingInput
                    Write-Host "`rCountdown reset to $Seconds.                                              "
                    $remaining = $Seconds
                    $wasReset = $true
                    break
                }
            }

            Start-Sleep -Milliseconds 100
        }

        if ($wasReset) {
            continue
        }

        $remaining--
    }

    Write-Host ("`rPress Enter to reset. Ctrl+C to stop. Killing SmallToolsBox.Cli.exe in  0s...")
}

function Stop-TargetProcesses {
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    $matchingProcesses = @(Get-Process -Name $Name -ErrorAction SilentlyContinue)

    if ($matchingProcesses.Count -eq 0) {
        Write-Host ("[{0}] No {1}.exe processes found." -f (Get-Date -Format 'HH:mm:ss'), $Name) -ForegroundColor DarkGray
        return
    }

    foreach ($process in $matchingProcesses) {
        try {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-Host ("[{0}] Stopped {1}.exe (PID {2})." -f (Get-Date -Format 'HH:mm:ss'), $Name, $process.Id) -ForegroundColor Yellow
        } catch {
            Write-Host ("[{0}] Failed to stop {1}.exe (PID {2}): {3}" -f (Get-Date -Format 'HH:mm:ss'), $Name, $process.Id, $_.Exception.Message) -ForegroundColor Red
        }
    }
}

if ($CountdownSeconds -lt 0) {
    throw 'CountdownSeconds must be zero or greater.'
}

Clear-PendingInput

while ($true) {
    Wait-ForCountdownOrReset -Seconds $CountdownSeconds
    Stop-TargetProcesses -Name $ProcessName
}