# setup_choco_git_ssh.ps1
# Sets up WSL, Chocolatey, Git, and a GitHub SSH key in one elevated PowerShell run.

param(
    [switch]$ForceNewSshKey
)

# --- Configuration ---------------------------------------------------------
$ChocolateyPackagesToInstall = @(
    'launchy',
    'notepadplusplus',
    'signal',
    'vscode-insiders'
)

# Winget/Store identifiers documented via `winget search WhatsApp`
$StoreAppsToInstall = @(
    @{ Id = 'WhatsApp.WhatsApp'; DisplayName = 'WhatsApp Messenger'; AppxPackageName = '5319275A.WhatsAppDesktop' }
)

$TotalSetupSteps = 6
$scriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

if ($MyInvocation.MyCommand.Path -and (Get-Command Unblock-File -ErrorAction SilentlyContinue)) {
    try { Unblock-File -LiteralPath $MyInvocation.MyCommand.Path -ErrorAction Stop } catch {}
}

if ($MyInvocation.MyCommand.Path -like '\\*') {
    try {
        $internetSettings = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        New-ItemProperty -Path $internetSettings -Name 'UNCAsIntranet' -PropertyType DWord -Value 1 -Force | Out-Null
        $domainsRoot = Join-Path $internetSettings 'ZoneMap\Domains'
        if (Test-Path $domainsRoot) {
            $uncHost = ($MyInvocation.MyCommand.Path -replace '^\\\\([^\\]+).*', '$1')
            if ($uncHost) {
                $segments = $uncHost.Split('.')
                $current = $domainsRoot
                for ($i = $segments.Length - 1; $i -ge 0; $i--) {
                    $segment = $segments[$i]
                    if (-not $segment) { continue }
                    $current = Join-Path $current $segment
                    if (-not (Test-Path -LiteralPath $current)) { New-Item -Path $current -Force | Out-Null }
                }
                New-ItemProperty -Path $current -Name 'file' -PropertyType DWord -Value 1 -Force | Out-Null
            }
        }
    } catch {
        Write-Warning "Failed to relax UNC trust for this script: $_"
    }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Reload-EnvironmentPath {
    try {
        $machine = [Environment]::GetEnvironmentVariable('Path','Machine')
        $user = [Environment]::GetEnvironmentVariable('Path','User')
        $env:Path = if ($machine -and $user) { $machine + ';' + $user } elseif ($machine) { $machine } else { $user }
    } catch {
        Write-Warning "Failed to reload PATH: $_"
    }
}

function Write-ActionStatus {
    param(
        [string] $Action,
        [string] $Message,
        [string] $Indent = '  '
    )

    $label = if ([string]::IsNullOrWhiteSpace($Action)) { 'Info' } else { $Action }
    $normalized = $label.ToLowerInvariant()

    $color = 'White'
    switch ($normalized) {
        'skipped' { $color = 'DarkGray' }
        'available' { $color = 'DarkGray' }
        'existing' { $color = 'DarkGray' }
        'unchanged' { $color = 'DarkGray' }
        'installed' { $color = 'Green' }
        'generated' { $color = 'Green' }
        'running' { $color = 'Green' }
        'started' { $color = 'Green' }
        'success' { $color = 'Green' }
        'warning' { $color = 'Yellow' }
        'pending' { $color = 'Yellow' }
        'installfailed' { $color = 'Red' }
        'missingchoco' { $color = 'Red' }
        'missing' { $color = 'Red' }
        'error' { $color = 'Red' }
        'unavailable' { $color = 'Red' }
        default { $color = 'White' }
    }

    Write-Host ("{0}[{1}] {2}" -f $Indent, $label, $Message) -ForegroundColor $color
}

function Get-WslExecutablePath {
    $cmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $fallback = Join-Path $env:WinDir 'System32\wsl.exe'
    if (Test-Path $fallback) { return $fallback }
    return $null
}

function Ensure-WSL {
    $wslPath = Get-WslExecutablePath
    if (-not $wslPath) {
        return [pscustomobject]@{
            Success = $false
            Action = 'Missing'
            Message = 'wsl.exe not found. Windows Subsystem for Linux is required.'
        }
    }

    $ready = $false
    $installed = $false
    try {
        & $wslPath --help *> $null
        $ready = $true
    } catch { $ready = $false }

    if (-not $ready) {
        Write-Host 'WSL not initialized. Installing WSL...'
        try {
            & $wslPath --install
            if ($LASTEXITCODE -ne 0) {
                return [pscustomobject]@{
                    Success = $false
                    Action = 'InstallFailed'
                    Message = "WSL install exited with code $LASTEXITCODE."
                }
            }
            $installed = $true
        } catch {
            return [pscustomobject]@{
                Success = $false
                Action = 'InstallFailed'
                Message = "WSL installation failed: $_"
            }
        }

        Start-Sleep -Seconds 5
        try {
            & $wslPath --help *> $null
            $ready = $true
        } catch {
            Write-Warning 'WSL install finished but wsl.exe is unavailable yet. A reboot may be required.'
            return [pscustomobject]@{
                Success = $false
                Action = 'Unavailable'
                Message = 'wsl.exe is unavailable after installation; a reboot may be required.'
            }
        }
    }

    try {
        & $wslPath --set-default-version 2
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Unable to set WSL default version to 2 (exit $LASTEXITCODE)."
        } else {
            Write-Host 'WSL default version set to 2.'
        }
    } catch {
        Write-Warning "Failed to set WSL default version: $_"
    }

    return [pscustomobject]@{
        Success = $true
        Action = if ($installed) { 'Installed' } else { 'Skipped' }
        Message = if ($installed) { 'WSL installation completed successfully.' } else { 'WSL already installed; skipping setup.' }
    }
}

function Ensure-UbuntuDistro {
    param([string] $DistributionName = 'Ubuntu')

    $wslPath = Get-WslExecutablePath
    if (-not $wslPath) {
        return [pscustomobject]@{
            Success = $false
            Action = 'Missing'
            Message = 'Cannot manage WSL distributions because wsl.exe is unavailable.'
        }
    }

    $existing = @()
    $installed = $false
    try {
        $existing = & $wslPath --list --quiet 2>$null | Where-Object { $_ } | ForEach-Object { $_.Trim() }
    } catch {
        Write-Warning "Failed to enumerate WSL distributions: $_"
    }

    $match = $existing | Where-Object { $_ -like "$DistributionName*" }
    if ($match.Count -gt 0) {
        return [pscustomobject]@{
            Success = $true
            Action = 'Skipped'
            Message = "Ubuntu distribution already present: $($match -join ', ')"
        }
    }

    Write-Host "Installing WSL distribution '$DistributionName'..."
    try {
        & $wslPath --install -d $DistributionName
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{
                Success = $false
                Action = 'InstallFailed'
                Message = "WSL distribution install exited with code $LASTEXITCODE."
            }
        }
        $installed = $true
    } catch {
        return [pscustomobject]@{
            Success = $false
            Action = 'InstallFailed'
            Message = "Failed to install '$DistributionName': $_"
        }
    }

    Start-Sleep -Seconds 5
    try {
        $existing = & $wslPath --list --quiet 2>$null | Where-Object { $_ } | ForEach-Object { $_.Trim() }
    } catch {
        Write-Warning "Could not confirm installation of '$DistributionName'."
    }

    $match = $existing | Where-Object { $_ -like "$DistributionName*" }
    if ($match.Count -gt 0) {
        return [pscustomobject]@{
            Success = $true
            Action = if ($installed) { 'Installed' } else { 'Available' }
            Message = if ($installed) { "WSL distribution '$DistributionName' installed as: $($match -join ', ')" } else { "WSL distribution '$DistributionName' is now available as: $($match -join ', ')" }
        }
    }

    Write-Warning "WSL reports that '$DistributionName' is not available yet. Complete any reboot prompts and try again."
    return [pscustomobject]@{
        Success = $false
        Action = 'Pending'
        Message = "WSL reports that '$DistributionName' is not available yet. Complete any reboot prompts and try again."
    }
}

function Ensure-Chocolatey {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $source = Get-Command choco | Select-Object -ExpandProperty Source
        return [pscustomobject]@{
            Success = $true
            Action = 'Skipped'
            Message = "Chocolatey already available at $source"
        }
    }

    Write-Host 'Chocolatey not found. Installing Chocolatey...'

    $installScript = {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }

    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -Command $installScript
    } catch {
        return [pscustomobject]@{
            Success = $false
            Action = 'InstallFailed'
            Message = "Chocolatey installation failed: $_"
        }
    }

    Reload-EnvironmentPath
    Start-Sleep -Seconds 2
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        return [pscustomobject]@{
            Success = $true
            Action = 'Installed'
            Message = 'Chocolatey installed successfully.'
        }
    }

    return [pscustomobject]@{
        Success = $false
        Action = 'InstallFailed'
        Message = "Chocolatey installation completed but 'choco' is unavailable."
    }
}

function Install-ChocoPackage {
    param([Parameter(Mandatory = $true)][string] $PackageName)

    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            Name = $PackageName
            Success = $false
            Action = 'MissingChoco'
            Message = 'Chocolatey is not available; cannot install package.'
        }
    }

    Write-Host "Checking for existing Chocolatey package: $PackageName" -ForegroundColor DarkGray
    $installed = $false
    try {
        $result = & choco list --local-only --exact $PackageName --limit-output 2>$null | ForEach-Object { $_.Trim() }
        if ($result -and ($result -match "^$([Regex]::Escape($PackageName))\|")) { $installed = $true }
    } catch {
        Write-Warning "Unable to determine existing installation state for ${PackageName}: $_"
    }

    if ($installed) {
        return [pscustomobject]@{
            Name = $PackageName
            Success = $true
            Action = 'Skipped'
            Message = 'Package already installed.'
        }
    }

    Write-Host "Installing $PackageName via Chocolatey (this may take a moment)..."
    try {
        & choco install $PackageName -y
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{
                Name = $PackageName
                Success = $false
                Action = 'InstallFailed'
                Message = "Chocolatey returned exit code $LASTEXITCODE."
            }
        }
    } catch {
        return [pscustomobject]@{
            Name = $PackageName
            Success = $false
            Action = 'InstallFailed'
            Message = "Failed to install package: $_"
        }
    }

    Reload-EnvironmentPath
    Write-Host "$PackageName install completed."
    return [pscustomobject]@{
        Name = $PackageName
        Success = $true
        Action = 'Installed'
        Message = 'Package installed successfully.'
    }
}

function Install-StoreApp {
    param(
        [Parameter(Mandatory = $true)][string] $Id,
        [string] $DisplayName,
        [string] $AppxPackageName,
        [string] $PackageFamilyName
    )

    $appName = if ($DisplayName) { $DisplayName } else { $Id }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            Name = $appName
            Success = $false
            Action = 'MissingWinget'
            Message = 'winget command not found; install the App Installer from the Microsoft Store.'
        }
    }

    Write-Host "Checking Microsoft Store application: $appName" -ForegroundColor DarkGray

    function Test-StoreAppInstalled {
        param()

        if ($AppxPackageName) {
            try {
                if (Get-AppxPackage -Name $AppxPackageName -ErrorAction SilentlyContinue) { return $true }
            } catch {}
        }

        if ($PackageFamilyName) {
            try {
                if (Get-AppxPackage -PackageFamilyName $PackageFamilyName -ErrorAction SilentlyContinue) { return $true }
            } catch {}
        }

        try {
            $listResult = & winget list --id $Id --exact --accept-source-agreements 2>$null
            if ($listResult -and $listResult -match [Regex]::Escape($Id)) {
                return $true
            }
        } catch {}

        return $false
    }

    if (Test-StoreAppInstalled) {
        return [pscustomobject]@{
            Name = $appName
            Success = $true
            Action = 'Skipped'
            Message = 'Application already installed.'
        }
    }

    Write-Host "Installing $appName from Microsoft Store (winget)..."

    $installExit = $null
    $installError = $null
    try {
        & winget install --id $Id --exact --accept-package-agreements --accept-source-agreements
        $installExit = $LASTEXITCODE
    } catch {
        $installExit = $LASTEXITCODE
        $installError = $_
    }

    if ($installExit -eq 0) {
        return [pscustomobject]@{
            Name = $appName
            Success = $true
            Action = 'Installed'
            Message = 'Application installed successfully.'
        }
    }

    if (Test-StoreAppInstalled) {
        return [pscustomobject]@{
            Name = $appName
            Success = $true
            Action = 'Skipped'
            Message = "Application already installed (winget exit code $installExit)."
        }
    }

    $errorMessage = if ($installError) { "winget failed: $installError" } else { "winget returned exit code $installExit." }
    return [pscustomobject]@{
        Name = $appName
        Success = $false
        Action = 'InstallFailed'
        Message = $errorMessage
    }
}

function Ensure-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $source = Get-Command git | Select-Object -ExpandProperty Source
        return [pscustomobject]@{
            Success = $true
            Action = 'Skipped'
            Message = "Git already available at $source"
        }
    }

    Write-Host 'Git not found. Installing git via Chocolatey...'

    try {
        iex "choco install git -y --no-progress"
    } catch {
        return [pscustomobject]@{
            Success = $false
            Action = 'InstallFailed'
            Message = "Failed to install git via choco: $_"
        }
    }

    Reload-EnvironmentPath
    Start-Sleep -Seconds 2
    if (Get-Command git -ErrorAction SilentlyContinue) {
        return [pscustomobject]@{
            Success = $true
            Action = 'Installed'
            Message = 'Git installed and available.'
        }
    }

    return [pscustomobject]@{
        Success = $false
        Action = 'InstallFailed'
        Message = "Git installation finished but 'git' is unavailable."
    }
}

function Ensure-OpenSshAgent {
    try {
        $svc = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
        if (-not $svc) {
            return [pscustomobject]@{
                Success = $false
                Action = 'Missing'
                Message = 'ssh-agent service not found. Ensure another agent is running.'
            }
        }

        if ($svc.Status -ne 'Running') {
            Set-Service -Name ssh-agent -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name ssh-agent -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }

        return [pscustomobject]@{
            Success = $true
            Action = if ($svc.Status -eq 'Running') { 'Running' } else { 'Started' }
            Message = 'ssh-agent service is running.'
        }
    } catch {
        return [pscustomobject]@{
            Success = $false
            Action = 'Error'
            Message = "Failed to ensure ssh-agent service: $_"
        }
    }
}

function Generate-And-Register-SshKey {
    param([string] $BaseName = 'toolbox_key')

    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir | Out-Null
        try { icacls $sshDir /inheritance:r | Out-Null } catch {}
    }

    $keyPath = Join-Path $sshDir $BaseName
    if ((Test-Path $keyPath) -and -not $ForceNewSshKey) {
        $existingPub = "$keyPath.pub"
        if (-not (Test-Path $existingPub)) {
            Write-Warning "Existing key found at $keyPath but public key is missing. Regenerating."
        } else {
            return [pscustomobject]@{
                Private = $keyPath
                Public = $existingPub
                Generated = $false
                AddedToAgent = $false
                Message = 'Existing SSH key reused.'
            }
        }
    }

    if (Test-Path $keyPath) {
        $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
        $keyPath = Join-Path $sshDir ("${BaseName}_${stamp}")
        Write-Host "Key name already existed. New key will be: $(Split-Path $keyPath -Leaf)"
    }

    $sshKeygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $sshKeygen) {
        Write-Error 'ssh-keygen not found. Ensure OpenSSH is installed.'
        return $null
    }

    $genArgs = @('-t','ed25519','-f',$keyPath,'-C',$BaseName,'-N','')
    Write-Host "Generating SSH key: $keyPath"
    & ssh-keygen @genArgs

    $pubPath = "$keyPath.pub"
    if (-not (Test-Path $pubPath)) {
        Write-Error 'Public key was not created as expected.'
        return $null
    }

    $agentResult = Ensure-OpenSshAgent
    if (-not $agentResult.Success) {
        Write-Warning $agentResult.Message
    } else {
        Write-Host $agentResult.Message
    }

    $addedToAgent = $false
    try {
        & ssh-add $keyPath | Out-Null
        Write-Host 'New key added to ssh-agent.'
        $addedToAgent = $true
    } catch {
        Write-Warning "ssh-add failed: $_"
    }

    return [pscustomobject]@{
        Private = $keyPath
        Public = $pubPath
        Generated = $true
        AddedToAgent = $addedToAgent
        Message = 'New SSH key generated.'
    }
}

if (-not (Test-IsAdmin)) {
    Write-Error 'Run this script from an elevated PowerShell session.'
    exit 1
}

Write-Output 'Starting setup: WSL, Chocolatey, Git, requested packages, and SSH key registration...'

Write-Output "Step 1/$TotalSetupSteps - Check WSL installation."
$wslStatus = Ensure-WSL
if (-not $wslStatus.Success) {
    Write-Error $wslStatus.Message
    exit 1
}
Write-ActionStatus -Action $wslStatus.Action -Message $wslStatus.Message

Write-Output "Step 2/$TotalSetupSteps - Check Ubuntu distribution availability."
$ubuntuStatus = Ensure-UbuntuDistro -DistributionName 'Ubuntu'
if (-not $ubuntuStatus.Success) {
    Write-Error $ubuntuStatus.Message
    exit 1
}
Write-ActionStatus -Action $ubuntuStatus.Action -Message $ubuntuStatus.Message

Write-Output "Step 3/$TotalSetupSteps - Check Chocolatey availability."
$chocoStatus = Ensure-Chocolatey
if (-not $chocoStatus.Success) {
    Write-Error $chocoStatus.Message
    exit 1
}
Write-ActionStatus -Action $chocoStatus.Action -Message $chocoStatus.Message
Reload-EnvironmentPath

Write-Output "Step 4/$TotalSetupSteps - Check Git availability."
$gitStatus = Ensure-Git
if (-not $gitStatus.Success) {
    Write-Error $gitStatus.Message
    exit 1
}
Write-ActionStatus -Action $gitStatus.Action -Message $gitStatus.Message
Reload-EnvironmentPath

Write-Host 'Installing supplemental Chocolatey packages.'
$packageResults = @()
foreach ($pkg in $ChocolateyPackagesToInstall) {
    $result = Install-ChocoPackage -PackageName $pkg
    $packageResults += $result
    if ($result) {
        Write-ActionStatus -Action $result.Action -Message "$($result.Name): $($result.Message)"
    }
}

$failedPackages = @()
foreach ($pkgResult in $packageResults) {
    if ($pkgResult -and -not $pkgResult.Success) {
        $nameProp = $pkgResult.PSObject.Properties['Name']
        if ($nameProp) { $failedPackages += $nameProp.Value }
    }
}

if ($failedPackages.Count -gt 0) {
    Write-Warning "Completed with package installation errors: $($failedPackages -join ', ')"
} else {
    $installedPackages = @($packageResults | Where-Object { $_ -and $_.Action -eq 'Installed' })
    if ($installedPackages.Count -gt 0) {
        Write-ActionStatus -Action 'Success' -Message 'Requested Chocolatey packages are installed.'
    } elseif ($ChocolateyPackagesToInstall.Count -gt 0) {
        Write-ActionStatus -Action 'Skipped' -Message 'No Chocolatey packages required installation.'
    } else {
        Write-ActionStatus -Action 'Skipped' -Message 'No Chocolatey packages configured.'
    }
}

Write-Output "Step 5/$TotalSetupSteps - Install Microsoft Store applications."
$storeResults = @()
foreach ($app in $StoreAppsToInstall) {
    $storeResult = Install-StoreApp -Id $app.Id -DisplayName $app.DisplayName -AppxPackageName $app.AppxPackageName -PackageFamilyName $app.PackageFamilyName
    $storeResults += $storeResult
    if ($storeResult) {
        Write-ActionStatus -Action $storeResult.Action -Message "$($storeResult.Name): $($storeResult.Message)"
    }
}

$failedStoreApps = @()
foreach ($appResult in $storeResults) {
    if ($appResult -and -not $appResult.Success) {
        $nameProp = $appResult.PSObject.Properties['Name']
        if ($nameProp) { $failedStoreApps += $nameProp.Value }
    }
}

if ($StoreAppsToInstall.Count -eq 0) {
    Write-ActionStatus -Action 'Skipped' -Message 'No Microsoft Store apps configured.'
} elseif ($failedStoreApps.Count -gt 0) {
    Write-Warning "Microsoft Store installs completed with errors: $($failedStoreApps -join ', ')"
} else {
    $installedStoreApps = @($storeResults | Where-Object { $_ -and $_.Action -eq 'Installed' })
    if ($installedStoreApps.Count -gt 0) {
        Write-ActionStatus -Action 'Success' -Message 'Microsoft Store applications are installed.'
    } else {
        Write-ActionStatus -Action 'Skipped' -Message 'No Microsoft Store applications required installation.'
    }
}

Write-Output "Step 6/$TotalSetupSteps - Generate SSH key and register with ssh-agent."
$keyInfo = Generate-And-Register-SshKey -BaseName 'toolbox_key'
if ($keyInfo -is [System.Array]) { $keyInfo = $keyInfo[-1] }
if (-not $keyInfo) {
    Write-Error 'SSH key generation or registration failed.'
    exit 1
}
$sshAction = if ($keyInfo.Generated) { 'Generated' } else { 'Skipped' }
Write-ActionStatus -Action $sshAction -Message $keyInfo.Message
if ($keyInfo.Generated) {
    Write-ActionStatus -Action 'Success' -Message 'SSH key generation completed.'
}

try {
    Remove-Item Env:\GIT_SSH -ErrorAction SilentlyContinue
    Remove-Item Env:\GIT_SSH_COMMAND -ErrorAction SilentlyContinue
} catch {}

try {
    $currentSshCommand = & git config --global --get core.sshCommand 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $currentSshCommand -or $currentSshCommand -ne 'ssh') {
        & git config --global core.sshCommand 'ssh' 2>$null
    } else {
        Write-ActionStatus -Action 'Skipped' -Message 'Git core.sshCommand already set to ssh.'
    }
} catch {
    Write-Warning "Unable to verify or update git core.sshCommand: $_"
}

Write-Host ''
$stepThreeMessage = $null
$pubKey = $null
if ($keyInfo.Generated -or $ForceNewSshKey) {
    $pubKey = Get-Content $keyInfo.Public -Raw
    Write-Host '--- PUBLIC KEY ---'
    Write-Host $pubKey
    Write-Host ''
    Write-Host 'Copy the public key above into GitHub manually.'
    $stepThreeMessage = '  3. Paste the public key that was printed above.'
} else {
    Write-ActionStatus -Action 'Skipped' -Message "SSH key reused from $($keyInfo.Private); public key not displayed." -Indent ''
    $stepThreeMessage = "  3. If you need the public key, open $($keyInfo.Public) and copy its contents."
}

Write-Host ''
if ($keyInfo.Generated) {
    if ($keyInfo.AddedToAgent) {
        Write-ActionStatus -Action 'Success' -Message 'New key added to ssh-agent.' -Indent ''
    } else {
        Write-ActionStatus -Action 'Warning' -Message 'Generated key could not be added to ssh-agent; you may need to add it manually.' -Indent ''
    }
    Write-Host ''
    Write-Host 'Next steps to add this key to GitHub:'
    Write-Host '  1. Open https://github.com -> Settings -> SSH and GPG keys -> New SSH key'
    Write-Host '  2. Use a title such as toolbox_key (or the filename shown above)'
    Write-Host $stepThreeMessage
    Write-Host ''
    Write-Host 'Optional: after adding the key, test the connection with:'
    Write-Host '  ssh -T git@github.com'
    Write-Host ''
    Write-Host 'Paste the key into GitHub to finish setup.'
} else {
    Write-ActionStatus -Action 'Skipped' -Message 'Existing ssh-agent identities left unchanged.' -Indent ''
}

if ($failedPackages.Count -gt 0) {
    Write-Warning 'Script completed with package installation warnings.'
    exit 2
}

Write-Host ''
$scriptStopwatch.Stop()
Write-ActionStatus -Action 'Success' -Message ("Setup completed in {0:N1} seconds." -f $scriptStopwatch.Elapsed.TotalSeconds) -Indent ''

exit 0
