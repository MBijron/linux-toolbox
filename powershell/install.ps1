param(
    [switch]$ForceNewSshKey,
    [switch]$NoGit,
    [switch]$VerboseOutput,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$AdditionalArgs
)

if ($AdditionalArgs) {
    foreach ($extraArg in $AdditionalArgs) {
        if (-not $extraArg) { continue }
        switch ($extraArg.ToLowerInvariant()) {
            '--no-git' { $NoGit = $true }
            '--force-new-ssh-key' { $ForceNewSshKey = $true }
            '--verbose' { $VerboseOutput = $true }
            default {
                Write-Host ("[Info] Ignoring unrecognized argument '{0}'." -f $extraArg) -ForegroundColor DarkGray
            }
        }
    }
}

$Script:InstallVerboseEnabled = [bool]$VerboseOutput

# --- Framework -------------------------------------------------------------

$Script:InstallStatusColors = @{
    'info'          = 'Cyan'
    'success'       = 'Green'
    'installed'     = 'Green'
    'generated'     = 'Green'
    'running'       = 'Green'
    'started'       = 'Green'
    'skipped'       = 'DarkGray'
    'available'     = 'DarkGray'
    'existing'      = 'DarkGray'
    'unchanged'     = 'DarkGray'
    'warning'       = 'Yellow'
    'pending'       = 'Yellow'
    'installfailed' = 'Red'
    'missing'       = 'Red'
    'missingchoco'  = 'Red'
    'missingwinget' = 'Red'
    'error'         = 'Red'
    'unavailable'   = 'Red'
}

function New-ActionResult {
    param(
        [Parameter(Mandatory = $true)][bool]$Success,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Message,
        $Data
    )

    return [pscustomobject]@{
        Success = $Success
        Status  = $Status
        Message = $Message
        Data    = $Data
    }
}

function Write-InstallStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Indent = '  '
    )

    $label = if ([string]::IsNullOrWhiteSpace($Status)) { 'Info' } else { $Status }
    $normalized = $label.ToLowerInvariant()
    $color = if ($Script:InstallStatusColors.ContainsKey($normalized)) { $Script:InstallStatusColors[$normalized] } else { 'White' }

    Write-Host ("{0}[{1}] {2}" -f $Indent, $label, $Message) -ForegroundColor $color
}

function Write-InstallVerbose {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    begin {
        $isEnabled = [bool]$Script:InstallVerboseEnabled
        $indent = '        '
        $color = 'DarkGray'
        $lastLine = $null
    }

    process {
        if (-not $isEnabled) { return }
        if ($null -eq $InputObject) { return }

        $text = switch ($InputObject) {
            { $_ -is [string] } { $_ }
            { $_ -is [scriptblock] } { $_.ToString() }
            { $_ -is [System.Collections.IEnumerable] } { ($InputObject | Out-String) }
            default { $_.ToString() }
        }

        if ([string]::IsNullOrWhiteSpace($text)) { return }

        $lines = [System.Text.RegularExpressions.Regex]::Split($text, '\r?\n')

        foreach ($line in $lines) {
            if ($null -eq $line) { continue }
            $normalized = ($line -replace '[\u0000\u0008\u0009\u000B\u000C\u000D]', '').Trim()
            if ([string]::IsNullOrWhiteSpace($normalized)) { continue }
            if ($normalized -eq $lastLine) { continue }
            $lastLine = $normalized
            Write-Host ("{0}{1}" -f $indent, $normalized) -ForegroundColor $color
        }
    }
}

function Format-InstallCommandLine {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [object[]]$Arguments
    )

    $parts = @()
    $exeText = [string]$Executable
    if ($exeText -match '[\s"`$]') {
        $parts += '"{0}"' -f $exeText.Replace('"', '\"')
    } else {
        $parts += $exeText
    }

    if ($Arguments) {
        foreach ($arg in $Arguments) {
            if ($null -eq $arg) { continue }
            $text = [string]$arg
            if ($text.Length -eq 0) {
                $parts += '""'
                continue
            }

            if ($text -match '[\s"`$]') {
                $escaped = $text.Replace('"', '\"')
                $parts += '"{0}"' -f $escaped
            } else {
                $parts += $text
            }
        }
    }

    return ($parts -join ' ')
}

function Invoke-InstallCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [object[]]$Arguments,
        [switch]$CaptureOutput
    )

    $argsArray = if ($Arguments) { $Arguments } else { @() }

    if ($Script:InstallVerboseEnabled) {
        (Format-InstallCommandLine -Executable $FilePath -Arguments $argsArray) | Write-InstallVerbose
    }

    $result = & $FilePath @argsArray 2>&1

    if ($Script:InstallVerboseEnabled -and $result) {
        $result | Write-InstallVerbose
    }

    if ($CaptureOutput) {
        return $result
    }

    return $null
}

function Initialize-ExecutionSurface {
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    } catch {}

    if ($Script:InstallStopwatch) {
        $Script:InstallStopwatch.Reset()
        $Script:InstallStopwatch.Start()
    } else {
        $Script:InstallStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }
}

function Test-IsAdmin {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Reload-EnvironmentPath {
    try {
        $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $user = [Environment]::GetEnvironmentVariable('Path', 'User')
        $segments = @($machine, $user) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $env:Path = [string]::Join(';', $segments)
    } catch {}
}

function New-InstallContext {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Profile
    )

    return [pscustomobject]@{
        Profile     = $Profile
        StepResults = @()
        ExitCode    = 0
        Halted      = $false
        Stopwatch   = $Script:InstallStopwatch
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context,
        [Parameter(Mandatory = $true)][pscustomobject]$Step
    )

    if ($Context.Halted) {
        return
    }

    Write-InstallStatus -Status 'Info' -Message ("Starting: {0}" -f $Step.Name) -Indent ''

    $result = $null
    try {
        $result = & $Step.Script $Context
    } catch {
        $result = New-ActionResult -Success:$false -Status 'Error' -Message ("{0} failed: {1}" -f $Step.Name, $_) -Data @{ Exception = $_ }
    }

    if (-not $result) {
        $result = New-ActionResult -Success:$false -Status 'Error' -Message ("{0} returned no result." -f $Step.Name)
    }

    Write-InstallStatus -Status $result.Status -Message ("{0}: {1}" -f $Step.Name, $result.Message) -Indent ''

    $Context.StepResults += [pscustomobject]@{
        Name   = $Step.Name
        Result = $result
    }

    if (-not $result.Success) {
        $exitCode = 1
        if ($result.Data -and $result.Data.ExitCode) {
            $exitCode = [int]$result.Data.ExitCode
        }
        if ($exitCode -gt $Context.ExitCode) {
            $Context.ExitCode = $exitCode
        }

        $allowContinue = $false
        if ($result.Data -and $result.Data.AllowContinue) {
            $allowContinue = $true
        }

        if (-not $allowContinue) {
            $Context.Halted = $true
        }
    }
}

function Get-StepResult {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context,
        [Parameter(Mandatory = $true)][string]$StepName
    )

    return $Context.StepResults | Where-Object { $_.Name -eq $StepName } | Select-Object -Last 1
}

function Complete-Install {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $elapsedText = $null
    if ($Context.Stopwatch) {
        if ($Context.Stopwatch.IsRunning) {
            $Context.Stopwatch.Stop()
        }
        $elapsedText = "{0:N1} seconds" -f $Context.Stopwatch.Elapsed.TotalSeconds
    }

    switch ($Context.ExitCode) {
        0 {
            $message = 'Setup completed successfully.'
            if ($elapsedText) { $message = "${message} ($elapsedText)" }
            Write-InstallStatus -Status 'Success' -Message $message -Indent ''
        }
        2 {
            $message = 'Setup completed with warnings.'
            if ($elapsedText) { $message = "${message} ($elapsedText)" }
            Write-InstallStatus -Status 'Warning' -Message $message -Indent ''
        }
        default {
            $message = 'Setup failed.'
            if ($elapsedText) { $message = "${message} ($elapsedText)" }
            Write-InstallStatus -Status 'Error' -Message $message -Indent ''
        }
    }
}

function Invoke-ItemCollection {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context,
        [Parameter(Mandatory = $true)][string]$CollectionName,
        [Parameter()][object[]]$Items,
        [Parameter(Mandatory = $true)][scriptblock]$Handler,
        [switch]$TreatFailuresAsWarnings
    )

    if (-not $Items -or $Items.Count -eq 0) {
        return New-ActionResult -Success:$true -Status 'Skipped' -Message ("No {0} configured." -f $CollectionName)
    }

    $results = @()
    $failedItems = @()

    foreach ($item in $Items) {
        try {
            $itemResult = & $Handler $Context $item
        } catch {
            $itemResult = [pscustomobject]@{
                Name    = ($item | Out-String).Trim()
                Success = $false
                Action  = 'Error'
                Message = $_.Exception.Message
            }
        }

        if ($null -eq $itemResult) {
            continue
        }

        $results += $itemResult

        $action = if ($itemResult.Action) { $itemResult.Action } elseif ($itemResult.Success) { 'Success' } else { 'Error' }
        $message = $itemResult.Message
        if ($itemResult.Name) {
            $message = "{0}: {1}" -f $itemResult.Name, $message
        }

        Write-InstallStatus -Status $action -Message $message -Indent '    '

        if (-not $itemResult.Success) {
            $failedItems += $itemResult
        }
    }

    if ($failedItems.Count -eq 0) {
        return New-ActionResult -Success:$true -Status 'Success' -Message ("{0} processed successfully." -f $CollectionName) -Data @{ Items = $results }
    }

    $failedNames = ($failedItems | ForEach-Object { $_.Name } | Where-Object { $_ } | Sort-Object -Unique) -join ', '

    if ($TreatFailuresAsWarnings) {
        return New-ActionResult -Success:$true -Status 'Warning' -Message ("{0} completed with warnings for: {1}" -f $CollectionName, $failedNames) -Data @{
            Items    = $results
            Warnings = $failedItems
        }
    }

    return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("{0} failed for: {1}" -f $CollectionName, $failedNames) -Data @{
        Items  = $results
        Failed = $failedItems
    }
}

function Set-GitSshCommand {
    $whereSsh = $null
    try {
        $whereResult = Invoke-InstallCommand -FilePath 'where.exe' -Arguments @('ssh') -CaptureOutput
        if ($whereResult) {
            $whereSsh = $whereResult | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
        }
    } catch {}

    if (-not $whereSsh) {
        return New-ActionResult -Success:$true -Status 'Warning' -Message 'Unable to resolve ssh executable path via where.exe.'
    }

    $normalizedWhereSsh = $whereSsh.Trim().Replace('\', '/')

    $currentSshCommand = $null
    try {
        $currentOutput = Invoke-InstallCommand -FilePath 'git' -Arguments @('config', '--global', '--get', 'core.sshCommand') -CaptureOutput
        if ($currentOutput) {
            $currentSshCommand = ($currentOutput | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
        }
    } catch {}

    if (-not $currentSshCommand -or $currentSshCommand.Trim() -ne $normalizedWhereSsh) {
        try {
            Invoke-InstallCommand -FilePath 'git' -Arguments @('config', '--global', 'core.sshCommand', $normalizedWhereSsh) | Out-Null
            return New-ActionResult -Success:$true -Status 'Installed' -Message ("Git core.sshCommand updated to {0}." -f $normalizedWhereSsh)
        } catch {
            return New-ActionResult -Success:$true -Status 'Warning' -Message ("Unable to update git core.sshCommand: {0}" -f $_)
        }
    }

    return New-ActionResult -Success:$true -Status 'Skipped' -Message ("Git core.sshCommand already set to {0}." -f $normalizedWhereSsh)
}

# --- Helpers ----------------------------------------------------------------

function Get-WslExecutablePath {
    $cmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $fallback = Join-Path $env:WinDir 'System32\\wsl.exe'
    if (Test-Path $fallback) { return $fallback }
    return $null
}

function Get-WslDistributionMatches {
    param(
        [Parameter(Mandatory = $true)][string]$WslPath,
        [Parameter(Mandatory = $true)][string]$DistributionName
    )

    $collected = @()
    $commands = @(
        @('-l', '-q'),
        @('-l', '-v')
    )

    foreach ($args in $commands) {
        $output = $null
        try {
            $output = Invoke-InstallCommand -FilePath $WslPath -Arguments $args -CaptureOutput
        } catch {
            $output = $null
        }

        if ($output) {
            foreach ($line in $output) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $collected += $line.ToString()
            }
        }

        if ($collected.Count -gt 0) { break }
    }

    if ($collected.Count -eq 0) { return @() }

    $needle = $DistributionName.Trim().ToLowerInvariant()
    $found = @()

    foreach ($raw in $collected) {
        if (-not $raw) { continue }
        $text = $raw.Trim()
        if (-not $text) { continue }

        $normalized = ($text -replace '\s*\(Default\)', '')
        $normalized = ($normalized -replace '\s*\(Running\)', '')
        $normalized = ($normalized -replace '\s*\(Stopped\)', '')
        $normalized = ($normalized -replace '\s*\(Installing\)', '')
        $normalized = ($normalized -replace '\s*\(Unregistering\)', '')
        $normalized = $normalized.Trim()

        if ($normalized.StartsWith('*')) {
            $normalized = $normalized.TrimStart('*').Trim()
        }

        $token = [regex]::Match($normalized, '^[^\s]+')
        $candidate = if ($token.Success) { $token.Value } else { $normalized }
        if (-not $candidate) { continue }

        $candidateLower = $candidate.ToLowerInvariant()
        if ($candidateLower -eq 'name') { continue }
        if ($candidateLower -eq $needle -or $candidateLower.StartsWith("$needle-")) {
            $found += $candidate
            continue
        }

        if ($normalized.ToLowerInvariant().StartsWith($needle)) {
            $found += $normalized
        }
    }

    return $found | Sort-Object -Unique
}

function Ensure-OpenSshAgent {
    try {
        $service = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
        if (-not $service) {
            return New-ActionResult -Success:$false -Status 'Missing' -Message 'ssh-agent service not found. Ensure another agent is running.'
        }

        if ($service.Status -ne 'Running') {
            Set-Service -Name ssh-agent -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name ssh-agent -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            $service.Refresh()
        }

        $status = if ($service.Status -eq 'Running') { 'Running' } else { 'Started' }
        return New-ActionResult -Success:$true -Status $status -Message 'ssh-agent service is running.'
    } catch {
        return New-ActionResult -Success:$false -Status 'Warning' -Message ("Failed to ensure ssh-agent service: {0}" -f $_)
    }
}

function Generate-And-Register-SshKey {
    param(
        [string]$BaseName = 'toolbox_key',
        [switch]$ForceNew
    )

    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir | Out-Null
        try { Invoke-InstallCommand -FilePath 'icacls' -Arguments @($sshDir, '/inheritance:r') | Out-Null } catch {}
    }

    $initialKeyPath = Join-Path $sshDir $BaseName
    if ((Test-Path $initialKeyPath) -and -not $ForceNew) {
        $existingPub = "$initialKeyPath.pub"
        if (Test-Path $existingPub) {
            $data = @{
                Name         = (Split-Path $initialKeyPath -Leaf)
                Private      = $initialKeyPath
                Public       = $existingPub
                Generated    = $false
                AddedToAgent = $false
            }
            return New-ActionResult -Success:$true -Status 'Skipped' -Message 'Existing SSH key reused.' -Data $data
        }

        Write-InstallStatus -Status 'Warning' -Message ("Existing key found at {0} but public key is missing. Regenerating." -f $initialKeyPath)
    }

    $keyPath = $initialKeyPath
    if (Test-Path $keyPath) {
        $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
        $keyPath = Join-Path $sshDir ("{0}_{1}" -f $BaseName, $stamp)
        Write-InstallStatus -Status 'Info' -Message ("Generating new key with unique name: {0}" -f (Split-Path $keyPath -Leaf))
    }

    $sshKeygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $sshKeygen) {
        return New-ActionResult -Success:$false -Status 'Missing' -Message 'ssh-keygen not found. Ensure OpenSSH is installed.'
    }

    Write-InstallStatus -Status 'Running' -Message ("Generating SSH key at {0}" -f $keyPath)

    try {
        Invoke-InstallCommand -FilePath 'ssh-keygen' -Arguments @('-t', 'ed25519', '-f', $keyPath, '-C', $BaseName, '-N', '') | Out-Null
        if ($LASTEXITCODE -ne 0) {
            return New-ActionResult -Success:$false -Status 'Error' -Message ("ssh-keygen returned exit code {0}." -f $LASTEXITCODE)
        }
    } catch {
        return New-ActionResult -Success:$false -Status 'Error' -Message ("ssh-keygen failed: {0}" -f $_)
    }

    $pubPath = "$keyPath.pub"
    if (-not (Test-Path $pubPath)) {
        return New-ActionResult -Success:$false -Status 'Error' -Message 'Public key was not created as expected.'
    }

    $agentResult = Ensure-OpenSshAgent
    if ($agentResult) {
        Write-InstallStatus -Status $agentResult.Status -Message $agentResult.Message -Indent '    '
    }

    $addedToAgent = $false
    try {
        Invoke-InstallCommand -FilePath 'ssh-add' -Arguments @($keyPath) | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $addedToAgent = $true
            Write-InstallStatus -Status 'Installed' -Message 'New key added to ssh-agent.' -Indent '    '
        } else {
            Write-InstallStatus -Status 'Warning' -Message ("ssh-add returned exit code {0}." -f $LASTEXITCODE) -Indent '    '
        }
    } catch {
        Write-InstallStatus -Status 'Warning' -Message ("ssh-add failed: {0}" -f $_) -Indent '    '
    }

    $data = @{
        Name         = (Split-Path $keyPath -Leaf)
        Private      = $keyPath
        Public       = $pubPath
        Generated    = $true
        AddedToAgent = $addedToAgent
        AgentResult  = $agentResult
    }

    return New-ActionResult -Success:$true -Status 'Generated' -Message 'New SSH key generated.' -Data $data
}

function Install-ChocoPackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackageName
    )

    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            Name    = $PackageName
            Success = $false
            Action  = 'MissingChoco'
            Message = 'Chocolatey is not available; cannot install package.'
        }
    }

    Write-InstallStatus -Status 'Info' -Message ("Checking Chocolatey package: {0}" -f $PackageName) -Indent '    '

    $installed = $false
    try {
        $listOutput = Invoke-InstallCommand -FilePath 'choco' -Arguments @('list', '--local-only', '--exact', $PackageName, '--limit-output') -CaptureOutput
        $result = $listOutput | ForEach-Object { $_.Trim() }
        if ($result -and ($result -match "^$([Regex]::Escape($PackageName))\|")) {
            $installed = $true
        }
    } catch {
        Write-InstallStatus -Status 'Warning' -Message ("Unable to determine installation state for {0}: {1}" -f $PackageName, $_) -Indent '    '
    }

    if ($installed) {
        return [pscustomobject]@{
            Name    = $PackageName
            Success = $true
            Action  = 'Skipped'
            Message = 'Package already installed.'
        }
    }

    Write-InstallStatus -Status 'Running' -Message ("Installing {0} via Chocolatey..." -f $PackageName) -Indent '    '

    try {
        Invoke-InstallCommand -FilePath 'choco' -Arguments @('install', $PackageName, '-y', '--no-progress') | Out-Null
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{
                Name    = $PackageName
                Success = $false
                Action  = 'InstallFailed'
                Message = "Chocolatey returned exit code $LASTEXITCODE."
            }
        }
    } catch {
        return [pscustomobject]@{
            Name    = $PackageName
            Success = $false
            Action  = 'InstallFailed'
            Message = "Failed to install package: $_"
        }
    }

    Reload-EnvironmentPath

    return [pscustomobject]@{
        Name    = $PackageName
        Success = $true
        Action  = 'Installed'
        Message = 'Package installed successfully.'
    }
}

function Install-StoreApp {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Application
    )

    $id = $Application.Id
    if ([string]::IsNullOrWhiteSpace($id)) {
        return [pscustomobject]@{
            Name    = '(unknown)'
            Success = $false
            Action  = 'Error'
            Message = 'Application Id is required.'
        }
    }

    $displayName = if ($Application.DisplayName) { $Application.DisplayName } else { $id }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            Name    = $displayName
            Success = $false
            Action  = 'MissingWinget'
            Message = 'winget command not found; install the App Installer from the Microsoft Store.'
        }
    }

    Write-InstallStatus -Status 'Info' -Message ("Checking Microsoft Store application: {0}" -f $displayName) -Indent '    '

    $testInstalled = {
        param(
            [string]$AppxPackageName,
            [string]$PackageFamilyName,
            [string]$Id
        )

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
            $listResult = Invoke-InstallCommand -FilePath 'winget' -Arguments @('list', '--id', $Id, '--exact', '--accept-source-agreements') -CaptureOutput
            if ($listResult -and ($listResult | Where-Object { $_ -match [Regex]::Escape($Id) })) { return $true }
        } catch {}

        return $false
    }

    if (& $testInstalled $Application.AppxPackageName $Application.PackageFamilyName $id) {
        return [pscustomobject]@{
            Name    = $displayName
            Success = $true
            Action  = 'Skipped'
            Message = 'Application already installed.'
        }
    }

    Write-InstallStatus -Status 'Running' -Message ("Installing {0} via winget..." -f $displayName) -Indent '    '

    $installExit = $null
    $installError = $null
    try {
        Invoke-InstallCommand -FilePath 'winget' -Arguments @('install', '--id', $id, '--exact', '--accept-package-agreements', '--accept-source-agreements') | Out-Null
        $installExit = $LASTEXITCODE
    } catch {
        $installError = $_
        $installExit = $LASTEXITCODE
    }

    if ($installExit -eq 0) {
        return [pscustomobject]@{
            Name    = $displayName
            Success = $true
            Action  = 'Installed'
            Message = 'Application installed successfully.'
        }
    }

    if (& $testInstalled $Application.AppxPackageName $Application.PackageFamilyName $id) {
        return [pscustomobject]@{
            Name    = $displayName
            Success = $true
            Action  = 'Skipped'
            Message = "Application already installed (winget exit code $installExit)."
        }
    }

    $errorMessage = if ($installError) { "winget failed: $installError" } else { "winget returned exit code $installExit." }
    return [pscustomobject]@{
        Name    = $displayName
        Success = $false
        Action  = 'InstallFailed'
        Message = $errorMessage
    }
}

# --- Steps ------------------------------------------------------------------

function Step-EnsureWsl {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $wslPath = Get-WslExecutablePath
    if (-not $wslPath) {
        return New-ActionResult -Success:$false -Status 'Missing' -Message 'wsl.exe not found. Windows Subsystem for Linux is required.'
    }

    $ready = $false
    $installed = $false
    try {
        Invoke-InstallCommand -FilePath $wslPath -Arguments @('-l', '-q') | Out-Null
        $ready = ($LASTEXITCODE -eq 0)
    } catch {
        $ready = $false
    }

    if (-not $ready) {
        Write-InstallStatus -Status 'Info' -Message 'WSL not initialized. Installing WSL...'
        try {
            Invoke-InstallCommand -FilePath $wslPath -Arguments @('--install') | Out-Null
            if ($LASTEXITCODE -ne 0) {
                return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("WSL install exited with code {0}." -f $LASTEXITCODE)
            }
            $installed = $true
        } catch {
            return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("WSL installation failed: {0}" -f $_)
        }

        Start-Sleep -Seconds 5
        try {
            Invoke-InstallCommand -FilePath $wslPath -Arguments @('-l', '-q') | Out-Null
            $ready = ($LASTEXITCODE -eq 0)
        } catch {
            return New-ActionResult -Success:$false -Status 'Unavailable' -Message 'wsl.exe is unavailable after installation; a reboot may be required.'
        }
    }

    try {
        Invoke-InstallCommand -FilePath $wslPath -Arguments @('--set-default-version', '2') | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-InstallStatus -Status 'Warning' -Message ("Unable to set WSL default version to 2 (exit {0})." -f $LASTEXITCODE)
        } else {
            Write-InstallStatus -Status 'Success' -Message 'WSL default version set to 2.'
        }
    } catch {
        Write-InstallStatus -Status 'Warning' -Message ("Failed to set WSL default version: {0}" -f $_)
    }

    if ($installed) {
        return New-ActionResult -Success:$true -Status 'Installed' -Message 'WSL installation completed successfully.'
    }

    return New-ActionResult -Success:$true -Status 'Skipped' -Message 'WSL already installed; skipping setup.'
}

function Step-EnsureUbuntu {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $distributionName = if ($Context.Profile.WslDistribution) { $Context.Profile.WslDistribution } else { 'Ubuntu' }

    $wslPath = Get-WslExecutablePath
    if (-not $wslPath) {
        return New-ActionResult -Success:$false -Status 'Missing' -Message 'Cannot manage WSL distributions because wsl.exe is unavailable.'
    }

    $existingMatches = Get-WslDistributionMatches -WslPath $wslPath -DistributionName $distributionName
    if ($existingMatches.Count -gt 0) {
        return New-ActionResult -Success:$true -Status 'Skipped' -Message ("{0} distribution already present: {1}" -f $distributionName, ($existingMatches -join ', '))
    }

    Write-InstallStatus -Status 'Info' -Message ("Installing WSL distribution '{0}'..." -f $distributionName)
    try {
        Invoke-InstallCommand -FilePath $wslPath -Arguments @('--install', '-d', $distributionName) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("WSL distribution install exited with code {0}." -f $LASTEXITCODE)
        }
    } catch {
        return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("Failed to install '{0}': {1}" -f $distributionName, $_)
    }

    Start-Sleep -Seconds 5

    $postInstallMatches = Get-WslDistributionMatches -WslPath $wslPath -DistributionName $distributionName
    if ($postInstallMatches.Count -gt 0) {
        return New-ActionResult -Success:$true -Status 'Installed' -Message ("WSL distribution '{0}' installed as: {1}" -f $distributionName, ($postInstallMatches -join ', '))
    }

    return New-ActionResult -Success:$false -Status 'Pending' -Message ("WSL reports that '{0}' is not available yet. Complete any reboot prompts and try again." -f $distributionName)
}

function Step-EnsureChocolatey {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $existing = Get-Command choco -ErrorAction SilentlyContinue
    if ($existing) {
        return New-ActionResult -Success:$true -Status 'Skipped' -Message ("Chocolatey already available at {0}" -f $existing.Source)
    }

    Write-InstallStatus -Status 'Info' -Message 'Chocolatey not found. Installing Chocolatey...'

    $installScript = {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }

    try {
        Invoke-InstallCommand -FilePath 'powershell' -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $installScript) | Out-Null
    } catch {
        return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("Chocolatey installation failed: {0}" -f $_)
    }

    Reload-EnvironmentPath
    Start-Sleep -Seconds 2

    if (Get-Command choco -ErrorAction SilentlyContinue) {
        return New-ActionResult -Success:$true -Status 'Installed' -Message 'Chocolatey installed successfully.'
    }

    return New-ActionResult -Success:$false -Status 'InstallFailed' -Message "Chocolatey installation completed but 'choco' is unavailable."
}

function Step-EnsureGit {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $existingGit = Get-Command git -ErrorAction SilentlyContinue
    if ($existingGit) {
        return New-ActionResult -Success:$true -Status 'Skipped' -Message ("Git already available at {0}" -f $existingGit.Source)
    }

    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        return New-ActionResult -Success:$false -Status 'MissingChoco' -Message 'Chocolatey is not available; cannot install git.'
    }

    Write-InstallStatus -Status 'Info' -Message 'Git not found. Installing via Chocolatey...'
    try {
        Invoke-InstallCommand -FilePath 'choco' -Arguments @('install', 'git', '-y', '--no-progress') | Out-Null
        if ($LASTEXITCODE -ne 0) {
            return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("Git installation exited with code {0}." -f $LASTEXITCODE)
        }
    } catch {
        return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("Failed to install git via choco: {0}" -f $_)
    }

    Reload-EnvironmentPath
    Start-Sleep -Seconds 2
    $existingGit = Get-Command git -ErrorAction SilentlyContinue
    if ($existingGit) {
        return New-ActionResult -Success:$true -Status 'Installed' -Message 'Git installed and available.'
    }

    return New-ActionResult -Success:$false -Status 'InstallFailed' -Message "Git installation finished but 'git' is unavailable."
}

function Step-InstallChocolateyPackages {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $result = Invoke-ItemCollection -Context $Context -CollectionName 'Chocolatey packages' -Items $Context.Profile.ChocolateyPackages -Handler {
        param($ctx, $packageName)
        Install-ChocoPackage -PackageName $packageName
    }

    if (-not $result.Success) {
        $data = @{}
        if ($result.Data) {
            foreach ($key in $result.Data.Keys) {
                $data[$key] = $result.Data[$key]
            }
        }
        $data.ExitCode = 2
        $data.AllowContinue = $true
        return New-ActionResult -Success:$false -Status $result.Status -Message $result.Message -Data $data
    }

    return $result
}

function Step-SetChromeAsDefault {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $candidatePaths = @()
    $candidateRoots = @(
        [Environment]::GetEnvironmentVariable('ProgramFiles')
        [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    ) | Where-Object { $_ }

    foreach ($root in ($candidateRoots | Select-Object -Unique)) {
        $candidatePaths += (Join-Path $root 'Google\Chrome\Application\chrome.exe')
    }

    $chromePath = $null
    foreach ($path in $candidatePaths) {
        if ($path -and (Test-Path $path)) {
            $chromePath = $path
            break
        }
    }

    if (-not $chromePath) {
        $chromeCommand = Get-Command chrome -ErrorAction SilentlyContinue
        if ($chromeCommand -and $chromeCommand.Source) {
            $chromePath = $chromeCommand.Source
        }
    }

    if (-not $chromePath -or -not (Test-Path $chromePath)) {
        return New-ActionResult -Success:$false -Status 'Missing' -Message 'Google Chrome executable not found; ensure installation succeeded.'
    }

    Write-InstallStatus -Status 'Running' -Message ("Setting Google Chrome as the default browser via {0}" -f $chromePath) -Indent '    '

    try {
        if ($Script:InstallVerboseEnabled) {
            (Format-InstallCommandLine -Executable $chromePath -Arguments @('--make-default-browser', '--no-first-run', '--no-default-browser-check')) | Write-InstallVerbose
        }
        $process = Start-Process -FilePath $chromePath -ArgumentList '--make-default-browser','--no-first-run','--no-default-browser-check' -WindowStyle Hidden -PassThru -ErrorAction Stop
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    } catch {
        return New-ActionResult -Success:$false -Status 'Error' -Message ("Failed to run Chrome to set default browser: {0}" -f $_)
    }

    if ($exitCode -ne 0) {
        return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("Chrome exited with code {0} while setting the default browser." -f $exitCode)
    }

    $associationTargets = @(
        @{ Name = 'http';  Path = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' }
        @{ Name = 'https'; Path = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' }
        @{ Name = '.htm';  Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\UserChoice' }
        @{ Name = '.html'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice' }
    )

    $nonChromeAssociations = @()

    foreach ($target in $associationTargets) {
        try {
            $association = Get-ItemProperty -Path $target.Path -Name ProgId -ErrorAction Stop
            if ($association.ProgId -ne 'ChromeHTML') {
                $nonChromeAssociations += [pscustomobject]@{
                    Target = $target.Name
                    ProgId = $association.ProgId
                }
            }
        } catch {
            $nonChromeAssociations += [pscustomobject]@{
                Target = $target.Name
                ProgId = '(unavailable)'
                Error  = $_.Exception.Message
            }
        }
    }

    if ($nonChromeAssociations.Count -eq 0) {
        Write-InstallStatus -Status 'Success' -Message 'Chrome confirmed as the default handler for http/https/html.' -Indent '    '
        return New-ActionResult -Success:$true -Status 'Installed' -Message 'Google Chrome set as the default browser.'
    }

    $details = $nonChromeAssociations | ForEach-Object {
        $progId = if ($_.ProgId) { $_.ProgId } else { 'unknown' }
        "{0} -> {1}" -f $_.Target, $progId
    }

    foreach ($entry in $nonChromeAssociations) {
        $progId = if ($entry.ProgId) { $entry.ProgId } else { 'unknown' }
        Write-InstallStatus -Status 'Warning' -Message ("{0} remains associated with {1}." -f $entry.Target, $progId) -Indent '    '
    }

    $data = @{
        AllowContinue = $true
        ExitCode      = 2
        Associations  = $nonChromeAssociations
    }

    return New-ActionResult -Success:$false -Status 'Warning' -Message ("Chrome attempted to set defaults, but these remain non-Chrome: {0}" -f ($details -join '; ')) -Data $data
}

function Step-InstallStoreApps {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    return Invoke-ItemCollection -Context $Context -CollectionName 'Microsoft Store applications' -Items $Context.Profile.StoreApps -Handler {
        param($ctx, $application)
        Install-StoreApp -Application $application
    } -TreatFailuresAsWarnings
}

function Step-SetupSsh {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $sshOptions = $Context.Profile.Ssh
    $baseName = if ($sshOptions.BaseName) { $sshOptions.BaseName } else { 'toolbox_key' }

    $keyResult = Generate-And-Register-SshKey -BaseName $baseName -ForceNew:$sshOptions.ForceNew
    if (-not $keyResult) {
        return New-ActionResult -Success:$false -Status 'Error' -Message 'SSH key generation returned no result.'
    }

    if (-not $keyResult.Success) {
        return $keyResult
    }

    if ($keyResult.Data.Generated) {
        Write-Host ''
        Write-Host '--- PUBLIC KEY ---'
        try {
            $pubKey = Get-Content $keyResult.Data.Public -Raw
            Write-Host $pubKey
        } catch {
            Write-InstallStatus -Status 'Warning' -Message ("Unable to read public key for display: {0}" -f $_) -Indent '    '
        }
        Write-Host '--- END PUBLIC KEY ---'
        Write-Host ''
        Write-Host 'Next steps to add this key to GitHub:'
        Write-Host '  1. Open https://github.com -> Settings -> SSH and GPG keys -> New SSH key'
        Write-Host ("  2. Use a title such as {0}" -f $keyResult.Data.Name)
        Write-Host '  3. Paste the public key that was printed above.'
        Write-Host ''
        Write-Host 'Optional: after adding the key, test the connection with:'
        Write-Host '  ssh -T git@github.com'

        if (-not $keyResult.Data.AddedToAgent) {
            Write-InstallStatus -Status 'Warning' -Message 'Generated key could not be added to ssh-agent; you may need to add it manually.' -Indent '    '
        }
    } else {
        Write-InstallStatus -Status 'Skipped' -Message ("SSH key reused from {0}; public key not displayed." -f $keyResult.Data.Private) -Indent '    '
    }

    try {
        Remove-Item Env:\GIT_SSH -ErrorAction SilentlyContinue
        Remove-Item Env:\GIT_SSH_COMMAND -ErrorAction SilentlyContinue
    } catch {}

    $gitSshResult = Set-GitSshCommand
    if ($gitSshResult) {
        Write-InstallStatus -Status $gitSshResult.Status -Message $gitSshResult.Message -Indent '    '
    }

    if ($gitSshResult -and -not $gitSshResult.Success) {
        return New-ActionResult -Success:$false -Status $gitSshResult.Status -Message ("SSH key ready, but {0}" -f $gitSshResult.Message) -Data $keyResult.Data
    }

    $message = if ($keyResult.Data.Generated) { 'SSH key generation completed.' } else { 'Existing SSH key confirmed.' }
    return New-ActionResult -Success:$true -Status $keyResult.Status -Message $message -Data $keyResult.Data
}

function Step-EnsureLocalRepository {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context
    )

    $repoOptions = $Context.Profile.LocalRepository
    $repoPath = if ($repoOptions -and $repoOptions.Path) { $repoOptions.Path } else { 'C:\localrepo\toolbox' }
    $gitUrl = if ($repoOptions -and $repoOptions.GitUrl) { $repoOptions.GitUrl } else { 'git@github.com:MBijron/toolbox.git' }

    if (Test-Path $repoPath) {
        return New-ActionResult -Success:$true -Status 'Skipped' -Message ("Repository already exists at {0}." -f $repoPath)
    }

    $parentDir = Split-Path -Parent $repoPath
    if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path $parentDir)) {
        try {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        } catch {
            return New-ActionResult -Success:$false -Status 'Error' -Message ("Failed to create directory {0}: {1}" -f $parentDir, $_)
        }
    }

    $sshStep = Get-StepResult -Context $Context -StepName 'Configure SSH access'
    $publicKeyPath = $null
    if ($sshStep -and $sshStep.Result -and $sshStep.Result.Data) {
        $publicKeyPath = $sshStep.Result.Data.Public
    }

    if ($publicKeyPath -and (Test-Path $publicKeyPath)) {
        Write-Host ''
        Write-Host '--- PUBLIC KEY ---'
        try {
            $publicKeyContent = Get-Content -Path $publicKeyPath -Raw
            Write-Host $publicKeyContent
        } catch {
            Write-InstallStatus -Status 'Warning' -Message ("Unable to display public key: {0}" -f $_)
        }
        Write-Host '--- END PUBLIC KEY ---'
        Write-Host ''
    } else {
        Write-InstallStatus -Status 'Warning' -Message 'Public key file not found; ensure it has been generated.'
    }

    while ($true) {
        $response = Read-Host 'Have you added this SSH key to your GitHub account? Enter Y to continue'
        if ($response -eq 'Y' -or $response -eq 'y') {
            break
        }

        Write-InstallStatus -Status 'Warning' -Message 'Add the SSH key to your GitHub account, then enter Y to continue.'
    }

    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCommand) {
        return New-ActionResult -Success:$false -Status 'Missing' -Message 'Git is required to clone the repository.'
    }

    Write-InstallStatus -Status 'Running' -Message ("Cloning repository from {0} to {1}" -f $gitUrl, $repoPath)

    $exitCode = 0
    try {
        Invoke-InstallCommand -FilePath 'git' -Arguments @('clone', $gitUrl, $repoPath) | Out-Null
        $exitCode = $LASTEXITCODE
    } catch {
        return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("git clone failed: {0}" -f $_)
    }

    if ($exitCode -eq 0) {
        return New-ActionResult -Success:$true -Status 'Installed' -Message 'Repository cloned successfully.'
    }

    return New-ActionResult -Success:$false -Status 'InstallFailed' -Message ("git clone exited with code {0}." -f $exitCode)
}

# --- Profile ---------------------------------------------------------------

function New-InstallProfile {
    param(
        [switch]$ForceNewSshKey,
        [switch]$NoGit
    )

    $chocolateyPackages = @(
        'launchy'
        'notepadplusplus'
        'signal'
        'vscode-insiders'
        'googlechrome'
        'ffmpeg'
        'powershell-core'
        'everything'
    )

    $storeApps = @(
        [pscustomobject]@{
            Id                = 'WhatsApp.WhatsApp'
            DisplayName       = 'WhatsApp Messenger'
            AppxPackageName   = '5319275A.WhatsAppDesktop'
            PackageFamilyName = $null
        }
    )

    $localRepository = [pscustomobject]@{
        Path   = 'C:\localrepo\toolbox'
        GitUrl = 'git@github.com:MBijron/toolbox.git'
    }

    $steps = @(
        [pscustomobject]@{ Name = 'Ensure WSL availability';      Script = { param($Context) Step-EnsureWsl -Context $Context } },
        [pscustomobject]@{ Name = 'Ensure Ubuntu distribution';   Script = { param($Context) Step-EnsureUbuntu -Context $Context } },
        [pscustomobject]@{ Name = 'Ensure Chocolatey';            Script = { param($Context) Step-EnsureChocolatey -Context $Context } }
        [pscustomobject]@{ Name = 'Install Chocolatey packages';  Script = { param($Context) Step-InstallChocolateyPackages -Context $Context } },
        [pscustomobject]@{ Name = 'Set Chrome as default browser'; Script = { param($Context) Step-SetChromeAsDefault -Context $Context } },
        [pscustomobject]@{ Name = 'Install Microsoft Store apps'; Script = { param($Context) Step-InstallStoreApps -Context $Context } }
    )

    if (-not $NoGit) {
        $steps += @(
            [pscustomobject]@{ Name = 'Ensure Git availability'; Script = { param($Context) Step-EnsureGit -Context $Context } }
            [pscustomobject]@{ Name = 'Configure SSH access';      Script = { param($Context) Step-SetupSsh -Context $Context } },
            [pscustomobject]@{ Name = 'Ensure toolbox repository'; Script = { param($Context) Step-EnsureLocalRepository -Context $Context } }
        )
    } else {
        $steps += [pscustomobject]@{
            Name   = 'Skip git/ssh setup'
            Script = {
                param($Context)
                Write-InstallStatus -Status 'Skipped' -Message 'Git, SSH, and repository steps skipped (--no-git).' -Indent ''
                return New-ActionResult -Success:$true -Status 'Skipped' -Message 'Git and SSH setup skipped.' -Data @{ AllowContinue = $true }
            }
        }
    }

    return [pscustomobject]@{
        ChocolateyPackages = $chocolateyPackages
        StoreApps          = $storeApps
        WslDistribution    = 'Ubuntu'
        Ssh                = [pscustomobject]@{
            BaseName = 'toolbox_key'
            ForceNew = [bool]$ForceNewSshKey
            Enabled  = (-not $NoGit)
        }
        LocalRepository    = $localRepository
        Steps              = $steps
    }
}

# --- Main ------------------------------------------------------------------

Initialize-ExecutionSurface

if (-not (Test-IsAdmin)) {
    Write-Error 'Run this script from an elevated PowerShell session.'
    exit 1
}

$profile = New-InstallProfile -ForceNewSshKey:$ForceNewSshKey -NoGit:$NoGit
$context = New-InstallContext -Profile $profile

Write-InstallStatus -Status 'Info' -Message 'Starting setup workflow.' -Indent ''

if ($Script:InstallVerboseEnabled) {
    Write-InstallStatus -Status 'Info' -Message 'Verbose command output enabled.' -Indent ''
}

foreach ($step in $profile.Steps) {
    Invoke-Step -Context $context -Step $step
    if ($context.Halted) { break }
}

Complete-Install -Context $context
exit $context.ExitCode
