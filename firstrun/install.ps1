# setup_choco_git_ssh.ps1
# Creates/ensures Chocolatey and Git are installed, generates an SSH key (toolbox_key),
# registers it with the OpenSSH agent and copies the public key to the clipboard.
# Run in PowerShell. Some steps may prompt for elevation (UAC).

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Reload-EnvironmentPath {
    # Reload Path from registry (Machine + User) into current process so newly-installed tools are found.
    try {
        $machine = [Environment]::GetEnvironmentVariable('Path','Machine')
        $user = [Environment]::GetEnvironmentVariable('Path','User')
        if ($machine -and $user) {
            $env:Path = $machine + ';' + $user
        } elseif ($machine) {
            $env:Path = $machine
        } elseif ($user) {
            $env:Path = $user
        }
    } catch {
        Write-Warning "Failed to reload PATH from registry: $_"
    }
}

function Ensure-Chocolatey {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Output "Chocolatey already installed: $(Get-Command choco | Select-Object -ExpandProperty Source)"
        return $true
    }

    Write-Output "Chocolatey not found. Installing Chocolatey..."

    $installScript = {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }

    if (Test-IsAdmin) {
        try {
            & powershell -NoProfile -ExecutionPolicy Bypass -Command $installScript
        } catch {
            Write-Error "Chocolatey installation failed: $_"
            return $false
        }
    } else {
        Write-Output "Requesting elevation to install Chocolatey..."
        $scriptBlock = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
        Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $scriptBlock" -Verb RunAs -Wait
    }

    # After installation, reload PATH and check again
    Reload-EnvironmentPath
    Start-Sleep -Seconds 2
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Output "Chocolatey installed successfully."
        return $true
    } else {
        Write-Error "Chocolatey installation completed but 'choco' command not found in this session. You may need to start a new shell."
        return $false
    }
}

function Ensure-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Output "Git already available: $(Get-Command git | Select-Object -ExpandProperty Source)"
        return $true
    }

    Write-Output "Git not found. Installing git via Chocolatey..."

    $chocoCmd = "choco install git -y --no-progress"

    if (Test-IsAdmin) {
        try {
            iex $chocoCmd
        } catch {
            Write-Error "Failed to install git via choco: $_"
            return $false
        }
    } else {
        # Elevate to install git
        Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $chocoCmd" -Verb RunAs -Wait
    }

    # Reload PATH and verify
    Reload-EnvironmentPath
    Start-Sleep -Seconds 2
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Output "Git installed and available."
        return $true
    } else {
        Write-Error "Git installation finished but 'git' command not found in this session. Try opening a new shell."
        return $false
    }
}

function Ensure-OpenSshAgent {
    # Ensure the OpenSSH Authentication Agent service exists and is running (Windows 10/11 modern behavior).
    try {
        $svc = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            Write-Warning "ssh-agent service not found. If you have a different SSH agent, please ensure it is running."
            return $false
        }

        if ($svc.Status -ne 'Running') {
            Set-Service -Name ssh-agent -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name ssh-agent -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }
        Write-Output "ssh-agent service is running."
        return $true
    } catch {
        Write-Warning "Failed to ensure ssh-agent service: $_"
        return $false
    }
}

function Generate-And-Register-SshKey {
    param(
        [string] $BaseName = 'toolbox_key'
    )

    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir | Out-Null
        # Make sure directory has correct permissions (user only)
        try { icacls $sshDir /inheritance:r | Out-Null } catch { }
    }

    $keyPath = Join-Path $sshDir $BaseName
    if (Test-Path $keyPath) {
        $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
        $keyPath = Join-Path $sshDir ("${BaseName}_${stamp}")
        Write-Output "Key name already existed. New key will be: $(Split-Path $keyPath -Leaf)"
    }

    $sshKeygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $sshKeygen) {
        Write-Error "ssh-keygen not found. Ensure OpenSSH is installed (Windows optional feature or included with Git for Windows)."
        return $null
    }

    # Generate ED25519 key without passphrase
    $genArgs = "-t ed25519 -f `"$keyPath`" -C `"$BaseName`" -N `"`""
    Write-Output "Generating SSH key: $keyPath"
    & ssh-keygen $genArgs

    $pubPath = "$keyPath.pub"
    if (-not (Test-Path $pubPath)) {
        Write-Error "Public key was not created as expected."
        return $null
    }

    # Ensure ssh-agent is running and add the key
    Ensure-OpenSshAgent | Out-Null
    try {
        # Add key to agent
        & ssh-add $keyPath | Out-Null
    } catch {
        Write-Warning "ssh-add failed: $_"
    }

    return @{ Private = $keyPath; Public = $pubPath }
}

# ---- Main ----
Write-Output "Starting setup: Chocolatey, Git, SSH key and ssh-agent registration..."

# Ensure Chocolatey
$chocoOk = Ensure-Chocolatey
Reload-EnvironmentPath

# Ensure Git
$gitOk = Ensure-Git
Reload-EnvironmentPath

# Generate SSH key and register with agent
$keyInfo = Generate-And-Register-SshKey -BaseName 'toolbox_key'

if ($null -eq $keyInfo) {
    Write-Error "SSH key generation/registration failed. Aborting final steps."
    exit 1
}

# Make sure Git will use the system ssh (not plink or a custom GIT_SSH)
try {
    Remove-Item Env:\GIT_SSH -ErrorAction SilentlyContinue
    Remove-Item Env:\GIT_SSH_COMMAND -ErrorAction SilentlyContinue
} catch { }

# Force git to use 'ssh' program (this sets a global config; user can change later)
try {
    git config --global core.sshCommand "ssh" 2>$null
} catch { }

# Show keys in agent
try {
    $agentList = & ssh-add -l 2>$null
    if ($agentList) { Write-Output "ssh-agent identities:\n$agentList" } else { Write-Output "ssh-agent has no public identities listed (or ssh-add -l not supported)." }
} catch { Write-Warning "Could not list ssh-agent identities: $_" }

# Read public key and copy to clipboard
$pubKey = Get-Content $keyInfo.Public -Raw
Write-Output "\n--- PUBLIC KEY (also copied to clipboard) ---\n"
Write-Output $pubKey

# Copy to clipboard (use Set-Clipboard if available, fallback to clip.exe)
if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
    $pubKey | Set-Clipboard
} else {
    $pubKey | clip
}

Write-Output "\nPublic key copied to clipboard."

# Print next steps for user
Write-Output "\nNext steps to add this key to GitHub:"
Write-Output "  1. Open https://github.com -> Settings -> SSH and GPG keys -> New SSH key"
Write-Output "  2. Give it a Title like: toolbox_key (or the filename shown above)"
Write-Output "  3. Paste the public key that was printed above and saved to your clipboard."
Write-Output "\nTo test your key with GitHub, run:"
Write-Output "  ssh -T git@github.com"
Write-Output "\nIf you run into 'permission denied' errors, ensure the key is present in the ssh-agent (ssh-add -l) and that GitHub has the correct public key."

Write-Output "\nAll done."
