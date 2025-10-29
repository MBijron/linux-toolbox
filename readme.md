# Install Script

For a first-time install run:

```powershell
iex ((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MBijron/linux-toolbox/main/powershell/install.ps1').Content)
```

With flags

```powershell
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
$tmp = "$env:TEMP\install.ps1"
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MBijron/linux-toolbox/main/powershell/install.ps1' -OutFile $tmp
& $tmp --verbose
Remove-Item $tmp
```

OR in two lines:

```powershell
$script = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MBijron/linux-toolbox/main/powershell/install.ps1').Content
Invoke-Expression $script
```