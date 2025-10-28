# Install Script

For a first-time install run:

```powershell
iex ((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MBijron/linux-toolbox/main/powershell/install.ps1').Content)
```

OR in two lines:

```powershell
$script = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MBijron/linux-toolbox/main/powershell/install.ps1').Content
Invoke-Expression $script
```