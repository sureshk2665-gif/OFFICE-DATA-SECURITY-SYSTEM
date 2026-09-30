<#
  Office Computer Security System - setup and removal.

  Runs inside OfficeSecurity-Setup.exe (made by MAKE-SETUP.bat), which unpacks the program files next
  to this script and passes its arguments on (for example: OfficeSecurity-Setup.exe -Role Main -Quiet).
  Windows PowerShell 5.1 compatible (built into Windows 10 and 11).

  Interactive:   install.ps1                     (asks: main office computer or staff computer)
  Unattended:    install.ps1 -Role Main -Quiet
                 install.ps1 -Role Staff -Server 192.168.1.20 -PairingCode <code> -EnrollmentCode <code> -Quiet
  Remove:        install.ps1 -Uninstall [-UninstallCode <code>] [-Quiet]
                 (also started by Windows Settings > Apps > "Office Computer Security" > Uninstall)

  Nothing secret is stored in this script or in the setup program: the server makes its own keys on first
  start, and codes typed here are passed to the agent once and not written to disk by this script.
#>
[CmdletBinding()]
param(
    [ValidateSet('', 'Main', 'Staff')] [string] $Role = '',
    [string] $Server = '',
    [string] $PairingCode = '',
    [string] $EnrollmentCode = '',
    [switch] $Uninstall,
    [string] $UninstallCode = '',
    [switch] $Quiet,
    [string] $LogFile = '',
    [string] $ResultFile = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$ProductName   = 'Office Computer Security'
$Publisher     = 'Office Computer Security System'
$InstallRoot   = Join-Path $env:ProgramFiles 'OfficeSecurity'
$AppDir        = Join-Path $InstallRoot 'App'
$ServerDir     = Join-Path $InstallRoot 'Server'
$AgentExe      = Join-Path $InstallRoot 'Agent\OfficeSecurity.Agent.exe'
$SetupDir      = Join-Path $InstallRoot 'Setup'
$ServerData    = Join-Path $env:ProgramData 'OfficeSecurity\Server'
$UninstallKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OfficeSecurity'
$ServerService = 'OfficeSecurityServer'
$AgentService  = 'OfficeSecurityAgent'
$FirewallRule  = 'Office Security Server (TCP 5443)'
$ShortcutName  = 'Office Security.lnk'
$script:UnpackedPayload = $null

# ---------------------------------------------------------------- administrator rights
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Start again with administrator rights (Windows asks for permission) and wait, so the setup
    # program keeps its extracted files until this finishes.
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Value -is [switch]) { if ($entry.Value) { $arguments += "-$($entry.Key)" } }
        else { $arguments += "-$($entry.Key)"; $arguments += "`"$($entry.Value)`"" }
    }
    try {
        $p = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        exit $p.ExitCode
    } catch {
        Write-Host 'Administrator permission was not given, so nothing was changed.'
        exit 5
    }
}

if ($LogFile) { Start-Transcript -Path $LogFile -Append | Out-Null }

Add-Type -AssemblyName System.Windows.Forms, System.Drawing, Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()

# Progress lines start with "STEP: " (the setup window shows them); everything else is detail for the log.
function Say([string] $text) { Write-Host "STEP: $text" }

# For the setup window: simple "name=value" lines (line breaks written as \n).
function Write-Result([hashtable] $values) {
    if (-not $ResultFile) { return }
    $lines = foreach ($key in $values.Keys) { "$key=" + ([string]$values[$key]).Replace("`r", '').Replace("`n", '\n') }
    [IO.File]::WriteAllLines($ResultFile, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
}

function Show-Message([string] $text, [string] $icon = 'Information') {
    Write-Host $text
    if (-not $Quiet) {
        [void][System.Windows.Forms.MessageBox]::Show($text, "$ProductName setup", 'OK', $icon)
    }
}

function Fail([string] $text, [int] $code = 1) {
    $sentence = $text.Substring(0, 1).ToUpperInvariant() + $text.Substring(1)
    Write-Result @{ Status = 'Failed'; Message = "Setup stopped: $sentence`n`nNothing more was changed." }
    Show-Message ("Setup stopped: $text`n`nNothing more was changed.") 'Error'
    if ($LogFile) { Stop-Transcript | Out-Null }
    exit $code
}

function Confirm([string] $text) {
    if ($Quiet) { return $true }
    return [System.Windows.Forms.MessageBox]::Show($text, "$ProductName setup", 'YesNo', 'Question') -eq 'Yes'
}

function Get-Service-Or-Null([string] $name) { Get-Service -Name $name -ErrorAction SilentlyContinue }

function Invoke-Sc([string[]] $arguments) {
    $output = & "$env:SystemRoot\System32\sc.exe" @arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sc.exe $($arguments -join ' ') failed ($LASTEXITCODE): $output" }
}

function Stop-ServiceAndWait([string] $name, [string] $programFolder) {
    $service = Get-Service-Or-Null $name
    if ($service -and $service.Status -ne 'Stopped') {
        Say "Stopping $name..."
        Stop-Service -Name $name -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    }
    # Windows reports "stopped" slightly before the program has closed and released its files.
    if ($programFolder) {
        for ($i = 0; $i -lt 60; $i++) {
            $running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -like "$programFolder\*" }
            if (-not $running) { return }
            Start-Sleep -Seconds 1
        }
        throw "the program in $programFolder did not close within 60 seconds."
    }
}

function Copy-WithRetry([scriptblock] $copy) {
    for ($i = 1; ; $i++) {
        try { & $copy; return } catch { if ($i -ge 10) { throw } ; Start-Sleep -Seconds 2 }
    }
}

function New-Shortcut([string] $path, [string] $target) {
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($path)
    $link.TargetPath = $target
    $link.WorkingDirectory = Split-Path $target
    $link.Description = $ProductName
    $link.Save()
}

function Get-ShortcutPaths {
    @(
        (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) $ShortcutName),
        (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) $ShortcutName)
    )
}

# ---------------------------------------------------------------- program files in this package
function Get-Payload {
    $here = Split-Path -Parent $PSCommandPath
    if (Test-Path (Join-Path $here 'App\OfficeSecurity.exe')) { return $here }
    $zip = Join-Path $here 'payload.zip'
    if (-not (Test-Path $zip)) { Fail 'the program files were not found next to the setup script (payload.zip or the App, Server and Agent folders).' }
    $target = Join-Path $env:TEMP ("OfficeSecuritySetup-" + [Guid]::NewGuid().ToString('N'))
    $script:UnpackedPayload = $target
    Say 'Unpacking the program files...'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $target)
    return $target
}

function Copy-Folder([string] $from, [string] $to) {
    New-Item -ItemType Directory -Force -Path $to | Out-Null
    Copy-Item -Path (Join-Path $from '*') -Destination $to -Recurse -Force
}

# ---------------------------------------------------------------- questions (interactive setup)
function Ask-Role {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$ProductName setup"
    $form.Size = New-Object System.Drawing.Size(560, 330)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 10)

    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'What is this computer?'
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
    $title.Location = New-Object System.Drawing.Point(20, 15); $title.AutoSize = $true
    $form.Controls.Add($title)

    $main = New-Object System.Windows.Forms.RadioButton
    $main.Text = "Main office computer`n(installs the server and the Administrator sign-in; choose ONE computer for this)"
    $main.Location = New-Object System.Drawing.Point(25, 60); $main.Size = New-Object System.Drawing.Size(500, 55)
    $form.Controls.Add($main)

    $staff = New-Object System.Windows.Forms.RadioButton
    $staff.Text = "Staff computer`n(installs the security agent and the Staff sign-in; you need the codes from the dashboard: Computers > Add computer)"
    $staff.Location = New-Object System.Drawing.Point(25, 125); $staff.Size = New-Object System.Drawing.Size(500, 70)
    $form.Controls.Add($staff)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Next'; $ok.Location = New-Object System.Drawing.Point(330, 235); $ok.Size = New-Object System.Drawing.Size(90, 32)
    $ok.DialogResult = 'OK'; $ok.Enabled = $false
    $form.Controls.Add($ok); $form.AcceptButton = $ok
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(430, 235); $cancel.Size = New-Object System.Drawing.Size(90, 32)
    $cancel.DialogResult = 'Cancel'
    $form.Controls.Add($cancel); $form.CancelButton = $cancel
    $main.Add_CheckedChanged({ $ok.Enabled = $true })
    $staff.Add_CheckedChanged({ $ok.Enabled = $true })

    if ($form.ShowDialog() -ne 'OK') { return '' }
    if ($main.Checked) { return 'Main' }
    return 'Staff'
}

function Ask-StaffCodes {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$ProductName setup - staff computer"
    $form.Size = New-Object System.Drawing.Size(560, 340)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 10)

    $help = New-Object System.Windows.Forms.Label
    $help.Text = 'On the main office computer, open Office Security > Administrator > Computers > Add computer. Type what it shows:'
    $help.Location = New-Object System.Drawing.Point(20, 15); $help.Size = New-Object System.Drawing.Size(510, 45)
    $form.Controls.Add($help)

    $fields = @{}
    $y = 70
    foreach ($item in @(@('Server', 'Server address (for example 192.168.1.20)', $Server),
                        @('Pairing', 'Pairing code', $PairingCode),
                        @('Enrollment', 'Enrollment code (valid 24 hours)', $EnrollmentCode))) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $item[1]; $label.Location = New-Object System.Drawing.Point(20, $y); $label.AutoSize = $true
        $form.Controls.Add($label)
        $box = New-Object System.Windows.Forms.TextBox
        $box.Text = $item[2]; $box.Location = New-Object System.Drawing.Point(20, ($y + 22)); $box.Size = New-Object System.Drawing.Size(505, 26)
        $form.Controls.Add($box)
        $fields[$item[0]] = $box
        $y += 60
    }

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Install'; $ok.Location = New-Object System.Drawing.Point(330, 255); $ok.Size = New-Object System.Drawing.Size(90, 32)
    $ok.DialogResult = 'OK'
    $form.Controls.Add($ok); $form.AcceptButton = $ok
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(430, 255); $cancel.Size = New-Object System.Drawing.Size(90, 32)
    $cancel.DialogResult = 'Cancel'
    $form.Controls.Add($cancel); $form.CancelButton = $cancel

    if ($form.ShowDialog() -ne 'OK') { return $null }
    return @{ Server = $fields['Server'].Text.Trim(); Pairing = $fields['Pairing'].Text.Trim(); Enrollment = $fields['Enrollment'].Text.Trim() }
}

# ---------------------------------------------------------------- common parts
function Install-App([string] $payload, [string] $role, [string] $serverAddress, [string] $pairingCode) {
    Say 'Installing the Office Security program...'
    # Close a running copy so its files can be replaced.
    Get-Process -Name 'OfficeSecurity' -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$AppDir*" } | Stop-Process -Force
    Copy-Folder (Join-Path $payload 'App') $AppDir
    Set-Content -Path (Join-Path $AppDir 'role.txt') -Value $role -Encoding ASCII
    # Fills in the server address and pairing code on the program's Connect screen. Not secret (the pairing code
    # only identifies the server); kept in Program Files so only administrators can change which server is trusted.
    if ($serverAddress -and $pairingCode) {
        Set-Content -Path (Join-Path $AppDir 'connection.txt') -Value @($serverAddress, $pairingCode) -Encoding ASCII
    }
    foreach ($link in Get-ShortcutPaths) { New-Shortcut $link (Join-Path $AppDir 'OfficeSecurity.exe') }

    # Keep this script (in Program Files, which only administrators can change) for removal.
    New-Item -ItemType Directory -Force -Path $SetupDir | Out-Null
    Copy-Item -Path $PSCommandPath -Destination (Join-Path $SetupDir 'install.ps1') -Force

    $version = (Get-Item (Join-Path $AppDir 'OfficeSecurity.exe')).VersionInfo.ProductVersion
    if (-not (Test-Path $UninstallKey)) { New-Item -Path $UninstallKey -Force | Out-Null }
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $values = @{
        DisplayName     = $ProductName
        DisplayVersion  = [string]$version
        Publisher       = $Publisher
        InstallLocation = $InstallRoot
        DisplayIcon     = (Join-Path $AppDir 'OfficeSecurity.exe')
        UninstallString = "`"$powershell`" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Join-Path $SetupDir 'install.ps1')`" -Uninstall"
        Comments        = "Installed as: $(if ($role -eq 'Main') { 'main office computer' } else { 'staff computer' })"
    }
    foreach ($name in $values.Keys) { Set-ItemProperty -Path $UninstallKey -Name $name -Value $values[$name] }
    Set-ItemProperty -Path $UninstallKey -Name NoModify -Value 1 -Type DWord
    Set-ItemProperty -Path $UninstallKey -Name NoRepair -Value 1 -Type DWord
}

function Test-Port([int] $port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try { $client.Connect('127.0.0.1', $port); return $true } catch { return $false } finally { $client.Dispose() }
}

# ---------------------------------------------------------------- main office computer
function Install-Main([string] $payload) {
    $serverExe = Join-Path $ServerDir 'OfficeSecurity.Server.exe'

    # A server started by hand (for example from the Downloads folder) would hold port 5443.
    $manual = Get-Process -Name 'OfficeSecurity.Server' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -notlike "$ServerDir*" }
    if ($manual) {
        if (-not (Confirm "The Office Security server is already running in a window (started by hand).`n`nClose it now so it can be installed as a Windows service? Its data (accounts, computers, keys) is kept.")) {
            Fail 'the server started by hand is still running.'
        }
        $manual | Stop-Process -Force
        Start-Sleep -Seconds 2
    }

    $wasInstalled = [bool](Get-Service-Or-Null $ServerService)
    try {
        Stop-ServiceAndWait $ServerService $ServerDir
        Say 'Installing the server...'
        Copy-WithRetry { Copy-Folder (Join-Path $payload 'Server') $ServerDir }
    } catch {
        # Do not leave the office without its server: start the version that was there before.
        if ($wasInstalled) { Start-Service -Name $ServerService -ErrorAction SilentlyContinue }
        Fail "the server files could not be updated, so the previous version was started again: $($_.Exception.Message)" 3
    }

    if (-not (Get-Service-Or-Null $ServerService)) {
        Invoke-Sc @('create', $ServerService, 'binPath=', "`"$serverExe`"", 'start=', 'auto', 'DisplayName=', 'Office Security Server')
    } else {
        Invoke-Sc @('config', $ServerService, 'binPath=', "`"$serverExe`"", 'start=', 'auto')
    }
    Invoke-Sc @('description', $ServerService, 'Central server of the Office Computer Security System (HTTPS port 5443).')
    Invoke-Sc @('failure', $ServerService, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/30000')

    # Other office computers connect on TCP 5443; allowed on private and domain networks only.
    Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5443 `
        -Program $serverExe -Profile Domain, Private | Out-Null

    Say 'Starting the server...'
    Start-Service -Name $ServerService
    $ready = $false
    for ($i = 0; $i -lt 90 -and -not $ready; $i++) {
        if ((Test-Port 5443) -and (Test-Path (Join-Path $ServerData 'SERVER-CONNECTION-INFO.txt'))) { $ready = $true } else { Start-Sleep -Seconds 1 }
    }
    if (-not $ready) {
        Fail "the server service was installed but did not start within 90 seconds. Open 'Services' and check 'Office Security Server', or Event Viewer > Windows Logs > Application." 3
    }

    $info = Get-Content (Join-Path $ServerData 'SERVER-CONNECTION-INFO.txt') -Raw
    $pairingMatch = [regex]::Match($info, 'Pairing code:\s*(\S+)')
    $pairing = if ($pairingMatch.Success) { $pairingMatch.Groups[1].Value } else { '' }
    Install-App $payload 'MAIN' 'localhost' $pairing

    $firstAdmin = Join-Path $ServerData 'FIRST-ADMIN-SETUP-CODE.txt'
    # Addresses other computers can use (not this computer's own loopback names).
    $addresses = @([regex]::Matches($info, 'https://([^\s:]+):5443') | ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $_ -notin @('127.0.0.1', 'localhost', '::1') })
    $result = @{ Status = $(if ($wasInstalled) { 'Updated' } else { 'Installed' }); Role = 'Main'; PairingCode = $pairing; Addresses = ($addresses -join '|') }
    if (Test-Path $firstAdmin) {
        $codeMatch = [regex]::Match((Get-Content $firstAdmin -Raw), '(?m)^\s*([A-Z0-9]{4}(-[A-Z0-9]{4})+)\s*$')
        if ($codeMatch.Success) { $result.SetupCode = $codeMatch.Groups[1].Value }
    }
    Write-Result $result
    $text = "Installed. The server now runs in the background and starts with Windows.`n`n$info"
    if (Test-Path $firstAdmin) {
        $text += "`n" + (Get-Content $firstAdmin -Raw)
    }
    $text += "`nNext: open 'Office Security' on the desktop and choose Administrator sign-in.`n" +
             "These details are saved in $ServerData.`n`n" +
             "If other computers cannot connect: Windows Settings > Network > set this network to 'Private'."
    Show-Message $text
}

# ---------------------------------------------------------------- staff computer
function Install-Staff([string] $payload) {
    $existing = Get-Service-Or-Null $AgentService
    if ($existing -and (Test-Path $AgentExe)) {
        # Already protected: update the agent program in place and keep its registration.
        Say 'Updating the security agent (it keeps its registration)...'
        try {
            Stop-ServiceAndWait $AgentService (Split-Path $AgentExe)
            Copy-WithRetry { Copy-Item -Path (Join-Path $payload 'Agent\OfficeSecurity.Agent.exe') -Destination $AgentExe -Force }
        } finally {
            # Whatever happened, the computer must stay protected.
            Start-Service -Name $AgentService -ErrorAction SilentlyContinue
        }
        if ((Get-Service -Name $AgentService).Status -ne 'Running') { Fail 'the security agent did not start again after the update. Restart the computer.' 3 }
        Install-App $payload 'STAFF' '' ''
        Write-Result @{ Status = 'Updated'; Role = 'Staff' }
        Show-Message "Updated. The security agent is running again.`n`nOpen 'Office Security' on the desktop and choose Staff sign-in."
        return
    }

    $server = $Server; $pairing = $PairingCode; $enrollment = $EnrollmentCode
    if (-not $Quiet -and (-not $server -or -not $pairing -or -not $enrollment)) {
        $codes = Ask-StaffCodes
        if (-not $codes) { Fail 'cancelled.' 2 }
        $server = $codes.Server; $pairing = $codes.Pairing; $enrollment = $codes.Enrollment
    }
    if (-not $server -or -not $pairing -or -not $enrollment) { Fail 'the server address, pairing code and enrollment code are all needed.' 2 }

    Say 'Installing the security agent and registering with the server...'
    $output = & (Join-Path $payload 'Agent\OfficeSecurity.Agent.exe') install --server $server --pairing-code $pairing --enrollment-code $enrollment 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host $output
    if ($code -ne 0) {
        # The agent's last line says what was wrong (for example a mistyped pairing code).
        $reason = ($output.Trim() -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)
        Fail "the security agent could not be installed: $reason" 4
    }

    Install-App $payload 'STAFF' $server $pairing
    Write-Result @{ Status = 'Installed'; Role = 'Staff' }
    Show-Message "Installed. The security agent is running and registered.`n`nNow, on the main office computer: Administrator > Computers > select this computer > Approve.`n`nStaff open 'Office Security' on the desktop and choose Staff sign-in."
}

# ---------------------------------------------------------------- removal
function Uninstall-All {
    $role = ''
    $roleFile = Join-Path $AppDir 'role.txt'
    if (Test-Path $roleFile) { $role = (Get-Content $roleFile -Raw).Trim().ToUpperInvariant() }

    if (-not (Confirm "Remove $ProductName from this computer?")) { exit 2 }

    if ((Get-Service-Or-Null $AgentService) -and (Test-Path $AgentExe)) {
        # While the computer is managed, the agent itself refuses removal without a valid code from the dashboard.
        $code = $UninstallCode
        if (-not $code -and -not $Quiet) {
            $code = [Microsoft.VisualBasic.Interaction]::InputBox(
                "This computer is protected by the Office Security agent.`n`nType the uninstall code from the dashboard`n(Administrator > Computers > select this computer > Uninstall code).`n`nLeave empty if the computer was never approved or was removed from management.",
                "$ProductName - uninstall code", '')
        }
        $arguments = @('uninstall')
        if ($code) { $arguments += @('--code', $code.Trim()) }
        $output = & $AgentExe @arguments 2>&1 | Out-String
        $exit = $LASTEXITCODE
        Write-Host $output
        if ($exit -ne 0) { Fail "the security agent was not removed (code $exit):`n`n$($output.Trim())" 7 }
    }

    if (Get-Service-Or-Null $ServerService) {
        Stop-ServiceAndWait $ServerService $ServerDir
        Invoke-Sc @('delete', $ServerService)
        Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }

    Get-Process -Name 'OfficeSecurity' -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$AppDir*" } | Stop-Process -Force
    foreach ($link in Get-ShortcutPaths) { Remove-Item -Path $link -Force -ErrorAction SilentlyContinue }
    foreach ($dir in @($AppDir, $ServerDir, (Split-Path $AgentExe), $SetupDir)) {
        if (Test-Path $dir) { Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if ((Test-Path $InstallRoot) -and -not (Get-ChildItem $InstallRoot -Force)) { Remove-Item $InstallRoot -Force }
    Remove-Item -Path $UninstallKey -Recurse -Force -ErrorAction SilentlyContinue

    $text = "$ProductName was removed from this computer."
    if ($role -eq 'MAIN' -or (Test-Path $ServerData)) {
        $text += "`n`nThe server's data (accounts, computers, audit log, keys) was kept in $ServerData so nothing is lost by accident. Installing again uses it."
    }
    Show-Message $text
}

# ---------------------------------------------------------------- start
try {
    if ($Uninstall) {
        Uninstall-All
    } else {
        $chosen = $Role
        if (-not $chosen) {
            if ($Quiet) { Fail '-Role Main or -Role Staff is needed with -Quiet.' 2 }
            $chosen = Ask-Role
            if (-not $chosen) { Fail 'cancelled.' 2 }
        }
        $payload = Get-Payload
        try {
            if ($chosen -eq 'Main') { Install-Main $payload } else { Install-Staff $payload }
        } finally {
            if ($script:UnpackedPayload) { Remove-Item -Path $payload -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
} catch {
    Fail $_.Exception.Message
}

if ($LogFile) { Stop-Transcript | Out-Null }
exit 0
