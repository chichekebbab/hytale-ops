<#
.SYNOPSIS
Hytale Ops CLI (PowerShell Version) - Deploy Hytale Servers on Hetzner

.DESCRIPTION
Interactive tool to deploy, manage, and connect to Hytale game servers on Hetzner Cloud.
Zero external dependencies (uses native PowerShell + ssh.exe).
#>

param (
    [string]$Command = $null,
    [string]$Name = $null
)

$ErrorActionPreference = "Stop"

# --- Configuration ---
$ConfigDir = "$env:USERPROFILE\.config\hytale-ops"
$ConfigFile = "$ConfigDir\config.env"
$SshKeyPath = "$env:USERPROFILE\.ssh\id_rsa"
$SshKeyName = "hytale-deploy-key"
$DefaultImage = "ubuntu-24.04"

# --- Helpers ---

function Log-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Log-Success($msg) { Write-Host "[OK]   $msg" -ForegroundColor Green }
function Log-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Log-Error($msg) { Write-Host "[ERR]  $msg" -ForegroundColor Red }

function Load-Config {
    if (Test-Path $ConfigFile) {
        Get-Content $ConfigFile | ForEach-Object {
            if ($_ -match "^HETZNER_TOKEN=(.*)") {
                $global:HetznerToken = $matches[1]
            }
        }
    }
}

function Save-Config {
    if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null }
    "HETZNER_TOKEN=$global:HetznerToken" | Set-Content $ConfigFile
}

function Check-Token {
    if ([string]::IsNullOrEmpty($global:HetznerToken)) {
        Write-Host "Hetzner API Token not found."
        $global:HetznerToken = Read-Host -Prompt "Paste your HCloud API Token" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:HetznerToken)
        $global:HetznerToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
        if ([string]::IsNullOrEmpty($global:HetznerToken)) {
            Log-Error "Token is required."
            exit 1
        }
        Save-Config
        Log-Success "Token saved to $ConfigFile"
    }
}

function Invoke-HetznerApi {
    param(
        [string]$Method = "GET",
        [string]$Uri,
        [hashtable]$Body = $null
    )
    
    $Headers = @{
        "Authorization" = "Bearer $global:HetznerToken"
        "Content-Type"  = "application/json"
    }
    
    $Url = "https://api.hetzner.cloud/v1$Uri"
    $JsonBody = $null
    if ($Body) {
        $JsonBody = $Body | ConvertTo-Json -Depth 10
    }

    try {
        if ($Body) {
            $Response = Invoke-RestMethod -Uri $Url -Method $Method -Headers $Headers -Body $JsonBody -ErrorAction Stop
        } else {
            $Response = Invoke-RestMethod -Uri $Url -Method $Method -Headers $Headers -ErrorAction Stop
        }
        return $Response
    } catch {
        Log-Error "Request Failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $Stream = $_.Exception.Response.GetResponseStream()
                $Reader = New-Object System.IO.StreamReader($Stream)
                Write-Host $Reader.ReadToEnd() -ForegroundColor Red
            } catch { }
        }
        exit 1
    }
}

# --- Actions ---

function Deploy-Server {
    param([string]$ServerName)

    Load-Config
    Check-Token

    if ([string]::IsNullOrEmpty($ServerName)) {
        $ServerName = Read-Host "Enter Server Name (e.g., hytale-smp)"
        if ([string]::IsNullOrEmpty($ServerName)) { Log-Error "Name is required."; exit 1 }
    }

    Write-Host "`nSelect Server Type:"
    Write-Host "1) cx23   (2 vCPU / 4GB RAM  / ~5 EUR/mo)"
    Write-Host "2) cpx21  (3 vCPU / 4GB RAM  / ~8 EUR/mo)"
    $TypeChoice = Read-Host "Choose [1-2]"
    $ServerType = if ($TypeChoice -eq "2") { "cpx21" } else { "cx23" }

    Write-Host "`nSelect Location:"
    Write-Host "1) Nuremberg (nbg1)"
    Write-Host "2) Falkenstein (fsn1)"
    $LocChoice = Read-Host "Choose [1-2]"
    $Location = if ($LocChoice -eq "2") { "fsn1" } else { "nbg1" }

    Log-Info "Deploying $ServerName ($ServerType)..."

    # SSH Key
    if (-not (Test-Path $SshKeyPath)) { Log-Error "SSH key missing."; exit 1 }
    $Keys = Invoke-HetznerApi -Uri "/ssh_keys?name=$SshKeyName"
    $SshKeyId = $null
    if ($Keys.ssh_keys.Count -eq 0) {
        Log-Warn "Uploading SSH Key..."
        $Pub = Get-Content "$SshKeyPath.pub" -Raw
        $NewKey = Invoke-HetznerApi -Method POST -Uri "/ssh_keys" -Body @{name=$SshKeyName; public_key=$Pub}
        $SshKeyId = $NewKey.ssh_key.id
    } else {
        $SshKeyId = $Keys.ssh_keys[0].id
    }

    # Create Server
    $Existing = Invoke-HetznerApi -Uri "/servers?name=$ServerName"
    if ($Existing.servers.Count -gt 0) {
        Log-Warn "Server exists. Re-run setup? (y/n)"
        if ((Read-Host) -ne "y") { return }
        $ServerIp = $Existing.servers[0].public_net.ipv4.ip
    } else {
        Log-Info "Provisioning..."
        $UserData = "#cloud-config`npackages:`n - openjdk-25-jre-headless`n - ufw`nruncmd:`n - ufw allow 22/tcp`n - ufw allow 5520/udp`n - ufw allow 5520/tcp`n - useradd -m -s /bin/bash hytale"
        $Body = @{
            name = $ServerName; server_type = $ServerType; image = $DefaultImage; location = $Location;
            ssh_keys = @($SshKeyId); user_data = $UserData
        }
        $Result = Invoke-HetznerApi -Method POST -Uri "/servers" -Body $Body
        $ServerIp = $Result.server.public_net.ipv4.ip
        Log-Success "Server created: $ServerIp"
    }

    Log-Info "Waiting for SSH..."
    $MaxRetries = 30
    $RetryCount = 0
    $SshReady = $false
    while (-not $SshReady -and $RetryCount -lt $MaxRetries) {
        Start-Sleep 10
        Write-Host -NoNewline "."
        try {
            $P = Start-Process ssh -ArgumentList "-o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i `"$SshKeyPath`" root@$ServerIp exit" -NoNewWindow -PassThru -Wait
            if ($P.ExitCode -eq 0) { $SshReady = $true; Write-Host "`n[OK] SSH UP!" -ForegroundColor Green }
        } catch {}
    }
    if (-not $SshReady) { Log-Error "SSH Timeout."; exit 1 }

    Log-Info "Configuring Hytale..."
    
    $ServiceFile = @"
[Unit]
Description=Hytale Dedicated Server
After=network.target
[Service]
User=hytale
Group=hytale
WorkingDirectory=/opt/hytale
ExecStart=/usr/bin/java -Xms2G -Xmx3G -jar Server/HytaleServer.jar --assets Assets.zip
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
"@ -replace "`r`n", "`n"

    $RemoteScript = @"
systemctl stop hytale 2>/dev/null
# Prep
mkdir -p /opt/hytale
chown hytale:hytale /opt/hytale
cd /opt/hytale

# Downloader
echo 'Downloading tools...'
wget -q https://downloader.hytale.com/hytale-downloader.zip
apt-get update -qq && apt-get install -y unzip
unzip -o -q hytale-downloader.zip
chmod +x hytale-downloader-linux-amd64

# Fetch Game
echo 'Fetching Game Files...'
su - hytale -c 'cd /opt/hytale && ./hytale-downloader-linux-amd64'

# Extract
cd /opt/hytale
ZIP_FILE=`$(ls *.zip | grep -v 'hytale-downloader.zip' | head -n 1)
if [ -n "`$ZIP_FILE" ]; then
    echo "Extracting `$ZIP_FILE..."
    unzip -o -q "`$ZIP_FILE"
    chown -R hytale:hytale /opt/hytale
fi

# Firewall
ufw allow 5520/udp
ufw allow 5520/tcp
ufw --force enable

# Service
echo '$ServiceFile' > /etc/systemd/system/hytale.service
systemctl daemon-reload
systemctl enable hytale

echo '-------------------------------------------------------'
echo 'SETUP PAUSED: AUTHENTICATION REQUIRED'
echo '1. Server starting INTERACTIVE mode.'
echo '2. Look for URL with code: https://.../verify?user_code=...'
echo '3. Authenticate on web.'
echo '4. CRITICAL: Type "/auth persistence Encrypted" to save!'
echo '5. Type "stop" to finish.'
echo '-------------------------------------------------------'
read -p 'Press ENTER to start auth...'

su - hytale -c 'cd /opt/hytale && java -Xms2G -Xmx3G -jar Server/HytaleServer.jar --assets Assets.zip'

echo 'Starting background service...'
systemctl start hytale
systemctl status hytale --no-pager
"@ -replace "`r`n", "`n"

    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($RemoteScript)
    $B64 = [Convert]::ToBase64String($Bytes)
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$ServerIp "echo $B64 | base64 -d | bash"
    Log-Success "Done! Connect: ssh root@$ServerIp"
}

function Update-Server {
    param([string]$ServerName)
    Load-Config
    Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Server Name" }
    
    $Result = Invoke-HetznerApi -Uri "/servers?name=$ServerName"
    if ($Result.servers.Count -eq 0) { Log-Error "Not found."; exit 1 }
    $Ip = $Result.servers[0].public_net.ipv4.ip
    
    Log-Info "Updating $ServerName ($Ip)..."
    
    $UpdateScript = @"
echo 'Stopping server...'
systemctl stop hytale
echo 'Downloading updates...'
su - hytale -c 'cd /opt/hytale && ./hytale-downloader-linux-amd64'
echo 'Extracting...'
cd /opt/hytale
ZIP_FILE=`$(ls *.zip | grep -v 'hytale-downloader.zip' | head -n 1)
if [ -n "`$ZIP_FILE" ]; then
    unzip -o -q "`$ZIP_FILE"
    chown -R hytale:hytale /opt/hytale
fi
echo 'Restarting...'
systemctl start hytale
systemctl status hytale --no-pager
"@ -replace "`r`n", "`n"

    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($UpdateScript)
    $B64 = [Convert]::ToBase64String($Bytes)
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$Ip "echo $B64 | base64 -d | bash"
    Log-Success "Update complete!"
}

function Get-Status {
    param([string]$ServerName)
    Load-Config
    Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Server Name" }
    $Result = Invoke-HetznerApi -Uri "/servers?name=$ServerName"
    if ($Result.servers.Count -eq 0) { Log-Error "Not found."; return }
    $S = $Result.servers[0]
    Write-Host "Status: $($S.status) | IP: $($S.public_net.ipv4.ip)" -ForegroundColor Green
}

function Connect-Ssh {
    param([string]$ServerName)
    Load-Config
    Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Server Name" }
    $Result = Invoke-HetznerApi -Uri "/servers?name=$ServerName"
    if ($Result.servers.Count -eq 0) { Log-Error "Not found."; exit 1 }
    $Ip = $Result.servers[0].public_net.ipv4.ip
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$Ip
}

# --- Main ---
if ([string]::IsNullOrEmpty($Command)) {
    Write-Host "Hytale Ops CLI" -ForegroundColor Cyan
    Write-Host "1) Deploy / Re-install"
    Write-Host "2) Update Server"
    Write-Host "3) Status"
    Write-Host "4) SSH"
    $Action = Read-Host "Option"
    switch ($Action) {
        "1" { Deploy-Server }
        "2" { Update-Server }
        "3" { Get-Status }
        "4" { Connect-Ssh }
    }
} else {
    switch ($Command) {
        "deploy" { Deploy-Server -ServerName $Name }
        "update" { Update-Server -ServerName $Name }
        "status" { Get-Status -ServerName $Name }
        "ssh"    { Connect-Ssh -ServerName $Name }
    }
}
