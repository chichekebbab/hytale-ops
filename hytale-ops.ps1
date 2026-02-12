<#
.SYNOPSIS
Hytale Ops CLI (PowerShell Version)

.DESCRIPTION
Deploy Hytale Servers on Hetzner Cloud.
Zero dependencies.

.EXAMPLE
.\hytale-ops.ps1
#>

param (
    [string]$Command = $null,
    [string]$Name = $null
)

$ErrorActionPreference = "Stop"

# --- Config ---
$ConfigDir = "$env:USERPROFILE\.config\hytale-ops"
$ConfigFile = "$ConfigDir\config.env"
$SshKeyPath = "$env:USERPROFILE\.ssh\id_rsa"
$SshKeyName = "hytale-deploy-key"
$DefaultImage = "ubuntu-24.04"

# --- Helpers ---

function Log-Info($msg) { Write-Host "ℹ️  $msg" -ForegroundColor Cyan }
function Log-Success($msg) { Write-Host "✅ $msg" -ForegroundColor Green }
function Log-Warn($msg) { Write-Host "⚠️  $msg" -ForegroundColor Yellow }
function Log-Error($msg) { Write-Host "❌ $msg" -ForegroundColor Red }

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
        Write-Host "🔑 Hetzner API Token not found."
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

function Call-Hetzner {
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
        $ServerName = Read-Host "🏷️  Enter Server Name"
        if ([string]::IsNullOrEmpty($ServerName)) { Log-Error "Name is required."; exit 1 }
    }

    # Select Type
    Write-Host "`n🖥️  Select Server Type:"
    Write-Host "1) cx23   (2 vCPU / 4GB RAM  / ~5€/mo)"
    Write-Host "2) cpx21  (3 vCPU / 4GB RAM  / ~8€/mo)"
    $TypeChoice = Read-Host "Choose [1-2]"
    
    $ServerType = switch ($TypeChoice) {
        "1" { "cx23" }
        "2" { "cpx21" }
        Default { "cpx21" }
    }
    Write-Host "Selected: $ServerType" -ForegroundColor Yellow

    # Select Location
    Write-Host "`n🌍 Select Location:"
    Write-Host "1) Nuremberg (nbg1)"
    Write-Host "2) Falkenstein (fsn1)"
    $LocChoice = Read-Host "Choose [1-2]"

    $Location = switch ($LocChoice) {
        "1" { "nbg1" }
        "2" { "fsn1" }
        Default { "nbg1" }
    }
    Write-Host "Selected: $Location" -ForegroundColor Yellow

    Log-Info "Deploying $ServerName ($ServerType in $Location)..."

    # SSH Key Check
    if (-not (Test-Path $SshKeyPath)) {
        Log-Error "SSH key not found at $SshKeyPath."
        exit 1
    }

    # Check/Upload SSH Key
    Log-Info "Checking SSH Key..."
    $Keys = Call-Hetzner -Uri "/ssh_keys?name=$SshKeyName"
    $SshKeyId = $null
    
    if ($Keys.ssh_keys.Count -eq 0) {
        Log-Warn "Key '$SshKeyName' missing. Uploading..."
        $PubKeyContent = Get-Content "$SshKeyPath.pub" -Raw
        $KeyBody = @{ name = $SshKeyName; public_key = $PubKeyContent }
        $NewKey = Call-Hetzner -Method "POST" -Uri "/ssh_keys" -Body $KeyBody
        $SshKeyId = $NewKey.ssh_key.id
        Log-Success "Key uploaded (ID: $SshKeyId)."
    } else {
        $SshKeyId = $Keys.ssh_keys[0].id
        Log-Success "Key found (ID: $SshKeyId)."
    }

    # Check existence
    $Existing = Call-Hetzner -Uri "/servers?name=$ServerName"
    if ($Existing.servers.Count -gt 0) {
        Log-Warn "Server exists (IP: $($Existing.servers[0].public_net.ipv4.ip))."
        $ServerIp = $Existing.servers[0].public_net.ipv4.ip
        
        $Confirm = Read-Host "Re-run configuration? (y/n)"
        if ($Confirm -ne "y") { return }
    } else {
        Log-Info "Provisioning VPS..."
        $UserData = "#cloud-config`npackages:`n - openjdk-25-jre-headless`n - ufw`nruncmd:`n - ufw allow 22/tcp`n - ufw allow 25565/tcp`n - useradd -m -s /bin/bash hytale"
        $Body = @{
            name = $ServerName
            server_type = $ServerType
            image = $DefaultImage
            location = $Location
            ssh_keys = @($SshKeyId)
            user_data = $UserData
        }
        $Result = Call-Hetzner -Method "POST" -Uri "/servers" -Body $Body
        $ServerIp = $Result.server.public_net.ipv4.ip
        Log-Success "Server created: $ServerIp"
    }

    Log-Info "Waiting for SSH..."
    $MaxRetries = 30
    $RetryCount = 0
    $SshReady = $false

    while (-not $SshReady -and $RetryCount -lt $MaxRetries) {
        Start-Sleep -Seconds 10
        $RetryCount++
        Write-Host -NoNewline "."
        $TestSsh = ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SshKeyPath" root@$ServerIp "echo ready" 2>$null
        if ($TestSsh -match "ready") { $SshReady = $true; Write-Host "`n✅ SSH UP!" -ForegroundColor Green }
    }

    if (-not $SshReady) {
        Log-Error "SSH Timeout."
        exit 1
    }

    Log-Info "Configuring..."
    $ServiceFile = @"
[Unit]
Description=Hytale Server
After=network.target
[Service]
User=hytale
WorkingDirectory=/opt/hytale
ExecStart=/usr/bin/java -Xmx4G -jar hytale-server.jar
Restart=always
[Install]
WantedBy=multi-user.target
"@

    $RemoteScript = @"
mkdir -p /opt/hytale
chown hytale:hytale /opt/hytale
echo '$ServiceFile' > /etc/systemd/system/hytale.service
systemctl daemon-reload
systemctl enable hytale
"@
    
    $RemoteScript | ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$ServerIp
    Write-Host "`n🎉 Done! IP: $ServerIp" -ForegroundColor Green
}

function Get-Status {
    param([string]$ServerName)
    Load-Config
    Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Server Name" }
    $Result = Call-Hetzner -Uri "/servers?name=$ServerName"
    if ($Result.servers.Count -eq 0) { Log-Error "Not found."; return }
    $Server = $Result.servers[0]
    Write-Host "Status: $($Server.status) | IP: $($Server.public_net.ipv4.ip)" -ForegroundColor Green
}

function Connect-Ssh {
    param([string]$ServerName)
    Load-Config
    Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Server Name" }
    $Result = Call-Hetzner -Uri "/servers?name=$ServerName"
    if ($Result.servers.Count -eq 0) { Log-Error "Not found."; exit 1 }
    $Ip = $Result.servers[0].public_net.ipv4.ip
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$Ip
}

# --- Main ---

if ([string]::IsNullOrEmpty($Command)) {
    Write-Host "Hytale Ops CLI" -ForegroundColor Cyan
    Write-Host "1) Deploy"
    Write-Host "2) Status"
    Write-Host "3) SSH"
    $Action = Read-Host "Option"
    switch ($Action) {
        "1" { Deploy-Server }
        "2" { Get-Status }
        "3" { Connect-Ssh }
    }
} else {
    switch ($Command) {
        "deploy" { Deploy-Server -ServerName $Name }
        "status" { Get-Status -ServerName $Name }
        "ssh"    { Connect-Ssh -ServerName $Name }
    }
}
