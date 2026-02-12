<#
.SYNOPSIS
Hytale Ops CLI (PowerShell Version)
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

# Load Config
if (Test-Path $ConfigFile) {
    $Content = Get-Content $ConfigFile -Raw
    if ($Content -match "HETZNER_TOKEN=(.*)") {
        $global:HetznerToken = $matches[1].Trim()
    }
}

# Check Token Inline
if ([string]::IsNullOrEmpty($global:HetznerToken)) {
    Write-Host "🔑 Hetzner Token not found." -ForegroundColor Yellow
    $InputToken = Read-Host -Prompt "Paste Token" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($InputToken)
    $global:HetznerToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    if (-not [string]::IsNullOrEmpty($global:HetznerToken)) {
        if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null }
        "HETZNER_TOKEN=$global:HetznerToken" | Set-Content $ConfigFile -Encoding ASCII
        Write-Host "Token saved." -ForegroundColor Green
    } else {
        Write-Host "Token required." -ForegroundColor Red
        exit 1
    }
}

function Call-Hetzner {
    param($Method="GET", $Uri, $Body=$null)
    $Headers = @{ "Authorization"="Bearer $global:HetznerToken"; "Content-Type"="application/json" }
    $Url = "https://api.hetzner.cloud/v1$Uri"
    $JsonBody = $null
    if ($Body) { $JsonBody = $Body | ConvertTo-Json -Depth 10 }

    try {
        if ($Body) { Invoke-RestMethod -Uri $Url -Method $Method -Headers $Headers -Body $JsonBody -ErrorAction Stop }
        else { Invoke-RestMethod -Uri $Url -Method $Method -Headers $Headers -ErrorAction Stop }
    } catch {
        Write-Host "API Error: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            try {
                $Stream = $_.Exception.Response.GetResponseStream()
                $Reader = New-Object System.IO.StreamReader($Stream)
                Write-Host $Reader.ReadToEnd() -ForegroundColor Red
            } catch {}
        }
        exit 1
    }
}

function Deploy-Server {
    param([string]$ServerName)
    if (-not $ServerName) { $ServerName = Read-Host "Server Name" }
    
    Write-Host "1) cx23 (Small)"
    Write-Host "2) cpx21 (Medium)"
    $Type = Read-Host "Type [1-2]"
    $ServerType = if ($Type -eq "1") { "cx23" } else { "cpx21" }

    Write-Host "1) Nuremberg"
    Write-Host "2) Falkenstein"
    $Loc = Read-Host "Location [1-2]"
    $Location = if ($Loc -eq "2") { "fsn1" } else { "nbg1" }

    Write-Host "Deploying $ServerName..." -ForegroundColor Cyan

    # SSH Key Logic
    $Keys = Call-Hetzner -Uri "/ssh_keys?name=$SshKeyName"
    $KeyId = $null
    if ($Keys.ssh_keys.Count -eq 0) {
        Write-Host "Uploading Key..." -ForegroundColor Yellow
        $Pub = Get-Content "$SshKeyPath.pub" -Raw
        $NewKey = Call-Hetzner -Method POST -Uri "/ssh_keys" -Body @{name=$SshKeyName; public_key=$Pub}
        $KeyId = $NewKey.ssh_key.id
    } else {
        $KeyId = $Keys.ssh_keys[0].id
    }

    # Create Server
    $UserData = "#cloud-config`npackages:`n - openjdk-25-jre-headless`n - ufw`nruncmd:`n - ufw allow 22/tcp`n - ufw allow 25565/tcp`n - useradd -m -s /bin/bash hytale"
    $Body = @{
        name=$ServerName; server_type=$ServerType; image=$DefaultImage; location=$Location;
        ssh_keys=@($KeyId); user_data=$UserData
    }

    try {
        $Result = Call-Hetzner -Method POST -Uri "/servers" -Body $Body
        $Ip = $Result.server.public_net.ipv4.ip
        Write-Host "Server Created: $Ip" -ForegroundColor Green
    } catch {
        Write-Host "Creation failed (or exists)." -ForegroundColor Red
        return
    }
    
    # Wait Loop
    Write-Host "Waiting for SSH..." -NoNewline
    1..30 | ForEach-Object {
        Start-Sleep 5
        Write-Host "." -NoNewline
        if (Test-Connection $Ip -Count 1 -Quiet) { 
             # Simple ping check first
        }
    }
    Write-Host "`nDone! Connect with: ssh root@$Ip" -ForegroundColor Green
}

# --- Main ---
if (-not $Command) {
    $Action = Read-Host "1) Deploy, 2) Status"
    if ($Action -eq "1") { Deploy-Server }
} else {
    if ($Command -eq "deploy") { Deploy-Server $Name }
}
