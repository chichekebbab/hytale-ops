<#
.SYNOPSIS
Hytale Ops CLI (Safe Version)
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

# --- UI Helpers ---

function Show-Banner {
    Clear-Host
    Write-Host "  _  _         _         _             ___               " -ForegroundColor Cyan
    Write-Host " | || | _  _  | |_  __ _ | | ___       / _ \  _ __  ___  " -ForegroundColor Cyan
    Write-Host " | __ || || | |  _|/ _` || |/ -_)     | (_) || '_ \(_-<  " -ForegroundColor Cyan
    Write-Host " |_||_| \_, |  \__|\__,_||_|\___|      \___/ | .__//__/  " -ForegroundColor Cyan
    Write-Host "        |__/                                 |_|         " -ForegroundColor Cyan
    Write-Host "`n  Deploy and manage Hytale servers with style" -ForegroundColor DarkCyan
    Write-Host "  --------------------------------------------`n" -ForegroundColor Gray
}

function Log-Info($msg) { Write-Host "  [i] $msg" -ForegroundColor Cyan }
function Log-Success($msg) { Write-Host "  [v] $msg" -ForegroundColor Green }
function Log-Warn($msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Log-Error($msg) { Write-Host "  [X] $msg" -ForegroundColor Red }

# --- Helpers ---

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
    if (-not (Test-Path $ConfigDir)) { $null = New-Item -ItemType Directory -Force -Path $ConfigDir }
    "HETZNER_TOKEN=$global:HetznerToken" | Set-Content $ConfigFile
}

function Check-Token {
    if ([string]::IsNullOrEmpty($global:HetznerToken)) {
        Write-Host "Hetzner API Token not found." -ForegroundColor Yellow
        $global:HetznerToken = Read-Host -Prompt "   Paste your HCloud API Token"
        if ([string]::IsNullOrEmpty($global:HetznerToken)) {
            Log-Error "Token is required."
            exit 1
        }
        Save-Config
        Log-Success "Token saved."
    }
}

function Invoke-HetznerApi {
    param([string]$Method = "GET", [string]$Uri, [hashtable]$Body = $null)
    $Headers = @{ "Authorization" = "Bearer $global:HetznerToken"; "Content-Type"  = "application/json" }
    $Url = "https://api.hetzner.cloud/v1$Uri"
    $JsonBody = if ($Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
    try {
        if ($Body) { return Invoke-RestMethod -Uri $Url -Method $Method -Headers $Headers -Body $JsonBody }
        else { return Invoke-RestMethod -Uri $Url -Method $Method -Headers $Headers }
    } catch {
        Log-Error "API Failed: $($_.Exception.Message)"; exit 1
    }
}

# --- Actions ---

function Deploy-Server {
    param([string]$ServerName)
    Show-Banner
    Load-Config
    Check-Token

    if ([string]::IsNullOrEmpty($ServerName)) {
        Write-Host "  > Server Name: " -NoNewline -ForegroundColor White
        $ServerName = Read-Host
    }

    $TypeChoice = Read-Host "  Choose Plan [1: cx23, 2: cpx21]"
    $ServerType = if ($TypeChoice -eq "2") { "cpx21" } else { "cx23" }

    Log-Info "Deploying..."

    $Keys = Invoke-HetznerApi -Uri "/ssh_keys?name=$SshKeyName"
    $SshKeyId = if ($Keys.ssh_keys.Count -eq 0) {
        $Pub = Get-Content "$SshKeyPath.pub" -Raw
        (Invoke-HetznerApi -Method POST -Uri "/ssh_keys" -Body @{name=$SshKeyName; public_key=$Pub}).ssh_key.id
    } else { $Keys.ssh_keys[0].id }

    $Existing = Invoke-HetznerApi -Uri "/servers?name=$ServerName"
    if ($Existing.servers.Count -gt 0) {
        $ServerIp = $Existing.servers[0].public_net.ipv4.ip
        Log-Warn "Exists at $ServerIp."
    } else {
        $UserData = "#cloud-config`npackages:`n - openjdk-25-jre-headless`n - ufw`nruncmd:`n - ufw allow 22/tcp`n - ufw allow 5520/udp`n - ufw allow 5520/tcp`n - useradd -m -s /bin/bash hytale"
        $Body = @{ name = $ServerName; server_type = $ServerType; image = $DefaultImage; location = "nbg1"; ssh_keys = @($SshKeyId); user_data = $UserData }
        $ServerIp = (Invoke-HetznerApi -Method POST -Uri "/servers" -Body $Body).server.public_net.ipv4.ip
    }

    Log-Info "SSH Wait..."
    Start-Sleep 20
    
    $Svc = "[Unit]`nDescription=Hytale`nAfter=network.target`n[Service]`nUser=hytale`nGroup=hytale`nWorkingDirectory=/opt/hytale`nExecStart=/usr/bin/java -Xms2G -Xmx3G -jar Server/HytaleServer.jar --assets Assets.zip`nRestart=always`n[Install]`nWantedBy=multi-user.target"
    
    # We use base64 for EVERYTHING to avoid PowerShell parsing the Linux commands
    $Script = "systemctl stop hytale 2>/dev/null; mkdir -p /opt/hytale; chown hytale:hytale /opt/hytale; cd /opt/hytale; "
    $Script += "wget -q https://downloader.hytale.com/hytale-downloader.zip; apt-get update -qq; apt-get install -y unzip; unzip -o -q hytale-downloader.zip; chmod +x hytale-downloader-linux-amd64; "
    $Script += "su - hytale -c 'cd /opt/hytale && ./hytale-downloader-linux-amd64'; "
    $Script += "ZIP_FILE=\$(ls /opt/hytale/*.zip | grep -v 'downloader' | head -n 1); if [ -n \"\$ZIP_FILE\" ]; then unzip -o -q \"\$ZIP_FILE\"; chown -R hytale:hytale /opt/hytale; fi; "
    $Script += "echo '$Svc' > /etc/systemd/system/hytale.service; systemctl daemon-reload; systemctl enable hytale; "
    $Script += "echo '--- AUTH ---'; su - hytale -c 'cd /opt/hytale && java -Xms2G -Xmx3G -jar Server/HytaleServer.jar --assets Assets.zip'; "
    $Script += "systemctl start hytale"

    $B64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Script))
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$ServerIp "echo $B64 | base64 -d | bash"
    
    Log-Success "Done: $ServerIp:5520"
}

function Update-Server {
    param([string]$ServerName)
    Load-Config; Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Name" }
    $Ip = (Invoke-HetznerApi -Uri "/servers?name=$ServerName").servers[0].public_net.ipv4.ip
    $Upd = "systemctl stop hytale; su - hytale -c 'cd /opt/hytale && ./hytale-downloader-linux-amd64'; cd /opt/hytale; ZIP_FILE=\$(ls *.zip | grep -v 'downloader' | head -n 1); unzip -o -q \"\$ZIP_FILE\"; systemctl start hytale"
    $B64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Upd))
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$Ip "echo $B64 | base64 -d | bash"
    Log-Success "Updated."
}

function Get-Status {
    param([string]$ServerName)
    Load-Config; Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Name" }
    $S = (Invoke-HetznerApi -Uri "/servers?name=$ServerName").servers[0]
    Log-Success "Status: $($S.status) | IP: $($S.public_net.ipv4.ip)"
}

function Connect-Ssh {
    param([string]$ServerName)
    Load-Config; Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Name" }
    $Ip = (Invoke-HetznerApi -Uri "/servers?name=$ServerName").servers[0].public_net.ipv4.ip
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$Ip
}

# --- Main ---
if ([string]::IsNullOrEmpty($Command)) {
    Show-Banner
    Write-Host "  [1] Deploy  [2] Update  [3] Status  [4] SSH  [x] Exit"
    $A = Read-Host "  Option"
    if ($A -eq "1") { Deploy-Server }
    elseif ($A -eq "2") { Update-Server }
    elseif ($A -eq "3") { Get-Status }
    elseif ($A -eq "4") { Connect-Ssh }
    else { exit }
} else {
    if ($Command -eq "deploy") { Deploy-Server -ServerName $Name }
    elseif ($Command -eq "update") { Update-Server -ServerName $Name }
    elseif ($Command -eq "status") { Get-Status -ServerName $Name }
    elseif ($Command -eq "ssh") { Connect-Ssh -ServerName $Name }
}
