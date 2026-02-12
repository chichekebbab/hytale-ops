<#
.SYNOPSIS
Hytale Ops CLI (Final Bulletproof Version)
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
    Write-Host " |_||_| \_, |  \__|\__,_||_| \___|      \___/ | .__//__/  " -ForegroundColor Cyan
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

    Write-Host "`n  Available Plans:" -ForegroundColor Gray
    Write-Host "  1) cx23   (2 vCPU / 4GB RAM)  ~5 EUR/mo (Recommended)" -ForegroundColor White
    Write-Host "  2) cpx21  (3 vCPU / 4GB RAM)  ~8 EUR/mo" -ForegroundColor White
    $TypeChoice = Read-Host "  Choose [1-2]"
    $ServerType = if ($TypeChoice -eq "2") { "cpx21" } else { "cx23" }

    Write-Host "`n  Select Location:" -ForegroundColor Gray
    Write-Host "  1) Nuremberg (nbg1)" -ForegroundColor White
    Write-Host "  2) Falkenstein (fsn1)" -ForegroundColor White
    $LocChoice = Read-Host "  Choose [1-2]"
    $Location = if ($LocChoice -eq "2") { "fsn1" } else { "nbg1" }

    Log-Info "Deploying..."

    # SSH Key Check
    if (-not (Test-Path $SshKeyPath)) { Log-Error "SSH key missing at $SshKeyPath"; exit 1 }
    
    $Keys = Invoke-HetznerApi -Uri "/ssh_keys?name=$SshKeyName"
    $SshKeyId = if ($Keys.ssh_keys.Count -eq 0) {
        $Pub = Get-Content "$SshKeyPath.pub" -Raw
        (Invoke-HetznerApi -Method POST -Uri "/ssh_keys" -Body @{name=$SshKeyName; public_key=$Pub}).ssh_key.id
    } else { $Keys.ssh_keys[0].id }

    # Server Check
    $Existing = Invoke-HetznerApi -Uri "/servers?name=$ServerName"
    if ($Existing.servers.Count -gt 0) {
        $ServerIp = $Existing.servers[0].public_net.ipv4.ip
        Log-Warn "Server '$ServerName' already exists at $ServerIp."
        Write-Host "  Re-run setup/overwrite? (y/n): " -NoNewline -ForegroundColor White
        $Confirm = Read-Host
        if ($Confirm -ne "y") { 
            Write-Host "  Aborted." -ForegroundColor Yellow
            return 
        }
    } else {
        $UserData = "#cloud-config`npackages:`n - openjdk-25-jre-headless`n - ufw`nruncmd:`n - ufw allow 22/tcp`n - ufw allow 5520/udp`n - ufw allow 5520/tcp`n - useradd -m -s /bin/bash hytale"
        $Body = @{ name = $ServerName; server_type = $ServerType; image = $DefaultImage; location = $Location; ssh_keys = @($SshKeyId); user_data = $UserData }
        $ServerIp = (Invoke-HetznerApi -Method POST -Uri "/servers" -Body $Body).server.public_net.ipv4.ip
        Log-Success "VPS Created: $ServerIp"
    }

    Log-Info "Waiting for SSH..."
    Start-Sleep 20
    
    # ---------------------------------------------------------
    # BASH SCRIPT (Base64 Encoded)
    # This prevents ANY PowerShell parsing errors with $, ", or &&
    # ---------------------------------------------------------
    
    # Payload: Install Java/Unzip, Download Hytale, Auth Prompt, Systemd Service
    $Payload = "c3lzdGVtY3RsIHN0b3AgaHl0YWxlIDI+L2Rldi9udWxsCm1rZGlyIC1wIC9vcHQvaHl0YWxlCmNob3duIGh5dGFsZTpoeXRhbGUgL29wdC9oeXRhbGUKY2QgL29wdC9oeXRhbGUKCndnZXQgLXEgaHR0cHM6Ly9kb3dubG9hZGVyLmh5dGFsZS5jb20vaHl0YWxlLWRvd25sb2FkZXIuemlwCmFwdC1nZXQgdXBkYXRlIC1xcQphcHQtZ2V0IGluc3RhbGwgLXkgdW56aXAKdW56aXAgLW8gLXEgaHl0YWxlLWRvd25sb2FkZXIuemlwCmNobW9kICt4IGh5dGFsZS1kb3dubG9hZGVyLWxpbnV4LWFtZDY0CgpzdSAtIGh5dGFsZSAtYyAnY2QgL29wdC9oeXRhbGUgJiYgLi9oeXRhbGUtZG93bmxvYWRlci1saW51eC1hbWQ2NCcKCiMgRXh0cmFjdApjZCAvb3B0L2h5dGFsZQpaSVBfRklMRT0kKGxzICouemlwIHwgZ3JlcCAtdiAnaHl0YWxlLWRvd25sb2FkZXIuemlwJyB8IGhlYWQgLW4gMSkKaWYgWyAtbiAiJFpJUF9GSUxFIiBdOyB0aGVuCiAgICBlY2hvICJFeHRyYWN0aW5nICRaSVBfRklMRS4uLiIKICAgIHVuemlwIC1vIC1xICIkWklQX0ZJTEUiCiAgICBjaG93biAtUiBoeXRhbGU6aHl0YWxlIC9vcHQvaHl0YWxlCmZpCgojIEZpcmV3YWxsCnVZdyBhbGxvdyA1NTIwL3VkcAp1ZncgYWxsb3cgNTUyMC90Y3AKdWZ3IC0tZm9yY2UgZW5hYmxlCgojIFNlcnZpY2UKZWNobyAnW1VuaXRdCkRlc2NyaXB0aW9uPUh5dGFsZSBEZWRpY2F0ZWQgU2VydmVyCkFmdGVyPW5ldHdvcmsudGFyZ2V0CltTZXJ2aWNlXQpVc2VyPWh5dGFsZQpHcm91cD1oeXRhbGUKV29ya2luZ0RpcmVjdG9yeT0vb3B0L2h5dGFsZQpFeGVjU3RhcnQ9L3Vzci9iaW4vamF2YSAtWG1zMkcgLVhteDNHIC1qYXIgU2VydmVyL0h5dGFsZVNlcnZlci5qYXIgLS1hc3NldHMgQXNzZXRzLnppcApSZXN0YXJ0PWFsd2F5cwpSZXN0YXJ0U2VjPTEwCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldCcgPiAvZXRjL3N5c3RlbWQvc3lzdGVtL2h5dGFsZS5zZXJ2aWNlCnN5c3RlbWN0bCBkYWVtb24tcmVsb2FkCnN5c3RlbWN0bCBlbmFibGUgaHl0YWxlCgplY2hvICctLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJwplY2hvICdTRVRVUCBQQVVTRUQ6IEFVVEhFTlRJQ0FUSU9OIFJFUVVJUkVEJwplY2hvICcxLiBTZXJ2ZXIgc3RhcnRpbmcgSU5URVJBQ1RJVkUgbW9kZS4nCmVjaG8gJzIuIExvb2sgZm9yIFVSTCB3aXRoIGNvZGU6IGh0dHBzOi8vLi4uL3ZlcmlmeT91c2VyX2NvZGU9Li4uJwplY2hvICczLiBBdXRoZW50aWNhdGUgb24gd2ViLycKZWNobyAnNC4gQ1JJVElDQUw6IFR5cGUgIi9hdXRoIHBlcnNpc3RlbmNlIEVuY3J5cHRlZCIgdG8gc2F2ZSEnCmVjaG8gJzUuIFR5cGUgInN0b3AiIHRvIGZpbmlzaC4nCmVjaG8gJy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0nCnJlYWQgLXAgJ1ByZXNzIEVOVEVSIHRvIHN0YXJ0IGF1dGguLi4nCgpzdSAtIGh5dGFsZSAtYyAnY2QgL29wdC9oeXRhbGUgJiYgamF2YSAtWG1zMkcgLVhteDNHIC1qYXIgU2VydmVyL0h5dGFsZVNlcnZlci5qYXIgLS1hc3NldHMgQXNzZXRzLnppcCcKCmVjaG8gJ1N0YXJ0aW5nIGJhY2tncm91bmQgc2VydmljZS4uLicKc3lzdGVtY3RsIHN0YXJ0IGh5dGFsZQpzeXN0ZW1jdGwgc3RhdHVzIGh5dGFsZSAtLW5vLXBhZ2VyCg=="

    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$ServerIp "echo $Payload | base64 -d | bash"
    
    Log-Success "Deployment finished! Address: $ServerIp:5520"
}

function Update-Server {
    param([string]$ServerName)
    Load-Config; Check-Token
    if ([string]::IsNullOrEmpty($ServerName)) { $ServerName = Read-Host "Name" }
    $Ip = (Invoke-HetznerApi -Uri "/servers?name=$ServerName").servers[0].public_net.ipv4.ip
    
    # BASH UPDATE SCRIPT (Base64 Encoded)
    $Payload = "c3lzdGVtY3RsIHN0b3AgaHl0YWxlCnN1IC0gaHl0YWxlIC1jICdjZCAvb3B0L2h5dGFsZSAmJiAuL2h5dGFsZS1kb3dubG9hZGVyLWxpbnV4LWFtZDY0JwpjZCAvb3B0L2h5dGFsZQpaSVBfRklMRT0kKGxzICouemlwIHwgZ3JlcCAtdiAnaHl0YWxlLWRvd25sb2FkZXIuemlwJyB8IGhlYWQgLW4gMSkKaWYgWyAtbiAiJFpJUF9GSUxFIiBdOyB0aGVuCiAgICB1bnppcCAtbyAtcSAiJFpJUF9GSUxFIgogICAgY2hvd24gLVIgaHl0YWxlOmh5dGFsZSAvb3B0L2h5dGFsZQpmaQpzeXN0ZW1jdGwgc3RhcnQgaHl0YWxlCg=="
    
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$Ip "echo $Payload | base64 -d | bash"
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
