<#
.SYNOPSIS
Hytale Ops CLI (PowerShell Version) - Deploy Hytale Servers on Hetzner

.DESCRIPTION
Interactive tool to deploy, manage, and connect to Hytale game servers on Hetzner Cloud.
Zero external dependencies (uses native PowerShell + ssh.exe).

.EXAMPLE
.\hytale-ops.ps1
Run in interactive mode.

.EXAMPLE
.\hytale-ops.ps1 -Command deploy -Name "my-server"
Deploy a server named "my-server".
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
        # Convert SecureString back to plain text for API usage (local only)
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
        # Check PowerShell Version
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # Modern PowerShell (Core 7+)
            # Use SkipHttpErrorCheck to avoid exceptions on 4xx/5xx
            $Response = Invoke-WebRequest -Uri $Url -Method $Method -Headers $Headers -Body $JsonBody -SkipHttpErrorCheck
            
            # Check Status Code manually
            if ($Response.StatusCode -ge 400) {
                $ErrorContent = $Response.Content
                
                # Handle 401 Unauthorized
                if ($Response.StatusCode -eq 401) {
                    Log-Warn "Authentication failed (401 Unauthorized). Removing invalid token..."
                    $global:HetznerToken = $null
                    if (Test-Path $ConfigFile) { Remove-Item $ConfigFile -Force }
                    Check-Token
                    return Invoke-HetznerApi -Method $Method -Uri $Uri -Body $Body
                }
                
                Log-Error "API Error ($($Response.StatusCode))"
                Write-Host $ErrorContent -ForegroundColor Red
                exit 1
            }
            
            return $Response.Content | ConvertFrom-Json
        } else {
            # Legacy Windows PowerShell (5.1)
            # Use classic try/catch with WebException
            if ($Body) {
                $Response = Invoke-RestMethod -Uri $Url -Method $Method -Headers $Headers -Body $JsonBody -ErrorAction Stop
            } else {
                $Response = Invoke-RestMethod -Uri $Url -Method $Method -Headers $Headers -ErrorAction Stop
            }
            return $Response
        }

    } catch {
        # Fallback for unexpected network errors or PS 5.1 HTTP errors
        Log-Error "Request Failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
             # Attempt to read stream for PS 5.1
            try {
                $Stream = $_.Exception.Response.GetResponseStream()
                $Reader = New-Object System.IO.StreamReader($Stream)
                Write-Host $Reader.ReadToEnd() -ForegroundColor Red
            } catch {
                Write-Host "(Could not read error details)" -ForegroundColor DarkRed
            }
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
        $ServerName = Read-Host "🏷️  Enter Server Name (e.g., hytale-smp)"
        if ([string]::IsNullOrEmpty($ServerName)) { Log-Error "Name is required."; exit 1 }
    }

    # Select Type
    Write-Host "`n🖥️  Select Server Type (CPU / RAM / Price / Capacity):"
    Write-Host "1) cx23   (2 vCPU / 4GB RAM  / ~5€/mo  / ~1-5 Players)"
    Write-Host "2) cpx21  (3 vCPU / 4GB RAM  / ~8€/mo  / ~5-10 Players - Recommended)"
    Write-Host "3) cpx31  (4 vCPU / 8GB RAM  / ~14€/mo / ~10-20 Players)"
    Write-Host "4) cpx41  (8 vCPU / 16GB RAM / ~26€/mo / ~20-50 Players)"
    $TypeChoice = Read-Host "Choose an option [1-4]"
    
    $ServerType = switch ($TypeChoice) {
        "1" { "cx23" }
        "2" { "cpx21" }
        "3" { "cpx31" }
        "4" { "cpx41" }
        Default { "cpx21" }
    }
    Write-Host "Selected: $ServerType" -ForegroundColor Yellow

    # Select Location
    Write-Host "`n🌍 Select Data Center Location:"
    Write-Host "1) Nuremberg, Germany (nbg1)"
    Write-Host "2) Falkenstein, Germany (fsn1)"
    Write-Host "3) Helsinki, Finland (hel1)"
    Write-Host "4) Ashburn, USA (ash)"
    Write-Host "5) Hillsboro, USA (hil)"
    $LocChoice = Read-Host "Choose an option [1-5]"

    $Location = switch ($LocChoice) {
        "1" { "nbg1" }
        "2" { "fsn1" }
        "3" { "hel1" }
        "4" { "ash" }
        "5" { "hil" }
        Default { "nbg1" }
    }
    Write-Host "Selected: $Location" -ForegroundColor Yellow

    Log-Info "Deploying Hytale Server: $ServerName ($ServerType in $Location)..."

    # SSH Key Check
    if (-not (Test-Path $SshKeyPath)) {
        Log-Error "SSH key not found at $SshKeyPath. Please run 'ssh-keygen' first."
        exit 1
    }

    # Check/Upload SSH Key
    Log-Info "Verifying SSH Key on Hetzner..."
    $Keys = Invoke-HetznerApi -Uri "/ssh_keys?name=$SshKeyName"
    $SshKeyId = $null
    
    if ($Keys.ssh_keys.Count -eq 0) {
        Log-Warn "SSH Key '$SshKeyName' not found on Hetzner. Uploading..."
        
        $PubPath = "$SshKeyPath.pub"
        if (-not (Test-Path $PubPath)) {
            Log-Error "Public key not found at $PubPath. Please generate one with 'ssh-keygen'."
            exit 1
        }
        
        $PubKeyContent = Get-Content $PubPath -Raw
        $KeyBody = @{
            name = $SshKeyName
            public_key = $PubKeyContent
        }
        
        $NewKey = Invoke-HetznerApi -Method "POST" -Uri "/ssh_keys" -Body $KeyBody
        $SshKeyId = $NewKey.ssh_key.id
        Log-Success "SSH Key uploaded successfully (ID: $SshKeyId)."
    } else {
        $SshKeyId = $Keys.ssh_keys[0].id
        Log-Success "SSH Key '$SshKeyName' found (ID: $SshKeyId)."
    }

    # Check existence
    $Existing = Invoke-HetznerApi -Uri "/servers?name=$ServerName"
    if ($Existing.servers.Count -gt 0) {
        Log-Warn "Server '$ServerName' already exists (IP: $($Existing.servers[0].public_net.ipv4.ip))."
        $ServerIp = $Existing.servers[0].public_net.ipv4.ip
        
        $Confirm = Read-Host "Do you want to re-run the installation/configuration on this server? (y/n)"
        if ($Confirm -ne "y") {
            Log-Info "Skipping installation."
            return
        }
    } else {
        Log-Info "📦 Provisioning VPS on Hetzner..."
        
        $UserData = "#cloud-config`npackages:`n - openjdk-25-jre-headless`n - ufw`nruncmd:`n - ufw allow 22/tcp`n - ufw allow 25565/tcp`n - useradd -m -s /bin/bash hytale"
        
        $Body = @{
            name = $ServerName
            server_type = $ServerType
            image = $DefaultImage
            location = $Location
            ssh_keys = @($SshKeyId)
            user_data = $UserData
        }

        $Result = Invoke-HetznerApi -Method "POST" -Uri "/servers" -Body $Body
        $ServerIp = $Result.server.public_net.ipv4.ip
        Log-Success "Server created at $ServerIp."
    }

    Log-Info "⏳ Waiting for SSH to become available (this may take 1-2 minutes)..."
    
    # Retry loop for SSH
    $MaxRetries = 20
    $RetryCount = 0
    $SshReady = $false

    while (-not $SshReady -and $RetryCount -lt $MaxRetries) {
        Start-Sleep -Seconds 10
        $RetryCount++
        Write-Host -NoNewline "."
        
        # Test connection strictly (ConnectTimeout=5)
        # We redirect stderr to null to avoid ugly messages during checks
        $TestSsh = ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SshKeyPath" root@$ServerIp "echo ready" 2>$null
        
        if ($TestSsh -match "ready") {
            $SshReady = $true
            Write-Host "`n✅ SSH is UP!" -ForegroundColor Green
        }
    }

    if (-not $SshReady) {
        Log-Error "SSH Timed out after $($MaxRetries * 10) seconds. The server might still be booting."
        Log-Error "Try running 'ssh root@$ServerIp' manually later."
        exit 1
    }

    Log-Info "🔧 Configuring Hytale environment..."

    # Create Service File content
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

    # Remote Setup via SSH
    # Note: We use a Here-String for the remote script
    $RemoteScript = @"
mkdir -p /opt/hytale
chown hytale:hytale /opt/hytale
echo '$ServiceFile' > /etc/systemd/system/hytale.service
systemctl daemon-reload
systemctl enable hytale
"@
    
    # Using ssh.exe directly (standard on Win10/11)
    # We pipe the commands into ssh
    $RemoteScript | ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$ServerIp

    Write-Host "`n🎉 Deployment complete!" -ForegroundColor Green
    Write-Host "   Server Name: $ServerName" -ForegroundColor Yellow
    Write-Host "   IP Address:  $ServerIp" -ForegroundColor Yellow
    Write-Host "`n👉 To connect via SSH:"
    Write-Host "   ssh -i $SshKeyPath root@$ServerIp" -ForegroundColor Green
    Write-Host "`n👉 Or use this tool:"
    Write-Host "   .\hytale-ops.ps1 ssh $ServerName" -ForegroundColor Green
}

function Get-Status {
    param([string]$ServerName)
    Load-Config
    Check-Token

    if ([string]::IsNullOrEmpty($ServerName)) {
        $ServerName = Read-Host "🔍 Enter Server Name to check"
    }

    Log-Info "Checking status for $ServerName..."
    $Result = Invoke-HetznerApi -Uri "/servers?name=$ServerName"

    if ($Result.servers.Count -eq 0) {
        Log-Error "Server not found."
        return
    }

    $Server = $Result.servers[0]
    Write-Host "`nServer: $($Server.name)" -ForegroundColor Yellow
    Write-Host "ID:     $($Server.id)"
    Write-Host "Status: $($Server.status)" -ForegroundColor Green
    Write-Host "IP:     $($Server.public_net.ipv4.ip)" -ForegroundColor Cyan
    Write-Host "Type:   $($Server.server_type.name)"
}

function Connect-Ssh {
    param([string]$ServerName)
    Load-Config
    Check-Token

    if ([string]::IsNullOrEmpty($ServerName)) {
        $ServerName = Read-Host "🔌 Enter Server Name to connect"
    }

    $Result = Invoke-HetznerApi -Uri "/servers?name=$ServerName"
    if ($Result.servers.Count -eq 0) { Log-Error "Server not found."; exit 1 }
    
    $Ip = $Result.servers[0].public_net.ipv4.ip
    Log-Info "Connecting to $ServerName ($Ip)..."
    ssh -o StrictHostKeyChecking=no -i "$SshKeyPath" root@$Ip
}

# --- Main Dispatch ---

if ([string]::IsNullOrEmpty($Command)) {
    Write-Host "Hytale Ops CLI (PowerShell)" -ForegroundColor Cyan
    Write-Host "1) Deploy New Server"
    Write-Host "2) Check Status"
    Write-Host "3) SSH Connect"
    $Action = Read-Host "Choose an action [1-3]"
    
    switch ($Action) {
        "1" { Deploy-Server }
        "2" { Get-Status }
        "3" { Connect-Ssh }
        Default { Write-Host "Invalid option." }
    }
} else {
    switch ($Command) {
        "deploy" { Deploy-Server -ServerName $Name }
        "status" { Get-Status -ServerName $Name }
        "ssh"    { Connect-Ssh -ServerName $Name }
        Default  { Write-Host "Unknown command: $Command" }
    }
}
