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
    
    try {
        if ($Body) {
            $JsonBody = $Body | ConvertTo-Json -Depth 10
            Invoke-RestMethod -Uri "https://api.hetzner.cloud/v1$Uri" -Method $Method -Headers $Headers -Body $JsonBody
        } else {
            Invoke-RestMethod -Uri "https://api.hetzner.cloud/v1$Uri" -Method $Method -Headers $Headers
        }
    } catch {
        # Capture error details immediately
        $ErrorMessage = $_.Exception.Message
        $ErrorContent = ""
        
        if ($_.Exception.Response) {
             # Read content based on PS version
            if ($_.Exception.Response.GetType().Name -eq "HttpResponseMessage") {
                # PowerShell Core / 7+ (HttpClient based)
                # Need to read content before disposing
                try {
                    $ErrorContent = $_.Exception.Response.Content.ReadAsStringAsync().Result
                } catch {
                    $ErrorContent = "(Could not read error content)"
                }
            } elseif ($_.Exception.Response.GetResponseStream) {
                # Windows PowerShell 5.1 (WebClient based)
                $Stream = $_.Exception.Response.GetResponseStream()
                $Reader = New-Object System.IO.StreamReader($Stream)
                $ErrorContent = $Reader.ReadToEnd()
            }
            
            # Auto-retry on 401 Unauthorized
            if ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::Unauthorized) {
                Log-Warn "Authentication failed (401 Unauthorized). Removing invalid token..."
                $global:HetznerToken = $null
                if (Test-Path $ConfigFile) { Remove-Item $ConfigFile -Force }
                
                # Retry logic: ask for new token
                Check-Token
                
                # Re-run the API call with new token (simple retry)
                # Note: Recursion risk if new token also fails 401
                return Invoke-HetznerApi -Method $Method -Uri $Uri -Body $Body
            }
        }

        Log-Error "API Error: $ErrorMessage"
        if (-not [string]::IsNullOrEmpty($ErrorContent)) {
            Write-Host $ErrorContent -ForegroundColor Red
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
    Write-Host "1) cx22   (2 vCPU / 4GB RAM  / ~4€/mo  / ~1-5 Players)"
    Write-Host "2) cpx21  (3 vCPU / 4GB RAM  / ~8€/mo  / ~5-10 Players - Recommended)"
    Write-Host "3) cpx31  (4 vCPU / 8GB RAM  / ~14€/mo / ~10-20 Players)"
    Write-Host "4) cpx41  (8 vCPU / 16GB RAM / ~26€/mo / ~20-50 Players)"
    $TypeChoice = Read-Host "Choose an option [1-4]"
    
    $ServerType = switch ($TypeChoice) {
        "1" { "cx22" }
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
        Log-Warn "Server '$ServerName' already exists. Fetching info..."
        $ServerIp = $Existing.servers[0].public_net.ipv4.ip
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
        
        Log-Success "Server created at $ServerIp. Waiting for SSH (approx 30s)..."
        Start-Sleep -Seconds 30
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
