#!/bin/bash

# Hytale Ops CLI - Linux/Mac Version
# Usage: ./hytale-ops.sh [deploy|update|status|ssh] [server_name]

set -e

# --- Configuration ---
CONFIG_FILE="$HOME/.config/hytale-ops/config.env"
SSH_KEY_NAME="hytale-deploy-key"
SSH_KEY_PATH="$HOME/.ssh/id_rsa"
DEFAULT_IMAGE="ubuntu-24.04"

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Helpers ---

log_info() { echo -e "${BLUE}[INFO] $1${NC}"; }
log_success() { echo -e "${GREEN}[OK]   $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERR]  $1${NC}"; }

load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
  fi
  if [ -n "$HCLOUD_TOKEN" ]; then
    HETZNER_TOKEN="$HCLOUD_TOKEN"
  fi
}

save_config() {
  mkdir -p "$(dirname "$CONFIG_FILE")"
  echo "HETZNER_TOKEN=\"$HETZNER_TOKEN\"" > "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
}

check_token() {
  if [ -z "$HETZNER_TOKEN" ]; then
    echo "🔑 Hetzner API Token not found."
    read -sp "Paste your HCloud API Token: " HETZNER_TOKEN
    echo ""
    if [ -z "$HETZNER_TOKEN" ]; then
      log_error "Token is required."
      exit 1
    fi
    save_config
    log_success "Token saved to $CONFIG_FILE"
  fi
}

call_hetzner() {
  local method=$1
  local uri=$2
  local body=$3
  
  if [ -n "$body" ]; then
    curl -s -X "$method" -H "Authorization: Bearer $HETZNER_TOKEN" \
         -H "Content-Type: application/json" -d "$body" \
         "https://api.hetzner.cloud/v1$uri"
  else
    curl -s -X "$method" -H "Authorization: Bearer $HETZNER_TOKEN" \
         "https://api.hetzner.cloud/v1$uri"
  fi
}

# --- Actions ---

deploy() {
  local name=$1
  load_config
  check_token

  if [ -z "$name" ]; then
    read -p "Enter Server Name (e.g., hytale-smp): " name
    if [ -z "$name" ]; then log_error "Name is required."; exit 1; fi
  fi

  echo ""
  echo "Select Server Type:"
  echo "1) cx23   (2 vCPU / 4GB RAM  / ~5 EUR/mo)"
  echo "2) cpx21  (3 vCPU / 4GB RAM  / ~8 EUR/mo)"
  read -p "Choose [1-2]: " type_choice
  case $type_choice in
    1) SERVER_TYPE="cx23" ;;
    2) SERVER_TYPE="cpx21" ;;
    *) SERVER_TYPE="cx23" ;;
  esac

  echo ""
  echo "Select Location:"
  echo "1) Nuremberg (nbg1)"
  echo "2) Falkenstein (fsn1)"
  read -p "Choose [1-2]: " loc_choice
  case $loc_choice in
    1) LOCATION="nbg1" ;;
    2) LOCATION="fsn1" ;;
    *) LOCATION="nbg1" ;;
  esac

  log_info "Deploying $name ($SERVER_TYPE)..."

  # SSH Key Logic
  if [ ! -f "$SSH_KEY_PATH" ]; then
    log_error "SSH key not found at $SSH_KEY_PATH. Please run ssh-keygen."
    exit 1
  fi

  keys=$(call_hetzner GET "/ssh_keys?name=$SSH_KEY_NAME")
  key_count=$(echo "$keys" | jq '.ssh_keys | length')
  
  if [ "$key_count" -eq 0 ]; then
    log_warn "Uploading SSH Key..."
    pub_key=$(cat "$SSH_KEY_PATH.pub")
    new_key=$(call_hetzner POST "/ssh_keys" "{\"name\":\"$SSH_KEY_NAME\",\"public_key\":\"$pub_key\"}")
    SSH_KEY_ID=$(echo "$new_key" | jq -r '.ssh_key.id')
  else
    SSH_KEY_ID=$(echo "$keys" | jq -r '.ssh_keys[0].id')
  fi

  # Check Server Existence
  existing=$(call_hetzner GET "/servers?name=$name")
  existing_count=$(echo "$existing" | jq '.servers | length')

  if [ "$existing_count" -gt 0 ]; then
    SERVER_IP=$(echo "$existing" | jq -r '.servers[0].public_net.ipv4.ip')
    log_warn "Server exists (IP: $SERVER_IP). Re-run setup? (y/n)"
    read -p "> " confirm
    if [ "$confirm" != "y" ]; then return; fi
  else
    log_info "Provisioning VPS..."
    user_data="#cloud-config\npackages:\n - openjdk-25-jre-headless\n - ufw\nruncmd:\n - ufw allow 22/tcp\n - ufw allow 5520/udp\n - ufw allow 5520/tcp\n - useradd -m -s /bin/bash hytale"
    
    body=$(jq -n \
      --arg name "$name" \
      --arg type "$SERVER_TYPE" \
      --arg img "$DEFAULT_IMAGE" \
      --arg loc "$LOCATION" \
      --arg key "$SSH_KEY_ID" \
      --arg ud "$user_data" \
      '{name:$name, server_type:$type, image:$img, location:$loc, ssh_keys:[($key|tonumber)], user_data:$ud}')

    result=$(call_hetzner POST "/servers" "$body")
    SERVER_IP=$(echo "$result" | jq -r '.server.public_net.ipv4.ip')
    
    if [ "$SERVER_IP" == "null" ]; then
      log_error "Creation failed: $(echo "$result" | jq -r '.error.message')"
      exit 1
    fi
    log_success "Server created: $SERVER_IP"
  fi

  log_info "Waiting for SSH..."
  for i in {1..30}; do
    echo -n "."
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY_PATH" root@"$SERVER_IP" exit 2>/dev/null; then
      echo ""
      log_success "SSH UP!"
      break
    fi
    sleep 10
  done

  log_info "Configuring Hytale..."

  SERVICE_FILE="[Unit]
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
WantedBy=multi-user.target"

  # We use base64 to avoid escaping hell in bash heredocs
  SETUP_SCRIPT=$(cat <<EOF
systemctl stop hytale 2>/dev/null
mkdir -p /opt/hytale
chown hytale:hytale /opt/hytale
cd /opt/hytale

# Download
wget -q https://downloader.hytale.com/hytale-downloader.zip
apt-get update -qq && apt-get install -y unzip jq
unzip -o -q hytale-downloader.zip
chmod +x hytale-downloader-linux-amd64

# Fetch Game
su - hytale -c 'cd /opt/hytale && ./hytale-downloader-linux-amd64'

# Extract
cd /opt/hytale
ZIP_FILE=\$(ls *.zip | grep -v 'hytale-downloader.zip' | head -n 1)
if [ -n "\$ZIP_FILE" ]; then
    unzip -o -q "\$ZIP_FILE"
    chown -R hytale:hytale /opt/hytale
fi

# Firewall
ufw allow 5520/udp
ufw allow 5520/tcp
ufw --force enable

# Service
echo "$SERVICE_FILE" > /etc/systemd/system/hytale.service
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
EOF
)

  # Send encoded script
  B64_SCRIPT=$(echo "$SETUP_SCRIPT" | base64 -w 0)
  ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" root@"$SERVER_IP" "echo $B64_SCRIPT | base64 -d | bash"

  log_success "Deployment complete!"
  echo -e "   Address: ${YELLOW}$SERVER_IP:5520${NC}"
}

update() {
  local name=$1
  load_config
  check_token
  
  if [ -z "$name" ]; then read -p "Server Name: " name; fi
  
  res=$(call_hetzner GET "/servers?name=$name")
  ip=$(echo "$res" | jq -r '.servers[0].public_net.ipv4.ip')
  
  if [ "$ip" == "null" ]; then log_error "Not found."; exit 1; fi
  
  log_info "Updating $name ($ip)..."
  
  UPDATE_SCRIPT=$(cat <<EOF
systemctl stop hytale
su - hytale -c 'cd /opt/hytale && ./hytale-downloader-linux-amd64'
cd /opt/hytale
ZIP_FILE=\$(ls *.zip | grep -v 'hytale-downloader.zip' | head -n 1)
if [ -n "\$ZIP_FILE" ]; then
    unzip -o -q "\$ZIP_FILE"
    chown -R hytale:hytale /opt/hytale
fi
systemctl start hytale
systemctl status hytale --no-pager
EOF
)
  
  B64_UPDATE=$(echo "$UPDATE_SCRIPT" | base64 -w 0)
  ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" root@"$ip" "echo $B64_UPDATE | base64 -d | bash"
  log_success "Update complete!"
}

status() {
  local name=$1
  load_config
  check_token
  
  if [ -z "$name" ]; then read -p "Server Name: " name; fi
  
  res=$(call_hetzner GET "/servers?name=$name")
  ip=$(echo "$res" | jq -r '.servers[0].public_net.ipv4.ip')
  status=$(echo "$res" | jq -r '.servers[0].status')
  
  if [ "$ip" == "null" ]; then log_error "Not found."; return; fi
  
  echo ""
  echo -e "Status: ${GREEN}$status${NC} | Address: ${YELLOW}$ip:5520${NC}"
}

ssh_connect() {
  local name=$1
  load_config
  check_token
  
  if [ -z "$name" ]; then read -p "Server Name: " name; fi
  
  res=$(call_hetzner GET "/servers?name=$name")
  ip=$(echo "$res" | jq -r '.servers[0].public_net.ipv4.ip')
  
  if [ "$ip" == "null" ]; then log_error "Not found."; exit 1; fi
  
  ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" root@"$ip"
}

# --- Main ---

if [ $# -eq 0 ]; then
  echo "Hytale Ops CLI (Bash)"
  echo "1) Deploy / Re-install"
  echo "2) Update Server"
  echo "3) Status"
  echo "4) SSH"
  read -p "Option: " opt
  case $opt in
    1) deploy ;;
    2) update ;;
    3) status ;;
    4) ssh_connect ;;
  esac
else
  case "$1" in
    deploy) deploy "$2" ;;
    update) update "$2" ;;
    status) status "$2" ;;
    ssh)    ssh_connect "$2" ;;
    *)      echo "Usage: $0 {deploy|update|status|ssh} [name]" ;;
  esac
fi
