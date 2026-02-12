#!/bin/bash

# Hytale Ops CLI - Interactive Deployment Tool
# Usage: ./hytale-ops.sh [deploy|status|ssh|destroy] [server_name]

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

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
  fi
  # Fallback to env var if set
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

# --- Interactive Prompts ---

select_server_type() {
  echo ""
  echo "🖥️  Select Server Type (CPU / RAM / Price / Capacity):"
  echo "1) cx22   (2 vCPU / 4GB RAM  / ~4€/mo  / ~1-5 Players)"
  echo "2) cpx21  (3 vCPU / 4GB RAM  / ~8€/mo  / ~5-10 Players - Recommended)"
  echo "3) cpx31  (4 vCPU / 8GB RAM  / ~14€/mo / ~10-20 Players)"
  echo "4) cpx41  (8 vCPU / 16GB RAM / ~26€/mo / ~20-50 Players)"
  
  read -p "Choose an option [1-4]: " choice
  case $choice in
    1) SERVER_TYPE="cx22" ;;
    2) SERVER_TYPE="cpx21" ;;
    3) SERVER_TYPE="cpx31" ;;
    4) SERVER_TYPE="cpx41" ;;
    *) SERVER_TYPE="cpx21"; log_warn "Invalid choice, defaulting to cpx21" ;;
  esac
  echo -e "Selected: ${YELLOW}$SERVER_TYPE${NC}"
}

select_location() {
  echo ""
  echo "🌍 Select Data Center Location:"
  echo "1) Nuremberg, Germany (nbg1)"
  echo "2) Falkenstein, Germany (fsn1)"
  echo "3) Helsinki, Finland (hel1)"
  echo "4) Ashburn, USA (ash)"
  echo "5) Hillsboro, USA (hil)"
  
  read -p "Choose an option [1-5]: " choice
  case $choice in
    1) LOCATION="nbg1" ;;
    2) LOCATION="fsn1" ;;
    3) LOCATION="hel1" ;;
    4) LOCATION="ash" ;;
    5) LOCATION="hil" ;;
    *) LOCATION="nbg1"; log_warn "Invalid choice, defaulting to nbg1" ;;
  esac
  echo -e "Selected: ${YELLOW}$LOCATION${NC}"
}

# --- Core Functions ---

deploy() {
  local name=$1
  load_config
  check_token

  if [ -z "$name" ]; then
    read -p "🏷️  Enter Server Name (e.g., hytale-smp): " name
    if [ -z "$name" ]; then log_error "Name is required."; exit 1; fi
  fi

  select_server_type
  select_location

  echo ""
  log_info "Deploying Hytale Server: $name ($SERVER_TYPE in $LOCATION)..."

  # SSH Key Check
  if [ ! -f "$SSH_KEY_PATH" ]; then
    log_error "SSH key not found at $SSH_KEY_PATH. Please generate one first."
    exit 1
  fi
  
  # Check existence
  existing_id=$(curl -s -H "Authorization: Bearer $HETZNER_TOKEN" \
    "https://api.hetzner.cloud/v1/servers?name=$name" | jq -r '.servers[0].id')

  if [ "$existing_id" != "null" ] && [ "$existing_id" != "" ]; then
    log_warn "Server '$name' already exists (ID: $existing_id). Fetching IP..."
    SERVER_IP=$(curl -s -H "Authorization: Bearer $HETZNER_TOKEN" \
      "https://api.hetzner.cloud/v1/servers/$existing_id" | jq -r '.server.public_net.ipv4.ip')
  else
    # Create Server
    log_info "📦 Provisioning VPS on Hetzner..."
    create_response=$(curl -s -X POST -H "Authorization: Bearer $HETZNER_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"name\": \"$name\",
        \"server_type\": \"$SERVER_TYPE\",
        \"image\": \"$DEFAULT_IMAGE\",
        \"location\": \"$LOCATION\",
        \"ssh_keys\": [\"$SSH_KEY_NAME\"],
        \"user_data\": \"#cloud-config\npackages:\n - openjdk-25-jre-headless\n - ufw\nruncmd:\n - ufw allow 22/tcp\n - ufw allow 25565/tcp\n - useradd -m -s /bin/bash hytale\" 
      }" "https://api.hetzner.cloud/v1/servers")
    
    SERVER_IP=$(echo "$create_response" | jq -r '.server.public_net.ipv4.ip')
    
    if [ "$SERVER_IP" == "null" ] || [ -z "$SERVER_IP" ]; then
      log_error "Error creating server: $(echo "$create_response" | jq -r '.error.message')"
      exit 1
    fi

    log_success "Server created at $SERVER_IP. Waiting for SSH (approx 30s)..."
    sleep 30
  fi

  log_info "🔧 Configuring Hytale environment..."
  
  # Remote Setup
  ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" root@"$SERVER_IP" << 'EOF'
    # Setup Directory
    mkdir -p /opt/hytale
    chown hytale:hytale /opt/hytale
    
    # Systemd Service
    cat <<SERVICE > /etc/systemd/system/hytale.service
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
SERVICE

    systemctl daemon-reload
    systemctl enable hytale
EOF

  echo ""
  log_success "🎉 Deployment complete!"
  echo -e "   Server Name: ${YELLOW}$name${NC}"
  echo -e "   IP Address:  ${YELLOW}$SERVER_IP${NC}"
  echo -e "   Type:        ${YELLOW}$SERVER_TYPE${NC}"
  echo -e "   Location:    ${YELLOW}$LOCATION${NC}"
  echo ""
  log_info "👉 To connect via SSH:"
  echo -e "   ${GREEN}ssh -i $SSH_KEY_PATH root@$SERVER_IP${NC}"
  echo ""
  log_info "👉 Or use this tool:"
  echo -e "   ${GREEN}./hytale-ops.sh ssh $name${NC}"
}

status() {
  local name=$1
  load_config
  check_token
  
  if [ -z "$name" ]; then
    read -p "🔍 Enter Server Name to check: " name
  fi

  log_info "Checking status for $name..."
  response=$(curl -s -H "Authorization: Bearer $HETZNER_TOKEN" "https://api.hetzner.cloud/v1/servers?name=$name")
  
  id=$(echo "$response" | jq -r '.servers[0].id')
  if [ "$id" == "null" ]; then
    log_error "Server not found."
    return
  fi
  
  ip=$(echo "$response" | jq -r '.servers[0].public_net.ipv4.ip')
  status=$(echo "$response" | jq -r '.servers[0].status')
  type=$(echo "$response" | jq -r '.servers[0].server_type.name')
  
  echo ""
  echo -e "Server: ${YELLOW}$name${NC}"
  echo -e "ID:     $id"
  echo -e "Status: ${GREEN}$status${NC}"
  echo -e "IP:     ${BLUE}$ip${NC}"
  echo -e "Type:   $type"
}

ssh_connect() {
  local name=$1
  load_config
  check_token

  if [ -z "$name" ]; then
    read -p "🔌 Enter Server Name to connect: " name
  fi

  ip=$(curl -s -H "Authorization: Bearer $HETZNER_TOKEN" \
    "https://api.hetzner.cloud/v1/servers?name=$name" | jq -r '.servers[0].public_net.ipv4.ip')
  
  if [ "$ip" == "null" ] || [ -z "$ip" ]; then log_error "Server not found"; exit 1; fi
  
  log_info "Connecting to $name ($ip)..."
  ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" root@"$ip"
}

# --- Main ---

if [ $# -eq 0 ]; then
  echo "Usage: $0 {deploy|status|ssh} [server_name]"
  exit 1
fi

case "$1" in
  deploy) deploy "$2" ;;
  status) status "$2" ;;
  ssh)    ssh_connect "$2" ;;
  *)      echo "Usage: $0 {deploy|status|ssh} [server_name]" ;;
esac
