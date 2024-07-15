#!/bin/bash

# Nginx Proxy Manager CLI Script v1.1.1
# Erreur32 - July 2024
#
# This script allows you to manage Nginx Proxy Manager via the API. It provides
# functionalities such as creating proxy hosts, managing users, listing hosts,
# backing up configurations, and more.
#
# Usage:
#   ./nginx_proxy_manager_cli.sh [OPTIONS]
#
# Examples:
#
# 📦 Backup First!
#   ./nginx_proxy_manager_cli.sh --host-backup
#
# 🌐 Host Creation:
#   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 (check default values below)
#   ./nginx_proxy_manager_cli.sh --host-show-default
#   ./nginx_proxy_manager_cli.sh --host-create-user newuser password123 user@example.com
#   ./nginx_proxy_manager_cli.sh --host-delete-user 'username'
#   ./nginx_proxy_manager_cli.sh --host-list
#   ./nginx_proxy_manager_cli.sh --host-ssl-enable 10
#
# 🔧 Advanced Example:
#   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'
#
#   Custom Certificate:
#   ./nginx_proxy_manager_cli.sh --host-generate-cert example.com user@example.com --custom
#
#   Custom locations:
#   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'
#
#
# Options:
#
# 🌐 Host proxy creation:
#   -d DOMAIN_NAMES                       Domain name (required for creating/updating hosts)
#   -i FORWARD_HOST                       IP address or domain name of the target server (required for creating/updating hosts)
#   -p FORWARD_PORT                       Port of the target server (required for creating/updating hosts)
#   -f FORWARD_SCHEME                     Scheme for forwarding (http/https, default: http)
#   -c CACHING_ENABLED                    Enable caching (true/false, default: false)
#   -b BLOCK_EXPLOITS                     Block exploits (true/false, default: true)
#   -w ALLOW_WEBSOCKET_UPGRADE            Allow WebSocket upgrade (true/false, default: true)
#   -l CUSTOM_LOCATIONS                   Custom locations (JSON array of location objects)"
#   -a ADVANCED_CONFIG                    Advanced configuration (block of configuration settings)
#
# 📦 Backup and Restore:
#   --host-backup                         Backup all configurations to a file
#   --host-backup-id id                   Backup a single host configuration and its certificate (if exists)
#   --host-restore                        Restore configurations from a backup file
#   --host-restore-id id                  Restore a single host configuration and its certificate (if exists)
#
# 🔧 Miscellaneous:
#   --host-check-token                    Check if the current token is valid
#   --host-create-user user pass email    Create a user with a username, password and email
#   --host-delete-user username           Delete a user by username
#   --host-delete id                      Delete a proxy host by ID
#   --host-show id                        Show full details for a specific host by ID
#   --host-show-default                   Show default settings for creating hosts
#   --host-list                           List the names of all proxy hosts
#   --host-list-full                      List all proxy hosts with full details
#   --host-list-ssl-certificates          List all SSL certificates
#   --host-list-users                     List all users
#   --host-search hostname                Search for a proxy host by domain name
#   --host-enable id                      Enable a proxy host by ID
#   --host-disable id                     Disable a proxy host by ID
#   --host-ssl-enable id                  Enable SSL, HTTP/2, and HSTS for a proxy host
#   --host-ssl-disable id                 Disable SSL, HTTP/2, and HSTS for a proxy host
#   --host-generate-cert domain email [--custom] Generate a Let's Encrypt or Custom certificate for the given domain and email
#   --host-help                           Display this help

################################
# Variables to Edit (required) #
################################

NGINX_IP="127.0.0.1"
# Existing nginx user
API_USER="user@nginx"
API_PASS="pass nginx"

#################################
# Variables to Edit (optional) #
#################################

# Will create backup directory automatically
BACKUP_DIR="./backups"
DATE=$(date +"%Y%m%d%H%M%S")

# API Endpoints
BASE_URL="http://$NGINX_IP:81/api"
API_ENDPOINT="/tokens"
EXPIRY_FILE="expiry_${NGINX_IP}.txt"
TOKEN_FILE="token_${NGINX_IP}.txt"
# Set Token duration validity.
TOKEN_EXPIRY="1y"

# Default variables
CACHING_ENABLED=false
BLOCK_EXPLOITS=true
ALLOW_WEBSOCKET_UPGRADE=1
HTTP2_SUPPORT=0
ADVANCED_CONFIG=""
LETS_ENCRYPT_AGREE=false
LETS_ENCRYPT_EMAIL=""
FORWARD_SCHEME="http"
FORCE_CERT_CREATION=false
SSL_FORCED=0
HSTS_ENABLED=0
HSTS_SUBDOMAINS=0

# Control variables
CREATE_USER=false
DELETE_USER=false
DELETE_HOST=false
LIST_HOSTS=false
LIST_HOSTS_FULL=false
LIST_SSL_CERTIFICATES=false
LIST_USERS=false
SEARCH_HOST=false
ENABLE_HOST=false
DISABLE_HOST=false
CHECK_TOKEN=false
BACKUP=false
BACKUP_HOST=false
RESTORE=false
RESTORE_HOST=false
GENERATE_CERT=false
ENABLE_SSL=false
DISABLE_SSL=false
SHOW_HOST=false
SHOW_DEFAULT=false
CUSTOM_CERT=false

# Colors
COLOR_GREEN="\033[32m"
COLOR_RED="\033[41;1m"
COLOR_ORANGE="\033[38;5;202m"
COLOR_YELLOW="\033[93m"
COLOR_RESET="\033[0m"
WHITE_ON_GREEN="\033[30;48;5;83m"

# Check if necessary dependencies are installed
check_dependencies() {
  local dependencies=("curl" "jq")
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      echo -e "${COLOR_RED}Dependency $dep is not installed. Please install it before running this script.${COLOR_RESET}"
      exit 1
    fi
  done
}

check_dependencies

# Display help
usage() {
  echo -e "\n${COLOR_YELLOW}Usage: ./nginx_proxy_manager_cli.sh -d domain -i ip -p port [-f forward_scheme] [-c caching_enabled] [-b block_exploits] [-w allow_websocket_upgrade] [-a advanced_config] [-t token_expiry] [--host-create-user username password email] [--host-delete-user username] [--host-delete id] [--host-list] [--host-list-full] [--host-list-ssl-certificates] [--host-list-users] [--host-search hostname] [--host-enable id] [--host-disable id] [--host-check-token] [--host-backup] [--host-backup-id id] [--host-restore] [--host-restore-id id] [--host-generate-cert domain email [--custom]] [--host-ssl-enable id] [--host-ssl-disable id] [--host-show id] [--host-show-default] [--host-help]${COLOR_RESET}"
  echo ""
  echo -e "Examples:"
  echo -e "\n 📦 Backup First before doing anything!"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-backup"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-backup-id 10"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-restore"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-restore-id 10"
  echo -e "\n 🌐 Host Creation"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-show-default"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-ssl-enable 10"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-show 10"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-list"
  echo -e "\n 👤 User Management"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-create-user newuser password123 user@example.com"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-delete-user 'username'"
  echo -e "\n 🔧 Advanced Example:"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;'"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-generate-cert example.com user@example.com --custom"
  echo -e "\n 📁 Custom locations:"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"
  echo -e "\n 🔖 Full option:"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -f https -c true -b true -w true -a 'proxy_set_header X-Real-IP \$remote_addr;' -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"
  echo -e ""
  echo -e "Options:"
  echo -e "  -d ${COLOR_ORANGE}DOMAIN_NAMES${COLOR_RESET}                             Domain name (${COLOR_RED}required${COLOR_RESET})"
  echo -e "  -i ${COLOR_ORANGE}FORWARD_HOST${COLOR_RESET}                             IP address or domain name of the target server (${COLOR_RED}required${COLOR_RESET})"
  echo -e "  -p ${COLOR_ORANGE}FORWARD_PORT${COLOR_RESET}                             Port of the target server (${COLOR_RED}required${COLOR_RESET})"
  echo -e "  -f FORWARD_SCHEME                           Scheme for forwarding (http/https, default: $(colorize_booleanh $FORWARD_SCHEME))"
  echo -e "  -c CACHING_ENABLED                          Enable caching (true/false, default: $(colorize_boolean $CACHING_ENABLED))"
  echo -e "  -b BLOCK_EXPLOITS                           Block exploits (true/false, default: $(colorize_boolean $BLOCK_EXPLOITS))"
  echo -e "  -w ALLOW_WEBSOCKET_UPGRADE                  Allow WebSocket upgrade (true/false, default: $(colorize_boolean $ALLOW_WEBSOCKET_UPGRADE))"
  echo -e "  -l CUSTOM_LOCATIONS                         Custom locations (${COLOR_YELLOW}JSON array${COLOR_RESET} of location objects)"
  echo -e "  -a ADVANCED_CONFIG                          Advanced configuration (${COLOR_YELLOW}string${COLOR_RESET})"
  echo ""
  echo -e "  --host-backup                               📦 ${COLOR_GREEN}Backup${COLOR_RESET}  All configurations to a different files in $BACKUP_DIR"
  echo -e "  --host-backup-id id                         📦 ${COLOR_GREEN}Backup${COLOR_RESET}  Single host configuration and its certificate (if exists)"
  echo -e "  --host-restore                              📦 ${COLOR_GREEN}Restore${COLOR_RESET} All configurations from a backup file"
  echo -e "  --host-restore-id id                        📦 ${COLOR_GREEN}Restore${COLOR_RESET} Single host configuration and its certificate (if exists)"
  echo -e "  --host-check-token                          🔧 ${COLOR_YELLOW}Check${COLOR_RESET}   If the current token is valid"
  echo -e "  --host-create-user user pass email          👤 ${COLOR_GREEN}Create${COLOR_RESET}  User with a ${COLOR_YELLOW}username, ${COLOR_YELLOW}password${COLOR_RESET} and ${COLOR_YELLOW}email${COLOR_RESET}"
  echo -e "  --host-delete-user username                 💣 ${COLOR_ORANGE}Delete${COLOR_RESET}  User by ${COLOR_YELLOW}username${COLOR_RESET}"
  echo -e "  --host-delete id                            💣 ${COLOR_ORANGE}Delete${COLOR_RESET}  Proxy host by ${COLOR_YELLOW}ID${COLOR_RESET}"
  echo -e "  --host-search hostname                      🔍 ${COLOR_GREEN}Search${COLOR_RESET}  Proxy host by domain name"
  echo -e "  --host-show-default                         🔍 ${COLOR_YELLOW}Show${COLOR_RESET}    Default settings for creating hosts"
  echo -e "  --host-show id                              🔍 ${COLOR_YELLOW}Show${COLOR_RESET}    Full details for a specific host by ${COLOR_YELLOW}ID${COLOR_RESET}"
  echo -e "  --host-list                                 📋 ${COLOR_YELLOW}List${COLOR_RESET}    Names of all proxy hosts"
  echo -e "  --host-list-full                            📋 ${COLOR_YELLOW}List${COLOR_RESET}    All Proxy hosts with full details"
  echo -e "  --host-list-ssl-certificates                📋 ${COLOR_YELLOW}List${COLOR_RESET}    All SSL certificates"
  echo -e "  --host-list-users                           📋 ${COLOR_YELLOW}List${COLOR_RESET}    All Users"
  echo -e "  --host-enable id                            ✅ ${COLOR_GREEN}Enable${COLOR_RESET}  Proxy host by ${COLOR_YELLOW}ID${COLOR_RESET}"
  echo -e "  --host-disable id                           ❌ ${COLOR_ORANGE}Disable${COLOR_RESET} Proxy host by ${COLOR_YELLOW}ID${COLOR_RESET}"
  echo -e "  --host-ssl-enable id                        🔒 ${COLOR_GREEN}Enable${COLOR_RESET}  SSL, HTTP/2, and HSTS for a proxy host (Will generate Certificat auto if needed)"
  echo -e "  --host-ssl-disable id                       🔓 ${COLOR_ORANGE}Disable${COLOR_RESET} SSL, HTTP/2, and HSTS for a proxy host"
  echo -e "  --host-generate-cert domain email [--custom]🛡️  ${COLOR_GREEN}Generate${COLOR_RESET} Custom certificate for the given domain and email (Only for Custom certificat)"
  echo -e "  --host-help                                 ℹ️  ${COLOR_YELLOW}Display${COLOR_RESET} This help"
  echo ""
  exit 0
}

# Colorize boolean values for display
colorize_boolean() {
  local value=$1
  if [ "$value" = true ]; then
    echo -e "${COLOR_GREEN}true${COLOR_RESET}"
  else
    echo -e "${COLOR_YELLOW}false${COLOR_RESET}"
  fi
}

colorize_booleanh() {
  local value=$1
  if [ "$value" = https ]; then
    echo -e "${COLOR_GREEN}https${COLOR_RESET}"
  else
    echo -e "${COLOR_YELLOW}http${COLOR_RESET}"
  fi
}

# Parse options
while getopts "d:i:p:f:c:b:w:a:l:-:" opt; do
  case $opt in
    d) DOMAIN_NAMES="$OPTARG" ;;
    i) FORWARD_HOST="$OPTARG" ;;
    p) FORWARD_PORT="$OPTARG" ;;
    f) FORWARD_SCHEME="$OPTARG" ;;
    c) CACHING_ENABLED="$OPTARG" ;;
    b) BLOCK_EXPLOITS="$OPTARG" ;;
    w) ALLOW_WEBSOCKET_UPGRADE="$OPTARG" ;;
    a) ADVANCED_CONFIG="$OPTARG" ;;
    l) CUSTOM_LOCATIONS="$OPTARG" ;;
    -)
      case "${OPTARG}" in
        host-help) usage ;;
        host-backup-id)
          BACKUP_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        host-backup) BACKUP=true ;;
        host-restore)
          RESTORE=true
          ;;
        host-restore-id)
          RESTORE_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        host-create-user)
          CREATE_USER=true
          USERNAME="${!OPTIND}"; shift
          PASSWORD="${!OPTIND}"; shift
          EMAIL="${!OPTIND}"; shift
          ;;
        host-delete-user)
          DELETE_USER=true
          USERNAME="${!OPTIND}"; shift
          ;;
        host-delete)
          DELETE_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        host-list) LIST_HOSTS=true ;;
        host-list-full) LIST_HOSTS_FULL=true ;;
        host-list-ssl-certificates) LIST_SSL_CERTIFICATES=true ;;
        host-list-users) LIST_USERS=true ;;
        host-search)
          SEARCH_HOST=true
          SEARCH_HOSTNAME="${!OPTIND}"; shift
          ;;
        host-enable)
          ENABLE_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        host-disable)
          DISABLE_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        host-check-token) CHECK_TOKEN=true ;;
        host-generate-cert)
          GENERATE_CERT=true
          DOMAIN="${!OPTIND}"; shift
          EMAIL="${!OPTIND}"; shift
          ;;
        custom) CUSTOM_CERT=true ;;
        host-ssl-enable)
          ENABLE_SSL=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        host-ssl-disable)
          DISABLE_SSL=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        host-show-default)
          SHOW_DEFAULT=true
          ;;
        host-show)
          SHOW_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        force-cert-creation)
          FORCE_CERT_CREATION=true
          ;;
        *) echo "Unknown option --${OPTARG}" ; usage ;;
      esac ;;
    *) usage ;;
  esac
done

# If no arguments are provided, display usage
if [ $# -eq 0 ]; then
  usage
fi

# Check if the Nginx Proxy Manager API is accessible
check_nginx_access() {
  if ping -c 2 -W 2 $NGINX_IP &> /dev/null; then
    if curl --output /dev/null --silent --head --fail "$BASE_URL"; then
      echo -e "\n ✅ Nginx url: $BASE_URL"
    else
      echo -e "\n ⛔ Nginx url ⛔ $BASE_URL is NOT accessible."
      exit 1
    fi
  else
    echo -e "\n ⛔ $NGINX_IP ⛔ is not responding. Houston, we have a problem."
    exit 1
  fi
}

# Generate a new API token
generate_token() {
  response=$(curl -s -X POST "$BASE_URL$API_ENDPOINT" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "{\"identity\":\"$API_USER\",\"secret\":\"$API_PASS\",\"expiry\":\"$TOKEN_EXPIRY\"}")

  token=$(echo "$response" | jq -r '.token')
  expires=$(echo "$response" | jq -r '.expires')

  if [ "$token" != "null" ]; then
    echo "$token" > $TOKEN_FILE
    echo "$expires" > $EXPIRY_FILE
    echo "Token: $token"
    echo "Expiry: $expires"
  else
    echo -e "${COLOR_RED}Error generating token.${COLOR_RESET}"
    echo -e "Check your [user] and [pass] and [IP]"
    exit 1
  fi
}

# Validate the existing token
validate_token() {
  if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ]; then
    return 1
  fi

  token=$(cat $TOKEN_FILE)
  expires=$(cat $EXPIRY_FILE)
  current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  if [[ "$current_time" < "$expires" ]]; then
    echo -e " ✅ ${COLOR_GREEN}The token is valid. Expiry: $expires${COLOR_RESET}"
    return 0
  else
    echo -e " ⛔ ${COLOR_RED}The token is invalid. Expiry: $expires${COLOR_RESET}"
    return 1
  fi
}

# Ensure Nginx access and token validity before proceeding
if [[ ! "$1" =~ --host-help ]]; then
  check_nginx_access

  if ! validate_token; then
    echo "No valid token found. Generating a new token..."
    generate_token
  fi
fi

# Function to list backup versions for a given host ID
list_backup_versions() {
  echo -e "\n 🔍 Listing available backup versions for host ID $HOST_ID..."
  ls -t "$BACKUP_DIR"/proxy_host_ID_+"${HOST_ID}"_IP_"${NGINX_IP//./_}"_*.json | while read -r file; do
    timestamp=$(echo "$file" | grep -oE '[0-9]{14}')
    echo " - $timestamp"
  done
}

# Function to show differences between current and backup versions
show_backup_differences() {
  CURRENT_HOST=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  BACKUP_FILE=$(ls -t "$BACKUP_DIR"/proxy_host_ID_+"${HOST_ID}"_IP_"${NGINX_IP//./_}"_*.json | head -n 1)
  BACKUP_HOST=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$BACKUP_FILE")

  echo -e "\n 🔄 Differences between current and backup versions for host ID $HOST_ID:"
  diff <(echo "$CURRENT_HOST" | jq .) <(echo "$BACKUP_HOST" | jq .) | less
}

# Function to restore a single host configuration and its certificate (if exists)
restore_single_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 🩹 The --host-restore-id option requires a host ID."
    usage
  fi

  echo -e "\n 🩹 Restoring backup for host ID $HOST_ID from '$BACKUP_DIR'..."

  RESTORE_SUCCESS=true

  # Check if the proxy host already exists
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  if [ -n "$RESPONSE" ]; then
    echo -e "\n 🔔 Proxy host for ID $HOST_ID already exists."
    read -p " 👉 Do you want to (1) delete and restore, (2) choose which backup to restore, (3) show differences, or (4) abandon? (1/2/3/4): " -r choice
    case $choice in
      1)
        delete_proxy_host
        ;;
      2)
        list_backup_versions
        read -p " 👉 Enter the timestamp of the backup you want to restore: " -r timestamp
        PROXY_HOST_FILE="$BACKUP_DIR/proxy_host_ID_+${HOST_ID}_IP_${NGINX_IP//./_}_$timestamp.json"
        ;;
      3)
        show_backup_differences
        exit 0
        ;;
      4)
        echo "Abandoned."
        exit 0
        ;;
      *)
        echo "Invalid choice."
        exit 1
        ;;
    esac
  fi

  # Use the latest available backup file for the proxy host
  PROXY_HOST_FILE=$(ls -t "$BACKUP_DIR"/proxy_host_ID_+"${HOST_ID}"_IP_"${NGINX_IP//./_}"_*.json | head -n 1)
  if [ -f "$PROXY_HOST_FILE" ]; then
    RESPONSE=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$PROXY_HOST_FILE")
    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/proxy-hosts" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
      -H "Content-Type: application/json; charset=UTF-8" \
      --data-raw "$RESPONSE")

    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 201 ]; then
      echo -e "\n ✅ ${COLOR_GREEN}Proxy host restored from file: $PROXY_HOST_FILE${COLOR_RESET}"
    else
      echo -e "\n ⛔ ${COLOR_RED}Failed to restore proxy host. Error: $HTTP_BODY${COLOR_RESET}"
      RESTORE_SUCCESS=false
    fi
  else
    echo -e "\n ⛔ ${COLOR_RED}Proxy host backup file not found: $PROXY_HOST_FILE${COLOR_RESET}"
    RESTORE_SUCCESS=false
  fi

  # Use the latest available backup file for the SSL certificate
  CERTIFICATE_FILE=$(ls -t "$BACKUP_DIR"/ssl_certificate_ID_+"${HOST_ID}"_IP_"${NGINX_IP//./_}"_*.json | head -n 1)
  if [ -f "$CERTIFICATE_FILE" ]; then
    RESPONSE=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$CERTIFICATE_FILE")
    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/certificates" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
      -H "Content-Type: application/json; charset=UTF-8" \
      --data-raw "$RESPONSE")

    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 201 ]; then
      echo -e "\n ✅ ${COLOR_GREEN}SSL certificate restored from file: $CERTIFICATE_FILE${COLOR_RESET}"
    else
      echo -e "\n ⛔ ${COLOR_RED}Failed to restore SSL certificate. Error: $HTTP_BODY${COLOR_RESET}"
      RESTORE_SUCCESS=false
    fi
  else
    echo -e "\n ⛔ ${COLOR_RED}SSL certificate backup file not found: $CERTIFICATE_FILE${COLOR_RESET}"
    RESTORE_SUCCESS=false
  fi

  if [ "$RESTORE_SUCCESS" = true ]; then
    echo -e " ✅ ${COLOR_GREEN}Restore for host ID $HOST_ID completed successfully from 📂 '$BACKUP_DIR' ${COLOR_RESET}\n"
  else
    echo -e " ⛔ ${COLOR_RED}Restore for host ID $HOST_ID failed.${COLOR_RESET}\n"
  fi
}

# Function to backup a single host configuration and its certificate (if exists)
backup_single_host() {
  if [ -z "$HOST_ID" ]; then
    echo " 📦 The --host-backup-id option requires a host ID."
    usage
  fi

  mkdir -p "$BACKUP_DIR"

  # Backup proxy host
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo ""

  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$BACKUP_DIR/proxy_host_ID_+${HOST_ID}_IP_${NGINX_IP//./_}_$DATE.json"
    echo -e " ✅ ${COLOR_GREEN}Proxy host backup host ID $HOST_ID completed 🆗: ${BACKUP_DIR}/proxy_host_ID_+${HOST_ID}_IP_${NGINX_IP//./_}_$DATE.json${COLOR_RESET}"

    # Backup SSL certificate if it exists
    CERTIFICATE_ID=$(echo "$RESPONSE" | jq -r '.certificate_id')
    if [ "$CERTIFICATE_ID" != "null" ]; then
      CERT_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates/$CERTIFICATE_ID" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)")
      if [ -n "$CERT_RESPONSE" ]; then
        echo "$CERT_RESPONSE" | jq '.' > "$BACKUP_DIR/ssl_certificate_ID_+${CERTIFICATE_ID}_IP_${NGINX_IP//./_}_$DATE.json"
        echo -e " ✅ ${COLOR_GREEN}SSL certificate backup ID $CERTIFICATE_ID completed 🆗: ${BACKUP_DIR}/ssl_certificate_ID_+${CERTIFICATE_ID}_IP_${NGINX_IP//./_}_$DATE.json${COLOR_RESET}"
      else
        echo -e " ⛔ ${COLOR_RED}Failed to backup SSL certificate for certificate ID $CERTIFICATE_ID.${COLOR_RESET}"
      fi
    else
      echo -e " ⚠️ ${COLOR_YELLOW}No SSL certificate associated with host ID $HOST_ID.${COLOR_RESET}"
    fi
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup proxy host for host ID $HOST_ID.${COLOR_RESET}"
  fi
  echo ""
}

# Check if a proxy host with the given domain names already exists
check_existing_proxy_host() {
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  EXISTING_HOST=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN_NAMES" '.[] | select(.domain_names[] == $DOMAIN)')

  if [ -n "$EXISTING_HOST" ]; then
    echo -e "\n 🔔 Proxy host for $DOMAIN_NAMES already exists.${COLOR_GREEN}"
    read -p " 👉 Do you want to update it with the new configuration? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      HOST_ID=$(echo "$EXISTING_HOST" | jq -r '.id')
      update_proxy_host "$HOST_ID"
    else
      echo -e "${COLOR_RESET} No changes made.\n"
      exit 0
    fi
  else
    create_new_proxy_host
  fi
}

# Update an existing proxy host
update_proxy_host() {
  HOST_ID=$1
  echo -e "\n 🌀 Updating proxy host for $DOMAIN_NAMES..."

  if [ -n "$CUSTOM_LOCATIONS" ]; then
    CUSTOM_LOCATIONS_ESCAPED=$(printf '%s' "$CUSTOM_LOCATIONS" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
  else
    CUSTOM_LOCATIONS_ESCAPED="[]"
  fi

  ADVANCED_CONFIG_ESCAPED=$(printf '%s' "$ADVANCED_CONFIG" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')

  DATA=$(printf '{
    "domain_names": ["%s"],
    "forward_host": "%s",
    "forward_port": %s,
    "access_list_id": null,
    "certificate_id": null,
    "ssl_forced": %s,
    "caching_enabled": %s,
    "block_exploits": %s,
    "advanced_config": "%s",
    "meta": {
      "dns_challenge": %s
    },
    "allow_websocket_upgrade": %s,
    "http2_support": %s,
    "forward_scheme": "%s",
    "enabled": true,
    "locations": %s
  }' "$DOMAIN_NAMES" "$FORWARD_HOST" "$FORWARD_PORT" "$SSL_FORCED" "$CACHING_ENABLED" "$BLOCK_EXPLOITS" "$ADVANCED_CONFIG_ESCAPED" "$DNS_CHALLENGE" "$ALLOW_WEBSOCKET_UPGRADE" "$HTTP2_SUPPORT" "$FORWARD_SCHEME" "$CUSTOM_LOCATIONS_ESCAPED")

  echo -e "\n Request Data: $DATA"

  echo "$DATA" | jq . > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo -e "\n ${COLOR_RED}Invalid JSON format${COLOR_RESET}"
    exit 1
  fi

  RESPONSE=$(curl -v -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  echo -e "Response: $RESPONSE"

  if [ "$(echo "$RESPONSE" | jq -r '.error | length')" -eq 0 ]; then
    echo -e " ✅ ${COLOR_GREEN}Proxy host updated successfully!${COLOR_RESET} "
  else
    echo -e " ⛔ ${COLOR_RED}Failed to update proxy host. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
  fi
}

# Create a new proxy host
create_new_proxy_host() {
  echo -e "\n 🌍 Creating proxy host for $DOMAIN_NAMES..."

  if [ -n "$CUSTOM_LOCATIONS" ]; then
    CUSTOM_LOCATIONS_ESCAPED=$(printf '%s' "$CUSTOM_LOCATIONS" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
  else
    CUSTOM_LOCATIONS_ESCAPED="[]"
  fi

  DATA=$(printf '{
    "domain_names": ["%s"],
    "forward_host": "%s",
    "forward_port": %s,
    "access_list_id": null,
    "certificate_id": null,
    "ssl_forced": false,
    "caching_enabled": %s,
    "block_exploits": %s,
    "advanced_config": "%s",
    "meta": {
      "dns_challenge": %s
    },
    "allow_websocket_upgrade": %s,
    "http2_support": %s,
    "forward_scheme": "%s",
    "enabled": true,
    "locations": %s
  }' "$DOMAIN_NAMES" "$FORWARD_HOST" "$FORWARD_PORT" "$CACHING_ENABLED" "$BLOCK_EXPLOITS" "$ADVANCED_CONFIG" "$DNS_CHALLENGE" "$ALLOW_WEBSOCKET_UPGRADE" "$HTTP2_SUPPORT" "$FORWARD_SCHEME" "$CUSTOM_LOCATIONS_ESCAPED")

  echo -e "\n Request Data: $DATA"

  echo "$DATA" | jq . > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo -e "\n ${COLOR_RED}Invalid JSON format${COLOR_RESET}"
    exit 1
  fi

  RESPONSE=$(curl -s -X POST "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  if [ "$(echo "$RESPONSE" | jq -r '.error | length')" -eq 0 ]; then
    echo -e " ✅ ${COLOR_GREEN}Proxy host created successfully!${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to create proxy host. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}\n"
  fi
}

# Create or update a proxy host based on the existence of the domain
create_or_update_proxy_host() {
  if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ]; then
    echo -e "\n 🌍 The -d, -i, and -p options are required to create or update a proxy host.\n"
    usage
  fi

  check_existing_proxy_host
}

# Delete a proxy host by ID
delete_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 💣  The --host-delete option requires a host ID."
    usage
  fi
  echo -e " \n 💣 Deleting proxy host ID: $HOST_ID..."

  RESPONSE=$(curl -s -X DELETE "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  if echo "$RESPONSE" | jq -e .error > /dev/null 2>&1; then
    echo -e " ⛔ ${COLOR_RED}Failed to delete proxy host. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
  else
    echo -e " ✅ ${COLOR_GREEN}Proxy host 💣 deleted successfully!${COLOR_RESET}\n"
  fi
}

# Function to pad strings to a certain length
pad() {
  local str="$1"
  local len="$2"
  local str_len=${#str}
  local pad_len=$((len - str_len))
  local padding=$(printf '%*s' "$pad_len" "")
  echo "$str$padding"
}

# List all proxy hosts with basic details
list_proxy_hosts() {
  echo -e "\n${COLOR_ORANGE} 👉 List of proxy hosts (simple)${COLOR_RESET}"
  printf "  %-6s %-36s %-9s %-4s\n" "ID" "Domain" "Status" "SSL"

  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  # Clean the response to remove control characters
  CLEANED_RESPONSE=$(echo "$RESPONSE" | tr -d '\000-\031')

  echo "$CLEANED_RESPONSE" | jq -r '.[] | "\(.id) \(.domain_names | join(", ")) \(.enabled) \(.ssl_forced)"' | while read -r id domain enabled ssl_forced; do
    if [ "$enabled" -eq 1 ]; then
      status="$(echo -e "${WHITE_ON_GREEN} enabled ${COLOR_RESET}")"
    else
      status="$(echo -e "${COLOR_RED} disable ${COLOR_RESET}")"
    fi

    if [ "$ssl_forced" -eq 1 ]; then
      ssl_status="✅"
    else
      ssl_status="✘"
    fi

    # Print the row with colors
    printf "  ${COLOR_YELLOW}%6s${COLOR_RESET} ${COLOR_GREEN}%-36s${COLOR_RESET} %-8s %-4s\n" \
      "$(pad "$id" 6)" "$(pad "$domain" 36)" "$status" "$ssl_status"
  done
  echo ""
}

# List all proxy hosts with full details
list_proxy_hosts_full() {
  echo -e "\n${COLOR_ORANGE} 👉 List of proxy hosts with full details...${COLOR_RESET}\n"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -c '.[]' | while read -r proxy; do
    echo "$proxy" | jq .
  done
  echo ""
}

# Search for a proxy host by domain name
search_proxy_host() {
  if [ -z "$SEARCH_HOSTNAME" ]; then
    echo " 🔍 The --host-search option requires a domain name."
    usage
  fi
  echo -e "\n 🔍 Searching for proxy host for $SEARCH_HOSTNAME..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -c --arg search "$SEARCH_HOSTNAME" '.[] | select(.domain_names[] | contains($search))' | while IFS= read -r line; do
    id=$(echo "$line" | jq -r '.id')
    domain_names=$(echo "$line" | jq -r '.domain_names[]')

    echo -e " 🔎 id: ${COLOR_YELLOW}$id${COLOR_RESET} ${COLOR_GREEN}$domain_names${COLOR_RESET}"
  done
	echo ""
}

# List all SSL certificates
list_ssl_certificates() {
  echo " 👉 List of SSL certificates..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq
}

# List all users
list_users() {
  echo -e "\n 👉 List of users..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo -e "\n $RESPONSE" | jq
}

# Create a new user
create_user() {
  if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$EMAIL" ]; then
    echo -e "\n 👤 The username, password, and email parameters are required to create a user."
    usage
  fi
  echo -e "\n  👤 Creating user $USERNAME..."

  DATA=$(jq -n --arg username "$USERNAME" --arg password "$PASSWORD" --arg email "$EMAIL" --arg name "$USERNAME" --arg nickname "$USERNAME" --arg secret "$PASSWORD" '{
    name: $name,
    nickname: $nickname,
    email: $email,
    roles: ["admin"],
    is_disabled: false,
    auth: {
      type: "password",
      secret: $secret
    }
  }')

  echo "Data being sent: $DATA"  # Log the data being sent

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ "$HTTP_STATUS" -eq 201 ]; then
    echo -e " ✅ ${COLOR_GREEN}User created successfully!${COLOR_RESET}\n"
  else
    echo "Data sent: $DATA"  # Log the data sent
    echo -e " ⛔ ${COLOR_RED}Failed to create user. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${COLOR_RESET}\n"
  fi
}

# Delete a user by username
delete_user() {
  if [ -z "$USERNAME" ]; then
    echo " 🗑️  The --host-delete-user option requires a 👤 username."
    usage
  fi
  echo "  🗑️ Deleting user 👤 $USERNAME..."

  # Fetch the user ID based on the username
  USER_ID=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" | jq -r --arg USERNAME "$USERNAME" '.[] | select(.nickname == $USERNAME) | .id')

  if [ -n "$USER_ID" ]; then
    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/users/$USER_ID" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)")

    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
      echo -e " ✅ ${COLOR_GREEN}User deleted successfully!${COLOR_RESET}\n"
    else
      echo -e " ⛔ ${COLOR_RED}Failed to delete user. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${COLOR_RESET}\n"
    fi
  else
    echo -e " ${COLOR_RED}User not found: $USERNAME${COLOR_RESET}\n"
  fi
}

# Enable a proxy host by ID
enable_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 💣 The --host-enable option requires a host ID."
    usage
  fi
  echo -e "\n ✅ Enabling 🌐 proxy host ID: $HOST_ID..."

  # Check if the proxy host exists before enabling
  CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  if echo "$CHECK_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    # Proxy host exists, proceed to enable
    DATA=$(echo "$CHECK_RESPONSE" | jq '{enabled: 1}')

    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

    # Extract the body and the status
    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
      echo -e " ✅ ${COLOR_GREEN}Proxy host enabled successfully!${COLOR_RESET}\n"
    else
      echo -e " ⛔ ${COLOR_RED}Failed to enable proxy host. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${COLOR_RESET}\n"
    fi
  else
    echo -e " ⛔ ${COLOR_RED}Proxy host with ID $HOST_ID does not exist.${COLOR_RESET}\n"
  fi
}

# Disable a proxy host by ID
disable_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n ❌ The --host-disable option requires a host ID."
    usage
  fi
  echo -e "\n ❌ Disabling 🌐 proxy host ID: $HOST_ID..."

  # Check if the proxy host exists before disabling
  CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  if echo "$CHECK_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    # Proxy host exists, proceed to disable
    DATA=$(echo "$CHECK_RESPONSE" | jq '{enabled: 0}')

    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

    # Extract the body and the status
    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
      echo -e " ✅ ${COLOR_GREEN}Proxy host disabled successfully!${COLOR_RESET}\n"
    else
      echo -e " ⛔ ${COLOR_RED}Failed to disable proxy host. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${COLOR_RESET}\n"
    fi
  else
    echo -e " ⛔ ${COLOR_RED}Proxy host with ID $HOST_ID does not exist.${COLOR_RESET}\n"
  fi
}

# Generate Let's Encrypt certificate if not exists
generate_certificate() {
  if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
    echo -e "\n 🛡️ The --host-generate-cert option requires a domain and email."
    usage
  fi
  echo -e "\n 👀 Checking if Let's Encrypt certificate for domain: $DOMAIN exists..."

  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  EXISTING_CERT=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN" '.[] | select(.domain_names[] == $DOMAIN)')

  if [ -n "$EXISTING_CERT" ] && ! $FORCE_CERT_CREATION; then
    EXPIRES_ON=$(echo "$EXISTING_CERT" | jq -r '.expires_on')
    echo -e " 🔔 Certificate for $DOMAIN already exists and is valid until $EXPIRES_ON."
    exit 0
  fi

  echo -e " ⚙️ Generating Let's Encrypt certificate for domain: $DOMAIN..."

  DATA=$(jq -n --arg domain "$DOMAIN" --arg email "$EMAIL" --argjson agree true '{
    provider: "letsencrypt",
    domain_names: [$domain],
    meta: {
      letsencrypt_agree: $agree,
      letsencrypt_email: $email
    }
  }')

  echo -e "\n  🔔 Please WAIT until validation !!(or not)!! \n Data being sent: $DATA"  # Log the data being sent

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ "$HTTP_STATUS" -eq 201 ]; then
    echo -e " ✅ ${COLOR_GREEN}Certificate generated successfully!${COLOR_RESET}\n"
  else
    echo " Data sent: $DATA"  # Log the data sent
    echo -e " ⛔ ${COLOR_RED}Failed to generate certificate. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${COLOR_RESET}\n"
  fi
}

# enable_ssl function
enable_ssl() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 🛡️ The --host-ssl-enable option requires a host ID."
    usage
  fi
  echo -e "\n ✅ Enabling 🔒 SSL, HTTP/2, and HSTS for proxy host ID: $HOST_ID..."

  # Check host details
  CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  CERTIFICATE_ID=$(echo "$CHECK_RESPONSE" | jq -r '.certificate_id')
  DOMAIN_NAMES=$(echo "$CHECK_RESPONSE" | jq -r '.domain_names[]')

  # Check if a Let's Encrypt certificate exists
  CERT_EXISTS=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" | jq -r --arg domain "$DOMAIN_NAMES" '.[] | select(.provider == "letsencrypt" and .domain_names[] == $domain) | .id')

  if [ -z "$CERT_EXISTS" ]; then
    echo " ⛔ No Let's Encrypt certificate associated with this host. Generating a new certificate..."

    generate_certificate
    CERTIFICATE_ID=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)" | jq -r --arg domain "$DOMAIN_NAMES" '.[] | select(.provider == "letsencrypt" and .domain_names[] == $domain) | .id')
  else
    echo " ✅ Existing Let's Encrypt certificate found. Using certificate ID: $CERT_EXISTS"
    CERTIFICATE_ID="$CERT_EXISTS"
  fi

  # Update the host with SSL enabled
  DATA=$(jq -n --arg cert_id "$CERTIFICATE_ID" '{
    certificate_id: $cert_id,
    ssl_forced: true,
    http2_support: true,
    hsts_enabled: true,
    hsts_subdomains: false
  }')

  echo -e "\n Data being sent for SSL enablement: $DATA"  # Log the data being sent

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e "\n ✅ ${COLOR_GREEN}SSL, HTTP/2, and HSTS enabled successfully!${COLOR_RESET}\n"
  else
    echo -e "\n 👉Data sent: $DATA"  # Log the data sent
    echo -e "\n ⛔ ${COLOR_RED}Failed to enable SSL, HTTP/2, and HSTS. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${COLOR_RESET}\n"
  fi
}

# Function to disable SSL for a proxy host
disable_ssl() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 🛡️ The --host-ssl-disable option requires a host ID."
    usage
  fi
  echo -e "\n 🚫 Disabling 🔓 SSL for proxy host ID: $HOST_ID..."

  CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  CERTIFICATE_ID=$(echo "$CHECK_RESPONSE" | jq -r '.certificate_id')
  if [ "$CERTIFICATE_ID" != "null" ]; then
    CERTIFICATE_ID=null
  fi

  DATA=$(jq -n --argjson cert_id "$CERTIFICATE_ID" '{
    letsencrypt_agree: false,
    dns_challenge: false,
    allow_websocket_upgrade: 0,
    http2_support: 0,
    hsts_enabled: 0,
    hsts_subdomains: 0,
    ssl_forced: 0,
    certificate_id: $cert_id
  }')

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e " ✅ ${COLOR_GREEN}SSL disabled successfully!${COLOR_RESET}\n"
  else
    echo " Data sent: $DATA"  # Log the data sent
    echo -e " ⛔ ${COLOR_RED}Failed to disable SSL. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${COLOR_RESET}\n"
  fi
}

# Function to show full details for a specific host by ID
show_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n ⛔ The --host-show option requires a host ID."
    usage
  fi
  echo -e "\n${COLOR_ORANGE} 👉 Full details for proxy host ID: $HOST_ID...${COLOR_RESET}\n"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq .
  echo ""
}

# Display default settings for creating hosts
show_default() {
  echo -e "\n ⭐ ${COLOR_YELLOW}Default settings Token:${COLOR_RESET}"
  echo -e "  - TOKEN_EXPIRY: ${COLOR_ORANGE}${TOKEN_EXPIRY}${COLOR_RESET}"
  echo -e "\n ⭐ ${COLOR_YELLOW}Default settings for creating hosts (change according to your needs):${COLOR_RESET}"
  echo -e "  - FORWARD_SCHEME: ${COLOR_ORANGE}${FORWARD_SCHEME}${COLOR_RESET}"
  echo -e "  - SSL_FORCED: ${COLOR_ORANGE}${SSL_FORCED}${COLOR_RESET}"
  echo -e "  - CACHING_ENABLED: ${COLOR_ORANGE}${CACHING_ENABLED}${COLOR_RESET}"
  echo -e "  - BLOCK_EXPLOITS: ${COLOR_ORANGE}${BLOCK_EXPLOITS}${COLOR_RESET}"
  echo -e "  - ALLOW_WEBSOCKET_UPGRADE: ${COLOR_ORANGE}${ALLOW_WEBSOCKET_UPGRADE}${COLOR_RESET}"
  echo -e "  - HTTP2_SUPPORT: ${COLOR_ORANGE}${HTTP2_SUPPORT}${COLOR_RESET}"
  echo -e "  - HSTS_ENABLED: ${COLOR_ORANGE}${HSTS_ENABLED}${COLOR_RESET}"
  echo -e "  - HSTS_SUBDOMAINS: ${COLOR_ORANGE}${HSTS_SUBDOMAINS}${COLOR_RESET}"
  echo
  exit 0
}

# Perform a full backup of all configurations
full_backup() {
  mkdir -p "$BACKUP_DIR"

  # Backup proxy hosts
  PROXY_HOSTS_FILE="$BACKUP_DIR/proxy_hosts_${NGINX_IP//./_}_$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo ""
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$PROXY_HOSTS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Proxy hosts backup completed 🆗: $PROXY_HOSTS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup proxy hosts.${COLOR_RESET}"
  fi

  # Backup users
  USERS_FILE="$BACKUP_DIR/users_${NGINX_IP//./_}_$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$USERS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Users backup completed 🆗: $USERS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup users.${COLOR_RESET}"
  fi

  # Backup SSL certificates
  SSL_CERTS_FILE="$BACKUP_DIR/ssl_certificates_${NGINX_IP//./_}_$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$SSL_CERTS_FILE"
    echo -e " ✅ ${COLOR_GREEN}SSL certificates backup completed 🆗: $SSL_CERTS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup SSL certificates.${COLOR_RESET}"
  fi

  # Backup access lists
  ACCESS_LISTS_FILE="$BACKUP_DIR/access_lists_${NGINX_IP//./_}_$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$ACCESS_LISTS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Access lists backup completed 🆗: $ACCESS_LISTS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup access lists.${COLOR_RESET}"
  fi

  # Backup settings
  SETTINGS_FILE="$BACKUP_DIR/settings_${NGINX_IP//./_}_$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/settings" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$SETTINGS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Settings backup completed 🆗: $SETTINGS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup settings.${COLOR_RESET}"
  fi
  echo ""
}

# Main logic
if [ "$CREATE_USER" = true ]; then
  create_user
elif [ "$DELETE_USER" = true ]; then
  delete_user
elif [ "$DELETE_HOST" = true ]; then
  delete_proxy_host
elif [ "$LIST_HOSTS" = true ]; then
  list_proxy_hosts
elif [ "$LIST_HOSTS_FULL" = true ]; then
  list_proxy_hosts_full
elif [ "$SHOW_HOST" = true ]; then
  show_host
elif [ "$LIST_SSL_CERTIFICATES" = true ]; then
  list_ssl_certificates
elif [ "$LIST_USERS" = true ]; then
  list_users
elif [ "$SEARCH_HOST" = true ]; then
  search_proxy_host
elif [ "$ENABLE_HOST" = true ]; then
  enable_proxy_host
elif [ "$DISABLE_HOST" = true ]; then
  disable_proxy_host
elif [ "$CHECK_TOKEN" = true ]; then
  validate_token
elif [ "$BACKUP" = true ]; then
  full_backup
elif [ "$BACKUP_HOST" = true ]; then
  backup_single_host
elif [ "$RESTORE" = true ]; then
  restore_backup
elif [ "$RESTORE_HOST" = true ]; then
  restore_single_host
elif [ "$GENERATE_CERT" = true ]; then
  generate_certificate
elif [ "$ENABLE_SSL" = true ]; then
  enable_ssl
elif [ "$DISABLE_SSL" = true ]; then
  disable_ssl
elif [ "$SHOW_DEFAULT" = true ]; then
  show_default
else
  create_or_update_proxy_host
fi
