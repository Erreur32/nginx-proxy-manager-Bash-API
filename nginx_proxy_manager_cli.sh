#!/bin/bash

# Nginx Proxy Manager CLI Script v2.3.3
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
#   ./nginx_proxy_manager_cli.sh --backup
#
# 🌐 Host Creation:
#   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 (check default values below)
#   ./nginx_proxy_manager_cli.sh --show-default
#   ./nginx_proxy_manager_cli.sh --create-user newuser password123 user@example.com
#   ./nginx_proxy_manager_cli.sh --delete-user 'username'
#   ./nginx_proxy_manager_cli.sh --host-list
#   ./nginx_proxy_manager_cli.sh --host-ssl-enable 10
#
# 🔧 Advanced Example:
#   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'
#
#   Custom Certificate:
#   ./nginx_proxy_manager_cli.sh --generate-cert example.com user@example.com --custom
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
#   --backup                         Backup all configurations to a file
#   --backup-id id                   Backup a single host configuration and its certificate (if exists)
#   --restore                        Restore configurations from a backup file
#   --restore-id id                  Restore a single host configuration and its certificate (if exists)
#
# 🔧 Miscellaneous:
#   --check-token                    Check if the current token is valid
#   --create-user user pass email    Create a user with a username, password and email
#   --delete-user username           Delete a user by username
#   --host-delete id                      Delete a proxy host by ID
#   --host-show id                        Show full details for a specific host by ID
#   --show-default                   Show default settings for creating hosts
#   --host-list                           List the names of all proxy hosts
#   --host-list-full                      List all proxy hosts with full details
#   --host-list-ssl-certificates          List all SSL certificates
#   --host-list-users                     List all users
#   --host-search hostname                Search for a proxy host by domain name
#   --host-enable id                      Enable a proxy host by ID
#   --host-disable id                     Disable a proxy host by ID
#   --host-ssl-enable id                  Enable SSL, HTTP/2, and HSTS for a proxy host
#   --host-ssl-disable id                 Disable SSL, HTTP/2, and HSTS for a proxy host
#   --generate-cert domain email [--custom] Generate a Let's Encrypt or Custom certificate for the given domain and email
#   --help                           Display this help

################################
# Variables to Edit (required) #
################################

NGINX_IP="127.0.0.1"
# Existing nginx user
API_USER="user@nginx"
API_PASS="pass nginx"
# Path to store .txt files and Backups
BASE_DIR="/path/nginx_proxy_script/data"

#################################
# Variables to Edit (optional) #
#################################

# Will create backup directory automatically
BACKUP_DIR="./backups"
#DATE=$(date +"%Y%m%d%H%M%S")

# API Endpoints
BASE_URL="http://$NGINX_IP:81/api"
API_ENDPOINT="/tokens"
TOKEN_DIR="$BASE_DIR/token"
BACKUP_DIR="$BASE_DIR/backups"
EXPIRY_FILE="$TOKEN_DIR/expiry_${NGINX_IP}.txt"
TOKEN_FILE="$TOKEN_DIR/token_${NGINX_IP}.txt"

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
HOST_SHOW=false
SHOW_DEFAULT=false
CUSTOM_CERT=false

# Colors Custom
COLOR_GREEN="\033[32m"
COLOR_RED="\033[41;1m"
COLOR_ORANGE="\033[38;5;202m"
COLOR_YELLOW="\033[93m"
COLOR_RESET="\033[0m"
COLOR_GREY="\e[90m"
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


# Display help
usage() {
  echo -e "\n${COLOR_YELLOW}Usage: ./nginx_proxy_manager_cli.sh -d domain -i ip -p port [-f forward_scheme] [-c caching_enabled] [-b block_exploits] [-w allow_websocket_upgrade] [-a advanced_config] [-t token_expiry] [--create-user username password email] [--delete-user username] [--host-delete id] [--host-list] [--host-list-full] [--host-list-ssl-certificates] [--host-list-users] [--host-search hostname] [--host-enable id] [--host-disable id] [--check-token] [--backup] [--backup-id id] [--restore] [--restore-id id] [--generate-cert domain email [--custom]] [--host-ssl-enable id] [--host-ssl-disable id] [--host-show id] [--show-default] [--help]${COLOR_RESET}"
  echo -e ""
  echo -e "Examples:"
  echo -e "\n 📦 Backup First before doing anything!${COLOR_GREY}"
  echo -e "  ./nginx_proxy_manager_cli.sh --backup"
  echo -e "  ./nginx_proxy_manager_cli.sh --backup-id 10"
  echo -e "  ./nginx_proxy_manager_cli.sh --restore"
  echo -e "  ./nginx_proxy_manager_cli.sh --restore-id 10"
  echo -e "\n ${COLOR_RESET}🌐 Host Creation${COLOR_GREY}"
  echo -e "  ./nginx_proxy_manager_cli.sh --show-default"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-ssl-enable 10"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-show 10"
  echo -e "  ./nginx_proxy_manager_cli.sh --host-list"
  echo -e "\n ${COLOR_RESET}👤 User Management${COLOR_GREY}"
  echo -e "  ./nginx_proxy_manager_cli.sh --create-user newuser password123 user@example.com"
  echo -e "  ./nginx_proxy_manager_cli.sh --delete-user 'username'"
  echo -e "\n ${COLOR_RESET}🔧 Advanced Example:${COLOR_GREY}"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;'"
  echo -e "  ./nginx_proxy_manager_cli.sh --generate-cert example.com user@example.com --custom"
  echo -e "\n ${COLOR_RESET}📁 Custom locations:${COLOR_GREY}"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"
  echo -e "\n ${COLOR_RESET}🔖 Full option:${COLOR_GREY}"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -f https -c true -b true -w true -a 'proxy_set_header X-Real-IP \$remote_addr;' -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"
  echo -e "${COLOR_RESET}"
  echo -e "Options:"
  echo -e "  -d ${COLOR_ORANGE}DOMAIN_NAMES${COLOR_RESET}                       Domain name (${COLOR_RED}required${COLOR_RESET})"
  echo -e "  -i ${COLOR_ORANGE}FORWARD_HOST${COLOR_RESET}                       IP address or domain name of the target server (${COLOR_RED}required${COLOR_RESET})"
  echo -e "  -p ${COLOR_ORANGE}FORWARD_PORT${COLOR_RESET}                       Port of the target server (${COLOR_RED}required${COLOR_RESET})"
  echo -e "  -f FORWARD_SCHEME                       Scheme for forwarding (http/https, default: $(colorize_booleanh $FORWARD_SCHEME))"
  echo -e "  -c CACHING_ENABLED                      Enable caching (true/false, default: $(colorize_boolean $CACHING_ENABLED))"
  echo -e "  -b BLOCK_EXPLOITS                       Block exploits (true/false, default: $(colorize_boolean $BLOCK_EXPLOITS))"
  echo -e "  -w ALLOW_WEBSOCKET_UPGRADE              Allow WebSocket upgrade (true/false, default: $(colorize_boolean $ALLOW_WEBSOCKET_UPGRADE))"
  echo -e "  -l CUSTOM_LOCATIONS                     Custom locations (${COLOR_YELLOW}JSON array${COLOR_RESET} of location objects)"
  echo -e "  -a ADVANCED_CONFIG                      Advanced configuration (${COLOR_YELLOW}string${COLOR_RESET})"
  echo ""
  echo -e "  --info                                 ℹ️  ${COLOR_YELLOW}Display${COLOR_RESET} Script Variables Information"
  echo -e "  --show-default                         🔍 ${COLOR_YELLOW}Show${COLOR_RESET}    Default settings for creating hosts"
  echo -e "  --backup                               📦 ${COLOR_GREEN}Backup${COLOR_RESET}  All configurations to a different files in \$BACKUP_DIR"
  echo -e "  --backup-id id                         📦 ${COLOR_GREEN}Backup${COLOR_RESET}  Single host configuration and its certificate (if exists)"
  echo -e "  --restore                              📦 ${COLOR_GREEN}Restore${COLOR_RESET} All configurations from a backup file"
  echo -e "  --restore-id id                        📦 ${COLOR_GREEN}Restore${COLOR_RESET} Single host configuration and its certificate (if exists)"
  echo -e "  --check-token                          🔧 ${COLOR_YELLOW}Check${COLOR_RESET}   If the current token is valid"
  echo -e "  --create-user user pass email          👤 ${COLOR_GREEN}Create${COLOR_RESET}  User with a ${COLOR_YELLOW}username, ${COLOR_YELLOW}password${COLOR_RESET} and ${COLOR_YELLOW}email${COLOR_RESET}"
  echo -e "  --delete-user username                 💣 ${COLOR_ORANGE}Delete${COLOR_RESET}  User by ${COLOR_YELLOW}username${COLOR_RESET}"
  echo -e "  --host-delete id                       💣 ${COLOR_ORANGE}Delete${COLOR_RESET}  Proxy host by ${COLOR_YELLOW}ID${COLOR_RESET}"
  echo -e "  --host-search hostname                 🔍 ${COLOR_GREEN}Search${COLOR_RESET}  Proxy host by domain name"
  echo -e "  --host-show id                         🔍 ${COLOR_YELLOW}Show${COLOR_RESET}    Full details for a specific host by ${COLOR_YELLOW}ID${COLOR_RESET}"
  echo -e "  --host-list                            📋 ${COLOR_YELLOW}List${COLOR_RESET}    Names of all proxy hosts"
  echo -e "  --host-list-full                       📋 ${COLOR_YELLOW}List${COLOR_RESET}    All Proxy hosts with full details"
  echo -e "  --host-list-ssl-certificates           📋 ${COLOR_YELLOW}List${COLOR_RESET}    All SSL certificates"
  echo -e "  --host-list-users                      📋 ${COLOR_YELLOW}List${COLOR_RESET}    All Users"
  echo -e "  --host-enable id                       ✅ ${COLOR_GREEN}Enable${COLOR_RESET}  Proxy host by ${COLOR_YELLOW}ID${COLOR_RESET}"
  echo -e "  --host-disable id                      ❌ ${COLOR_ORANGE}Disable${COLOR_RESET} Proxy host by ${COLOR_YELLOW}ID${COLOR_RESET}"
  echo -e "  --host-ssl-enable id                   🔒 ${COLOR_GREEN}Enable${COLOR_RESET}  SSL, HTTP/2, and HSTS for a proxy host (Will generate Certificat auto if needed)"
  echo -e "  --host-ssl-disable id                  🔓 ${COLOR_ORANGE}Disable${COLOR_RESET} SSL, HTTP/2, and HSTS for a proxy host"
  echo -e "  --generate-cert domain email [--custom]🛡️  ${COLOR_GREEN}Generate${COLOR_RESET} Custom certificate for the given domain and email (Only for Custom certificat)"
  echo -e "  --help"    
  echo ""
  exit 0
}



# Display script variables info
display_info() {
  echo -e "\n${COLOR_YELLOW}Script Variables Information:${COLOR_RESET}"
  echo -e "  ${COLOR_GREEN}BASE_URL${COLOR_RESET}    ${BASE_URL}"
  echo -e "  ${COLOR_GREEN}NGINX_IP${COLOR_RESET}    ${NGINX_IP}"
  echo -e "  ${COLOR_GREEN}API_USER${COLOR_RESET}    ${API_USER}"
  echo -e "  ${COLOR_GREEN}BASE_DIR${COLOR_RESET}    ${BASE_DIR}"
  echo -e "  ${COLOR_GREEN}BACKUP_DIR${COLOR_RESET}  ${BACKUP_DIR}"

  if [ -d "$BACKUP_DIR" ]; then
    backup_count=$(ls -1 "$BACKUP_DIR" | wc -l)
    echo -e "  ${COLOR_GREEN}BACKUP HOST ${COLOR_YELLOW}$backup_count ${COLOR_RESET}"
  else
    echo -e "  ${COLOR_RED}Backup directory does not exist.${COLOR_RESET}"
  fi

  if [ -f "$TOKEN_FILE" ]; then
    echo -e "  ${COLOR_GREEN}Token NPM ${COLOR_YELLOW}  $TOKEN_FILE ${COLOR_RESET}"
  else
    echo -e "  ${COLOR_RED}Token file does not exist! ${COLOR_RESET} \n   Check ./nginx_proxy_manager_cli.sh --check-token  "
     echo -e "  Generating new token..."
     generate_token

  fi
}

# Vérification et création des dossiers si nécessaires
if [ ! -d "$BASE_DIR" ]; then
  echo -e "${COLOR_RED}Error : BASE_DIR  $BASE_DIR  Don't exist. Check config.${COLOR_RESET}"
  exit 1
fi

if [ ! -d "$TOKEN_DIR" ]; then
  #echo -e "${COLOR_YELLOW}Info : Le dossier de tokens $TOKEN_DIR n'existe pas. Création en cours...${COLOR_RESET}"
  mkdir -p "$TOKEN_DIR"
  if [ $? -ne 0 ]; then
    echo -e "${COLOR_RED}Error: Failed to create token directory $TOKEN_DIR.${COLOR_RESET}"
    exit 1
  fi
fi

if [ ! -d "$BACKUP_DIR" ]; then
  #echo -e "${COLOR_YELLOW}Info : Le dossier de backups $BACKUP_DIR n'existe pas. Création en cours...${COLOR_RESET}"
  mkdir -p "$BACKUP_DIR"
  if [ $? -ne 0 ]; then
      echo -e "${COLOR_RED}Dependency $dep is not installed. Please install it before running this script.${COLOR_RESET}"
    exit 1
  fi
fi

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
          show-default) SHOW_DEFAULT=true ;;
          backup) BACKUP=true ;;
          backup-id)
              BACKUP_HOST=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          host-restore) RESTORE=true ;;
          host-restore-id)
              RESTORE_HOST=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          ssl-restore) SSL_RESTORE=true ;;
          ssl-regenerate) SSL_REGENERATE=true ;;
          create-user)
              CREATE_USER=true
              USERNAME="${!OPTIND}"; shift
              PASSWORD="${!OPTIND}"; shift
              EMAIL="${!OPTIND}"; shift
              ;;
          delete-user)
              DELETE_USER=true
              USERNAME="${!OPTIND}"; shift
              ;;
          host-delete)
              DELETE_HOST=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          host-show)
              HOST_SHOW=true
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
          check-token) CHECK_TOKEN=true ;;
          generate-cert)
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
          force-cert-creation) FORCE_CERT_CREATION=true ;;
          info) display_info;echo; exit 0 ;;
      esac ;;
      *) display_info ;;
  esac
done

# If no arguments are provided, display usage
if [ $# -eq 0 ]; then
  #echo -e "\n  Unknown option --${OPTARG}" ; 
  display_info
  # usage
fi




######################################
# Function to validate JSON files
validate_json() {
  local file=$1
  jq empty "$file" 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "Invalid JSON: $file"
    return 1
  fi
  return 0
}


# Function to list global backup files
list_global_backup_files() {
  ls -t "$BACKUP_DIR"/*_*.json
}

# Function to list SSL backup files
list_ssl_backup_files() {
  ls -t "$BACKUP_DIR"/ssl_certif_*.json
}


# Function to regenerate SSL certificates for all hosts
regenerate_all_ssl_certificates() {
  echo -e "\n🔄 Regenerating SSL certificates for all hosts..."

  local hosts=$(curl -s -X GET -H "Authorization: Bearer $TOKEN" "$NGINX_API_URL/nginx/proxy-hosts")
  
  local host_ids=($(echo "$hosts" | jq -r '.[] | select(.ssl.enabled == true) | .id'))
  if [ ${#host_ids[@]} -eq 0 ]; then
    echo " ⛔ No hosts with SSL certificates found."
    return 1
  fi

  for host_id in "${host_ids[@]}"; do
    echo -e "\n🔄 Regenerating SSL certificate for host ID: $host_id"
    local response=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{"id":'"$host_id"',"provider":"letsencrypt"}' "$NGINX_API_URL/nginx/certificates/generate")
    if [[ $response == *"error"* ]]; then
      echo -e " ⛔ Error regenerating SSL certificate for host ID: $host_id: $response"
    else
      echo -e " ✅ SSL certificate regenerated for host ID: $host_id"
    fi
  done
}

# Function to restore SSL certificates from a backup file
restore_ssl_certificates() {
  echo -e "\n🩹 Restoring SSL certificates from backup..."

  local ssl_files=($(ls ./backups/ssl_certif_*.json 2>/dev/null))
  if [ ${#ssl_files[@]} -eq 0 ]; then
    echo " ⛔ No SSL backup files found."
    return 1
  fi

  echo -e "\n🔍 Available SSL backup files:"
  for i in "${!ssl_files[@]}"; do
    echo "$((i+1))) ${ssl_files[$i]}"
  done

  echo -n "#? "
  read -r ssl_choice

  local selected_file=${ssl_files[$((ssl_choice-1))]}
  if [ -z "$selected_file" ]; then
    echo "Invalid selection."
    return 1
  fi

  echo -e "\n🩹 Restoring SSL certificates from $selected_file..."

  validate_json "$selected_file"
  if [ $? -ne 0 ]; then
    echo " ⛔ Restoration aborted due to invalid JSON file."
    return 1
  fi

  local response=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d @"$selected_file" "$NGINX_API_URL/nginx/certificates/restore")

  if [[ $response == *"error"* ]]; then
    echo -e " ⛔ Error restoring SSL certificates: $response"
    return 1
  fi

  echo -e " ✅ SSL certificates restored successfully!"
}




# Function to delete all existing proxy hosts
delete_all_proxy_hosts() {
  echo -e "\n 🗑️ ${COLOR_ORANGE}Deleting all existing proxy hosts...${COLOR_RESET}"
  
  existing_hosts=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)" | jq -r '.[].id')

  for host_id in $existing_hosts; do
    echo -e " 💣 Deleting host ID $host_id..."
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/nginx/proxy-hosts/$host_id" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    
    http_body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
    http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$http_status" -ne 200 ]; then
      echo -e " ⛔ ${COLOR_RED}Failed to delete host ID $host_id. HTTP status: $http_status. Response: $http_body${COLOR_RESET}"
      return 1
    fi
  done

  echo -e " ✅ ${COLOR_GREEN}All existing proxy hosts deleted successfully!${COLOR_RESET}"
  return 0
}


# Function to restore from a backup file
restore_backup() {
  echo -e "\n 🩹 ${COLOR_ORANGE}Restoring all configurations from backup...${COLOR_RESET}"

  # Function to sanitize names for directory
  sanitize_name() {
    echo "$1" | sed 's/[^a-zA-Z0-9]/_/g'
  }

  GLOBAL_BACKUP_FILES=$(ls -t "$BACKUP_DIR"/*_*.json)
  if [ -z "$GLOBAL_BACKUP_FILES" ]; then
    echo -e " ⛔ ${COLOR_RED}No backup files found.${COLOR_RESET}"
    exit 1
  fi

  echo -e "\n 🔍 Available global backup files:"
  select global_file in $GLOBAL_BACKUP_FILES; do
    if [ -n "$global_file" ]; then
      case "$global_file" in
        *users_*.json)
          echo -e "\n 🩹 Restoring users from $global_file..."
          RESPONSE=$(cat "$global_file")
          curl -s -X POST "$BASE_URL/users/bulk" \
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE"
          echo -e " ✅ ${COLOR_GREEN}Users restored successfully!${COLOR_RESET}"
          ;;
        *settings_*.json)
          echo -e "\n 🩹 Restoring settings from $global_file..."
          RESPONSE=$(cat "$global_file")
          curl -s -X POST "$BASE_URL/nginx/settings/bulk" \
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE"
          echo -e " ✅ ${COLOR_GREEN}Settings restored successfully!${COLOR_RESET}"
          ;;
        *access_lists_*.json)
          echo -e "\n 🩹 Restoring access lists from $global_file..."
          RESPONSE=$(cat "$global_file")
          curl -s -X POST "$BASE_URL/nginx/access-lists/bulk" \
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE"
          echo -e " ✅ ${COLOR_GREEN}Access lists restored successfully!${COLOR_RESET}"
          ;;
      esac
    else
      echo -e " ⛔ ${COLOR_RED}Invalid selection.${COLOR_RESET}"
    fi
    break
  done

  echo -e "\n 🩹 Restoring proxy hosts and SSL certificates..."
  for host_dir in "$BACKUP_DIR"/*/; do
    if [ -d "$host_dir" ]; then
      HOST_FILES=$(ls -t "$host_dir"proxy_host_*.json 2>/dev/null)
      SSL_FILES=$(ls -t "$host_dir"ssl_certifi_*.json 2>/dev/null)
      if [ -n "$HOST_FILES" ]; then
        PROXY_HOST_FILE=$(echo "$HOST_FILES" | head -n 1)
        echo -e "\n 🩹 Restoring proxy host from $PROXY_HOST_FILE..."
        RESPONSE=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$PROXY_HOST_FILE")
        HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/proxy-hosts" \
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE")

        HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
        HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

        if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 201 ]; then
          echo -e " ✅ ${COLOR_GREEN}Proxy host restored successfully!${COLOR_RESET}"
        else
          echo -e " ⛔ ${COLOR_RED}Failed to restore proxy host. Error: $HTTP_BODY${COLOR_RESET}"
        fi
      fi

      if [ -n "$SSL_FILES" ]; then
        for SSL_FILE in $SSL_FILES; do
          echo -e "\n 🩹 Restoring SSL certificate from $SSL_FILE..."
          CERT_RESPONSE=$(cat "$SSL_FILE")
          HTTP_CERT_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/certificates" \
            -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
            -H "Content-Type: application/json; charset=UTF-8" \
            --data-raw "$CERT_RESPONSE")

          HTTP_CERT_BODY=$(echo "$HTTP_CERT_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
          HTTP_CERT_STATUS=$(echo "$HTTP_CERT_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

          if [ "$HTTP_CERT_STATUS" -eq 200 ] || [ "$HTTP_CERT_STATUS" -eq 201 ]; then
            echo -e " ✅ ${COLOR_GREEN}SSL certificate restored successfully!${COLOR_RESET}"
          else
            echo -e " ⛔ ${COLOR_RED}Failed to restore SSL certificate. Error: $HTTP_CERT_BODY${COLOR_RESET}"
          fi
        done
      fi
    fi
  done

  echo -e "\n ✅ ${COLOR_GREEN}All configurations restored successfully!${COLOR_RESET}\n"
}





# Function to list backup versions for a given host ID
list_backup_versions() {
  echo -e "\n 🔍 Listing available backup versions for host ID $HOST_ID..."
  ls -t "$BACKUP_DIR"/proxy_host_ID_+"${HOST_ID}"_IP_"${NGINX_IP//./_}"_*.json | head -n 10 | while read -r file; do
    timestamp=$(echo "$file" | grep -oE '[0-9]{14}')
    echo " - $timestamp"
  done
}

## en test
# Function to show content of the backup
show_backup_content() {
  BACKUP_FILE=$(ls -t "$BACKUP_DIR"/proxy_host_ID_+"${HOST_ID}"_IP_"${NGINX_IP//./_}"_*.json | head -n 1)
  if [ -f "$BACKUP_FILE" ]; then
    echo -e "\n 🔄 Content of the backup for host ID $HOST_ID:"
    jq . "$BACKUP_FILE" | less
  else
    echo -e "\n ⛔ ${COLOR_RED}No backup file found for host ID $HOST_ID.${COLOR_RESET}"
  fi
}

## en test
# Function to show differences between current and backup versions
show_backup_differences() {
  CURRENT_HOST=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  BACKUP_FILE=$(ls -t "$BACKUP_DIR"/proxy_host_ID_+"${HOST_ID}"_IP_"${NGINX_IP//./_}"_*.json | head -n 1)
  BACKUP_HOST=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$BACKUP_FILE")

  echo -e "\n 🔄 Differences between current and backup versions for host ID $HOST_ID:"
  diff <(echo "$CURRENT_HOST" | jq .) <(echo "$BACKUP_HOST" | jq .) | less
}


# Delete a proxy host by ID
delete_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 💣 The --host-delete option requires a host ID."
    usage
  fi
  echo -e " \n 💣 Deleting proxy host ID: $HOST_ID..."

  RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  HTTP_BODY=$(echo "$RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if ! [[ "$HTTP_STATUS" =~ ^[0-9]+$ ]] || [ "$HTTP_STATUS" -ne 200 ]; then
    echo -e " ⛔ ${COLOR_RED}Failed to delete proxy host. HTTP status: $HTTP_STATUS. Error: $HTTP_BODY${COLOR_RESET}"
    return 1
  else
    echo -e " ✅ ${COLOR_GREEN}Proxy host 💣 deleted successfully!${COLOR_RESET}\n"
    return 0
  fi
}


# Function to restore a single host configuration and its certificate (if exists)
restore_single_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 🩹 The --restore-id option requires a host ID."
    usage
  fi

  echo -e "\n 🩹 ${COLOR_ORANGE}Restoring backup for host ID $HOST_ID from '$BACKUP_DIR'...${COLOR_RESET}"

  # Get the current date in a formatted string
  DATE=$(date +"%Y_%m_%d__%H_%M_%S")

  # Fetch the host name to identify the directory
  HOST_NAME_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  HOST_NAME=$(echo "$HOST_NAME_RESPONSE" | jq -r '.domain_names[0]')
  SANITIZED_HOST_NAME=$(echo "$HOST_NAME" | sed 's/[^a-zA-Z0-9]/_/g')
  HOST_DIR="$BACKUP_DIR/$SANITIZED_HOST_NAME"

  # Vérifier l'existence des fichiers de sauvegarde
  BACKUP_FILES=$(ls "$HOST_DIR/proxy_host_${HOST_ID}_${NGINX_IP//./_}_*.json" 2>/dev/null)
  if [ -z "$BACKUP_FILES" ]; then
    echo -e "\n ⛔ ${COLOR_RED}No backup file found for host ID $HOST_ID in '$HOST_DIR'. Aborting restore.${COLOR_RESET}"
    exit 1
  fi

  # Compter le nombre de fichiers de sauvegarde
  BACKUP_COUNT=$(echo "$BACKUP_FILES" | wc -l)
  echo -e "\n 🔍 Found $BACKUP_COUNT backups for host ID $HOST_ID."

  if [ "$BACKUP_COUNT" -gt 0 ]; then
    read -p " 👉  you want to (1) restore the latest backup, (2) list backups and choose one, or (3) abandon? (1/2/3): " -r choice
    case $choice in
      1)
        PROXY_HOST_FILE=$(ls -t "$HOST_DIR/proxy_host_${HOST_ID}_${NGINX_IP//./_}_*.json" | head -n 1)
        ;;
      2)
        list_backup_versions() {
          echo -e "\n 🔍 Listing available backup versions for host ID $HOST_ID..."
          ls -t "$HOST_DIR/proxy_host_${HOST_ID}_${NGINX_IP//./_}_*.json" | while read -r file; do
            timestamp=$(echo "$file" | grep -oE '[0-9]{4}_[0-9]{2}_[0-9]{2}__[0-9]{2}_[0-9]{2}_[0-9]{2}')
            echo " - $timestamp"
          done
        }
        list_backup_versions
        read -p " 👉  Enter the timestamp of the backup you want to restore: " -r timestamp
        PROXY_HOST_FILE="$HOST_DIR/proxy_host_${HOST_ID}_${NGINX_IP//./_}_$timestamp.json"
        if [ ! -f "$PROXY_HOST_FILE" ]; then
          echo -e "\n ⛔ ${COLOR_RED}Selected backup file not found: $PROXY_HOST_FILE${COLOR_RESET}"
          exit 1
        fi
        ;;
      3)
        echo -e "\n${COLOR_RED} Abandoned.${COLOR_RESET}\n"
        exit 0
        ;;
      *)
        echo -e "\n ${COLOR_ORANGE}Invalid choice.${COLOR_RESET}\n"
        exit 1
        ;;
    esac
  fi

  echo -e "\n 🩹 Using backup file: $PROXY_HOST_FILE"

  # Vérifier si le proxy host existe
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ] && [ "$(echo "$RESPONSE" | jq -r '.id')" = "$HOST_ID" ]; then
    echo -e "\n 🔔 Proxy host for ID $HOST_ID already exists."
    read -p " 👉 Do you want to delete the existing proxy host and restore from the backup? (y/n): " -r confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
      if ! delete_proxy_host; then
        echo -e " ⛔ ${COLOR_RED}Failed to delete existing proxy host. Aborting restore.${COLOR_RESET}\n"
        exit 1
      fi
    else
      echo "Abandoned."
      exit 0
    fi
  fi

  if [ -f "$PROXY_HOST_FILE" ]; then
    RESPONSE=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$PROXY_HOST_FILE")
    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/proxy-hosts" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
      -H "Content-Type: application/json; charset=UTF-8" \
      --data-raw "$RESPONSE")

    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 201 ]; then
      echo -e "\n ✅ ${COLOR_GREEN}Proxy host restored 🆗 from file: $PROXY_HOST_FILE${COLOR_RESET}\n"

      # Restore SSL certificate if it exists
      SSL_BACKUP_FILE=$(ls "$HOST_DIR/ssl_certif_${HOST_ID}_${NGINX_IP//./_}_*.json" 2>/dev/null | head -n 1)
      if [ -f "$SSL_BACKUP_FILE" ]; then
        CERT_RESPONSE=$(cat "$SSL_BACKUP_FILE")
        HTTP_CERT_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/certificates" \
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$CERT_RESPONSE")

        HTTP_CERT_BODY=$(echo "$HTTP_CERT_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
        HTTP_CERT_STATUS=$(echo "$HTTP_CERT_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

        if [ "$HTTP_CERT_STATUS" -eq 200 ] || [ "$HTTP_CERT_STATUS" -eq 201 ]; then
          echo -e "\n ✅ ${COLOR_GREEN}SSL certificate restored 🆗 from file: $SSL_BACKUP_FILE${COLOR_RESET}\n"
        else
          echo -e "\n ⛔ ${COLOR_RED}Failed to restore SSL certificate. Error: $HTTP_CERT_BODY${COLOR_RESET}\n"
        fi
      else
        echo -e " ⚠️ ${COLOR_YELLOW}No SSL certificate backup file found.${COLOR_RESET}"
      fi

    else
      echo -e "\n ⛔ ${COLOR_RED}Failed to restore proxy host. Error: $HTTP_BODY${COLOR_RESET}\n"
      exit 1
    fi
  else
    echo -e "\n ⛔ ${COLOR_RED}Proxy host backup file not found: $PROXY_HOST_FILE${COLOR_RESET}\n"
    exit 1
  fi
}




################################






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
    echo " 🗑️  The --delete-user option requires a 👤 username."
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

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/proxy-hosts/$HOST_ID/disable" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json")

  # Extract the body and the status
  HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e " ✅ ${COLOR_GREEN}Proxy host disabled successfully!${COLOR_RESET}\n"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to disable proxy host. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${COLOR_RESET}\n"
  fi
}


# Generate Let's Encrypt certificate if not exists
generate_certificate() {
  if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
    echo -e "\n 🛡️ The --generate-cert option requires a domain and email."
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

  if echo "$CHECK_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    CERTIFICATE_ID=$(echo "$CHECK_RESPONSE" | jq -r '.certificate_id')

    DATA=$(jq -n --argjson cert_id null '{
      certificate_id: $cert_id,
      ssl_forced: false,
      http2_support: false,
      hsts_enabled: false,
      hsts_subdomains: false
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
  else
    echo -e " ⛔ ${COLOR_RED}Proxy host with ID $HOST_ID does not exist.${COLOR_RESET}\n"
  fi
}


# Function to show full details for a specific host by ID
host_show() {
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
full_backup2() {
  mkdir -p "$BACKUP_DIR"

  # Get the current date in a formatted string
  DATE=$(date +"_%Y_%m_%d__%H_%M_%S")

  echo ""

  # Function to sanitize names for directory
  sanitize_name() {
    echo "$1" | sed 's/[^a-zA-Z0-9]/_/g'
  }

  # Initialize counters
  HOST_COUNT=0
  USER_COUNT=0

  # Backup users
  USERS_FILE="$BACKUP_DIR/users_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$USERS_FILE"
    USER_COUNT=$(echo "$RESPONSE" | jq '. | length')
    echo -e " ✅ ${COLOR_GREEN}Users backup completed        🆗${COLOR_GREY}: $USERS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup users.${COLOR_RESET}"
  fi

  # Backup settings
  SETTINGS_FILE="$BACKUP_DIR/settings_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/settings" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$SETTINGS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Settings backup completed     🆗${COLOR_GREY}: $SETTINGS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup settings.${COLOR_RESET}"
  fi

  # Backup proxy hosts
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq -c '.[]' | while read -r proxy; do
      HOST_NAME=$(echo "$proxy" | jq -r '.domain_names[0]')
      SANITIZED_HOST_NAME=$(sanitize_name "$HOST_NAME")
      HOST_DIR="$BACKUP_DIR/$SANITIZED_HOST_NAME"
      mkdir -p "$HOST_DIR"
      HOST_ID=$(echo "$proxy" | jq -r '.id')
      echo "$proxy" | jq '.' > "$HOST_DIR/proxy_host_${HOST_ID}_${NGINX_IP//./_}$DATE.json"
      HOST_COUNT=$((HOST_COUNT + 1))

      # Backup SSL certificate if it exists
      CERTIFICATE_ID=$(echo "$proxy" | jq -r '.certificate_id')
      if [ "$CERTIFICATE_ID" != "null" ]; then
        CERT_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates/$CERTIFICATE_ID" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")
        if [ -n "$CERT_RESPONSE" ]; then
          echo "$CERT_RESPONSE" | jq '.' > "$HOST_DIR/ssl_certif_${CERTIFICATE_ID}_${NGINX_IP//./_}$DATE.json"
        else
          echo -e " ⛔ ${COLOR_RED}Failed to backup SSL certificate for certificate ID $CERTIFICATE_ID.${COLOR_RESET}"
        fi
      else
        echo -e " ⚠️ ${COLOR_YELLOW}No SSL certificate associated with host ID $HOST_ID.${COLOR_RESET}"
      fi
    done    
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup proxy hosts.${COLOR_RESET}"
    exit 1
  fi

  echo -e " ✅ ${COLOR_GREEN}Proxy host backup completed   🆗${COLOR_GREY}: $BACKUP_DIR ${COLOR_RESET}"
 

  # Backup access lists
  ACCESS_LISTS_FILE="$BACKUP_DIR/access_lists_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$ACCESS_LISTS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Access lists backup completed 🆗${COLOR_GREY}: $ACCESS_LISTS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup access lists.${COLOR_RESET}"
    exit 1
  fi

  # Count total number of backup files
  TOTAL_BACKUPS=$(find "$BACKUP_DIR" -type f -name "*.json" | wc -l)

  echo -e " ✅ ${COLOR_GREEN}Backup 🆗 ${COLOR_RESET}"
  echo -e " 📦 ${COLOR_YELLOW}Backup Summary:${COLOR_RESET}"
  echo -e "   - Number of users backed up: ${COLOR_CYAN}$USER_COUNT${COLOR_RESET}"
  echo -e "   - Number of proxy hosts backed up: ${COLOR_CYAN}$HOST_COUNT${COLOR_RESET}"
  echo -e "   - Total number of backup files: ${COLOR_CYAN}$TOTAL_BACKUPS${COLOR_RESET}\n"
}

full_backup() {
  mkdir -p "$BACKUP_DIR"

  # Get the current date in a formatted string
  DATE=$(date +"_%Y_%m_%d__%H_%M_%S")

  echo ""

  # Function to sanitize names for directory
  sanitize_name() {
    echo "$1" | sed 's/[^a-zA-Z0-9]/_/g'
  }

  # Initialize counters
  USER_COUNT=0

  # Backup users
  USERS_FILE="$BACKUP_DIR/users_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$USERS_FILE"
    USER_COUNT=$(echo "$RESPONSE" | jq '. | length')
    echo -e " ✅ ${COLOR_GREEN}Users backup completed        🆗${COLOR_GREY}: $USERS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup users.${COLOR_RESET}"
  fi

  # Backup settings
  SETTINGS_FILE="$BACKUP_DIR/settings_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/settings" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$SETTINGS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Settings backup completed     🆗${COLOR_GREY}: $SETTINGS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup settings.${COLOR_RESET}"
  fi

  # Backup proxy hosts
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq -c '.[]' | while read -r proxy; do
      HOST_NAME=$(echo "$proxy" | jq -r '.domain_names[0]')
      SANITIZED_HOST_NAME=$(sanitize_name "$HOST_NAME")
      HOST_DIR="$BACKUP_DIR/$SANITIZED_HOST_NAME"
      mkdir -p "$HOST_DIR"
      HOST_ID=$(echo "$proxy" | jq -r '.id')
      echo "$proxy" | jq '.' > "$HOST_DIR/proxy_host_${HOST_ID}_${NGINX_IP//./_}$DATE.json"

      # Backup SSL certificate if it exists
      CERTIFICATE_ID=$(echo "$proxy" | jq -r '.certificate_id')
      if [ "$CERTIFICATE_ID" != "null" ]; then
        CERT_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates/$CERTIFICATE_ID" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")
        if [ -n "$CERT_RESPONSE" ]; then
          echo "$CERT_RESPONSE" | jq '.' > "$HOST_DIR/ssl_certif_${CERTIFICATE_ID}_${NGINX_IP//./_}$DATE.json"
        else
          echo -e " ⛔ ${COLOR_RED}Failed to backup SSL certificate for certificate ID $CERTIFICATE_ID.${COLOR_RESET}"
        fi
      else
        echo -e " ⚠️ ${COLOR_YELLOW}No SSL certificate associated with host ID $HOST_ID.${COLOR_RESET}"
      fi
    done    
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup proxy hosts.${COLOR_RESET}"
    exit 1
  fi

  echo -e " ✅ ${COLOR_GREEN}Proxy host backup completed   🆗${COLOR_GREY}: $BACKUP_DIR ${COLOR_RESET}"

  # Backup access lists
  ACCESS_LISTS_FILE="$BACKUP_DIR/access_lists_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$ACCESS_LISTS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Access lists backup completed 🆗${COLOR_GREY}: $ACCESS_LISTS_FILE${COLOR_RESET}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup access lists.${COLOR_RESET}"
    exit 1
  fi

  # Count the number of host directories
  HOST_COUNT=$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)

  # Count total number of backup files
  TOTAL_BACKUPS=$(find "$BACKUP_DIR" -type f -name "*.json" | wc -l)

  echo -e " ✅ ${COLOR_GREEN}Backup 🆗 ${COLOR_RESET}"
  echo -e " 📦 ${COLOR_YELLOW}Backup Summary:${COLOR_RESET}"
  echo -e "   - Number of users backed up: ${COLOR_CYAN}$USER_COUNT${COLOR_RESET}"
  echo -e "   - Number of proxy hosts backed up: ${COLOR_CYAN}$HOST_COUNT${COLOR_RESET}"
  echo -e "   - Total number of backup files: ${COLOR_CYAN}$TOTAL_BACKUPS${COLOR_RESET}\n"
}


####

# Function to backup a single host configuration and its certificate (if exists)
backup_single_host() {
  if [ -z "$HOST_ID" ]; then
    echo " 📦 The --backup-id option requires a host ID."
    usage
  fi

  mkdir -p "$BACKUP_DIR"

  # Get the current date in a formatted string
  DATE=$(date +"_%Y_%m_%d__%H_%M_%S")

  # Fetch proxy host data
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  if [ -n "$RESPONSE" ]; then
    HOST_NAME=$(echo "$RESPONSE" | jq -r '.domain_names[0]')
    SANITIZED_HOST_NAME=$(echo "$HOST_NAME" | sed 's/[^a-zA-Z0-9]/_/g')
    HOST_DIR="$BACKUP_DIR/$SANITIZED_HOST_NAME"
    mkdir -p "$HOST_DIR"

    echo "$RESPONSE" | jq '.' > "$HOST_DIR/proxy_host_${HOST_ID}_${NGINX_IP//./_}_$DATE.json"
    echo -e " ✅ ${COLOR_GREEN}Proxy host backup completed      🆗${COLOR_GREY}: ${HOST_DIR}/proxy_host_${HOST_ID}_${NGINX_IP//./_}_$DATE.json${COLOR_RESET}"

    # Fetch SSL certificate if it exists
    CERTIFICATE_ID=$(echo "$RESPONSE" | jq -r '.certificate_id')
    if [ "$CERTIFICATE_ID" != "null" ]; then
      CERT_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates/$CERTIFICATE_ID" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)")
      if [ -n "$CERT_RESPONSE" ]; then
        echo "$CERT_RESPONSE" | jq '.' > "$HOST_DIR/ssl_certif_${CERTIFICATE_ID}_${NGINX_IP//./_}_$DATE.json"
        echo -e " ✅ ${COLOR_GREEN}SSL certificate backup completed 🆗${COLOR_GREY}: ${HOST_DIR}/ssl_certif_${CERTIFICATE_ID}_${NGINX_IP//./_}_$DATE.json${COLOR_RESET}"
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
elif [ "$HOST_SHOW" = true ]; then
   host_show
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
elif [ "$SSL_RESTORE" = true ]; then
  restore_ssl_certificates
elif [ "$SSL_REGENERATE" = true ]; then
  regenerate_all_ssl_certificates
elif [ "$1" = "--info" ]; then
  display_info  
else
  create_or_update_proxy_host
fi