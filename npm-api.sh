#!/bin/bash

# Nginx Proxy Manager CLI Script
#   Github [ https://github.com/Erreur32/nginx-proxy-manager-Bash-API ]
#   By Erreur32 - July 2024
#   NPM api https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema
#           https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema/components

VERSION="3.0.0"

#################################
# This script allows you to manage Nginx Proxy Manager via the API. It provides
# functionalities such as creating proxy hosts, managing users, listing hosts,
# backing up configurations, and more.
#
#################################
# PERSISTENT Config
#################################
# Create config file  $SCRIPT_DIR/npm-api.conf and Edit Variables (required)

# NGINX_IP="127.0.0.1"
# NGINX_PORT="81"
# API_USER="admin@example.com"
# API_PASS="changeme"
#
# Optional (only if you want in other placer than script directory)
# DATA_DIR="/path/nginx_backup/dir"
#
################################


#############################################
# Optional (for a future version, not use)
# NGINX_PATH_DOCKER="/home/docker/nginx_proxy/nginx"


#################################
# Common Examples
# 
# 1. Create a new proxy host:
#    ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080
#
# 2. Enable SSL for a host:
#    ./npm-api.sh --host-ssl-enable 1
#
# 3. Create a new user:
#    ./npm-api.sh --user-create admin admin@example.com password123
#
# 4. List all proxy hosts:
#    ./npm-api.sh --host-list
#
# 5. Generate SSL certificate:
#    ./npm-api.sh --cert-generate *.example.com admin@example.com
#
# 6. Show host details:
#    ./npm-api.sh --host-show 1
#

# debug version
set -eu -o pipefail
#set -x  # Active dbog
#set -eu -o pipefail

# Check if config file npm-api.conf exist
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/npm-api.conf"

################################
# Variables to Edit (required) #
#   or create a config file    #
################################

# set default variables
DEFAULT_NGINX_IP="127.0.0.1"
DEFAULT_NGINX_PORT="81"
DEFAULT_API_USER="admin@example.com"
DEFAULT_API_PASS="changeme"
DEFAULT_NGINX_PATH_DOCKER="/path/docker/npm"
# default backup directoy (You can override with your path)
DEFAULT_DATA_DIR="$SCRIPT_DIR/data"

################################
# DON'T TOUCH BELOW !!!  ;)
################################
# Colors Custom
COLOR_GREEN="\033[32m"
COLOR_GREEN_b="\e[92m"
COLOR_RED="\033[91m"
COLOR_RED_FULL="\033[41;1m"
COLOR_ORANGE="\033[38;5;202m"
COLOR_YELLOW="\033[93m"
COLOR_CYAN="\033[36m"
COLOR_GREY="\e[90m"
COLOR_GRAY=" \e[100m"
WHITE_ON_GREEN="\033[30;48;5;83m"
CoR="\033[0m"

# load config file if exists
if [ -f "$CONFIG_FILE" ]; then
  # First set default values
  NGINX_IP="$DEFAULT_NGINX_IP"
  NGINX_PORT="$DEFAULT_NGINX_PORT"
  API_USER="$DEFAULT_API_USER"
  API_PASS="$DEFAULT_API_PASS"
  DATA_DIR="$DEFAULT_DATA_DIR"
  NGINX_PATH_DOCKER="$DEFAULT_NGINX_PATH_DOCKER"
  # Then load config file which will override defaults
  source "$CONFIG_FILE"
  # Finally set variables as read only
  declare -r NGINX_IP
  declare -r NGINX_PORT
  declare -r API_USER
  declare -r API_PASS
  #declare -r DATA_DIR
  # NGINX_PATH_DOCKER is optional, only make it readonly if it was set in config
  if [ -n "${NGINX_PATH_DOCKER+x}" ]; then
    declare -r NGINX_PATH_DOCKER
  fi
else
  # Use default values
  NGINX_IP="$DEFAULT_NGINX_IP"
  NGINX_PORT="$DEFAULT_NGINX_PORT"
  API_USER="$DEFAULT_API_USER"
  API_PASS="$DEFAULT_API_PASS"
  DATA_DIR="$DEFAULT_DATA_DIR"
  NGINX_PATH_DOCKER="$DEFAULT_NGINX_PATH_DOCKER"

  # Check if using default API user
  if [ "$API_USER" = "$DEFAULT_API_USER" ]; then
    echo -e "\n⚠️ ${COLOR_RED}Using default API credentials - Please configure the script!${CoR}"
    echo -e "\n📝 Create configuration file: $CONFIG_FILE with content:"
    echo -e "${COLOR_GREY}NGINX_IP=\"$NGINX_IP\"${CoR}     ${COLOR_YELLOW}(current default)${CoR}"
    echo -e "${COLOR_GREY}NGINX_PORT=\"$NGINX_PORT\"${CoR}  ${COLOR_YELLOW}(current default)${CoR}"
    echo -e "${COLOR_RED}API_USER=\"admin@example.com\"${CoR}  ${COLOR_RED}(required)${CoR}"
    echo -e "${COLOR_RED}API_PASS=\"your_password\"${CoR}     ${COLOR_RED}(required)${CoR}"
    echo -e "${COLOR_GREY}DATA_DIR=\"$DATA_DIR\"${CoR}    ${COLOR_YELLOW}(current default)${CoR}"
    echo -e "\n❌ ${COLOR_RED}Cannot continue with default API credentials${CoR}\n"
    exit 1
  fi
fi



# API Endpoints
BASE_URL="http://$NGINX_IP:$NGINX_PORT/api"
# Set Token duration validity.
#TOKEN_EXPIRY="365d"
#TOKEN_EXPIRY="31536000s"
TOKEN_EXPIRY="1y"

# Default variables for creating a new proxy host (adapt to your needs)
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
#DNS_PROVIDER=""
#DNS_API_KEY=""
# Don't touch below that line (or you know ...)
DEFAULT_EMAIL="$API_USER"
DOMAIN=""
DOMAIN_NAMES=""
FORWARD_HOST=""
FORWARD_PORT=""
CUSTOM_LOCATIONS=""
USERNAME=""
PASSWORD=""
EMAIL=""
HOST_ID=""
FIELD=""
VALUE=""
FIELD_VALUE=""

# Control variables
AUTO_YES=false
CHECK_TOKEN=false
EXAMPLES=false
INFO=false
SHOW_HELP=false
SHOW_DEFAULT=false

USER_CREATE=false
USER_DELETE=false
USER_LIST=false

HOST_SHOW=false
HOST_LIST=false
HOST_LIST_FULL=false
HOST_SEARCH=false
HOST_UPDATE=false
HOST_ENABLE=false
HOST_SEARCHNAME=""
HOST_DISABLE=false
HOST_DELETE=false
HOST_ACL_ENABLE=false
HOST_ACL_DISABLE=false
HOST_CREATE=false

LIST_CERT_ALL=false
CERT_SHOW=false
CERT_GENERATE=false
CERT_DELETE=false
CERT_DOMAIN=""
CERT_EMAIL=""
DNS_PROVIDER=""
DNS_API_KEY=""
DOMAIN_EXISTS=""
HOST_SSL_ENABLE=false
HOST_SSL_DISABLE=false
SSL_RESTORE=false


ACCESS_LIST=false
ACCESS_LIST_CREATE=false
ACCESS_LIST_UPDATE=false
ACCESS_LIST_DELETE=false
ACCESS_LIST_SHOW=false
ACCESS_LIST_ID=""
AUTO_YES=false

BACKUP=false
BACKUP_LIST=false
### in progress
BACKUP_HOST=false
RESTORE_HOST=false
RESTORE_BACKUP=false
CLEAN_HOSTS=false



if [ $# -eq 0 ]; then
    INFO=true
    #SHOW_HELP=true
fi
###############################################
# Check if necessary dependencies are installed
################################
# Function to check and create required directories
# Usage: check_dependencies
# Returns: 0 if successful, exits with 1 if error
################################


check_dependencies() {

    #echo -e "\n  🔍 ${COLOR_CYAN}Checking system dependencies and directories...${CoR}"
    ################################
    # 1. Check System Dependencies #
    ################################
    local dependencies=("curl" "jq")
    local missing=()   
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done  
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e " ⛔ ${COLOR_RED}Missing dependencies. Please install:${CoR}"
        printf "   - %s\n" "${missing[@]}"
        exit 1
    fi
    
    #return 0
}
#check_dependencies

# Check if the Nginx Proxy Manager API is accessible
check_nginx_access() {
    local max_retries=3
    local retry_count=0
    local timeout=5
    #echo -e "\n🔍 Checking NPM availability..."
    #echo -e " • Attempting to connect to: ${COLOR_YELLOW}$BASE_URL${CoR}"
    #echo -e "\n ✅ Loading variables from file $CONFIG_FILE"
    while [ $retry_count -lt $max_retries ]; do
        # Try to connect with timeout
        if curl --output /dev/null --silent --head --fail --connect-timeout $timeout --max-redirs 0 "$BASE_URL"; then
            #echo -e " ✅ NPM is accessible at: ${COLOR_GREEN}$BASE_URL${CoR}"
            local version_info=$(curl -s --max-redirs 0 "${BASE_URL%/api}/version")
            return 0
        fi
        ((retry_count++))
        # Show retry message if not last attempt
        if [ $retry_count -lt $max_retries ]; then
            echo -e " ⏳ Attempt $retry_count/$max_retries - Retrying in ${timeout}s..."
            sleep $timeout
        fi
    done
    # If we get here, all attempts failed
    echo -e "\n❌ ${COLOR_RED}ERROR: Cannot connect to NPM${CoR}"
    echo -e "🔍 Details:"
    echo -e " • URL: ${COLOR_YELLOW}$BASE_URL${CoR}"
    echo -e " • Host: ${COLOR_YELLOW}$NGINX_IP${CoR}"
    echo -e " • Port: ${COLOR_YELLOW}${API_PORT}${CoR}"
    echo -e "\n📋 Troubleshooting:"
    echo -e " 1. Check if NPM is running"
    echo -e " 2. Verify network connectivity"
    echo -e " 3. Confirm NPM IP and port settings"
    echo -e " 4. Check NPM logs for errors"
    echo -e "\n💡 Command to check NPM status:"
    echo -e " $ docker ps | grep nginx-proxy-manager"
    echo -e " $ docker logs nginx-proxy-manager\n"
    exit 1
}

################################
# Generate and/or validate token
# $1: boolean - true pour afficher les messages, false pour mode silencieux
check_token() {
    local verbose=${1:-false}
    # PATH 
    ###############################
    [ "$verbose" = true ] && echo -e "\n 🔍 ${COLOR_CYAN}Checking system dependencies and directories...${CoR}"
    check_dependencies

    local ip_port_dir="${NGINX_IP//[.:]/_}_${NGINX_PORT}"
    DATA_DIR_ID="$DATA_DIR/$ip_port_dir"
    BACKUP_DIR="$DATA_DIR_ID/backups"
    TOKEN_DIR="$DATA_DIR_ID/token"
    TOKEN_FILE="$TOKEN_DIR/token.txt"
    EXPIRY_FILE="$TOKEN_DIR/expiry.txt"
 
    ################################
    # Create directories if they don't exist
    ################################
    for dir in "$DATA_DIR_ID" "$TOKEN_DIR" "$BACKUP_DIR"; do
        if [ ! -d "$dir" ]; then
            [ "$verbose" = true ] && echo -e "  📢 ${COLOR_YELLOW}Creating directory: $dir${CoR}"
            if ! mkdir -p "$dir" 2>/dev/null; then
                echo -e "\n  ${COLOR_RED}Error: Failed to create directory $dir${CoR}"
                exit 1
            fi
            # Set proper permissions
            chmod 755 "$dir" 2>/dev/null
        fi
    done

    [ "$verbose" = true ] && echo -e " ✅ ${COLOR_GREEN}All dependencies and directories are properly set up${CoR}"
    [ "$verbose" = true ] && echo -e "    ${COLOR_GREY}├── System tools: OK${CoR}"
    [ "$verbose" = true ] && echo -e "    ${COLOR_GREY}├── Directories : OK${CoR}"
    [ "$verbose" = true ] && echo -e "    ${COLOR_GREY}└── Permissions : OK${CoR}"

    [ "$verbose" = true ] && echo -e "\n 🔑 Checking token validity..."

    # Check if token files exist and are readable
    if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ] || \
       [ ! -r "$TOKEN_FILE" ] || [ ! -r "$EXPIRY_FILE" ] || \
       [ ! -s "$TOKEN_FILE" ] || [ ! -s "$EXPIRY_FILE" ]; then
        [ "$verbose" = true ] && echo -e " ⛔ ${COLOR_RED}Token files missing or unreadable. Generating new token...${CoR}"
        generate_new_token
        # Ensure files were created and are readable
        if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ] || \
           [ ! -r "$TOKEN_FILE" ] || [ ! -r "$EXPIRY_FILE" ]; then
            echo -e "\n  ${COLOR_RED}Error: Failed to create or read token files${CoR}"
            exit 1
        fi
        return
    fi

    # Read token and expiry
    token=$(cat "$TOKEN_FILE" 2>/dev/null)
    expires=$(cat "$EXPIRY_FILE" 2>/dev/null)
    current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Validate expiry date format
    if ! date -d "$expires" >/dev/null 2>&1; then
        [ "$verbose" = true ] && echo -e " ⛔ ${COLOR_RED}Invalid expiry date. Generating new token...${CoR}"
        generate_new_token
        return
    fi    

    # Check if token is expired or will expire soon (1 hour)
    local expiry_timestamp=$(date -d "$expires" +%s)
    local current_timestamp=$(date -d "$current_time" +%s)
    local time_diff=$((expiry_timestamp - current_timestamp))
    if [ $time_diff -lt 3600 ]; then
        [ "$verbose" = true ] && echo -e " ⚠️ ${COLOR_YELLOW}Token expires soon. Generating new token...${CoR}"
        generate_new_token
        return
    fi

    # Test token with API call
    local test_response
    test_response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -H "Authorization: Bearer $token" \
        --connect-timeout 5 \
        "$BASE_URL/tokens")

    local http_status=$(echo "$test_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$http_status" -eq 200 ]; then
        [ "$verbose" = true ] && echo -e " ✅ ${COLOR_GREEN}Token is valid${CoR}"
        [ "$verbose" = true ] && echo -e " 📅 Expires: ${COLOR_YELLOW}$expires${CoR}\n"
    else
        [ "$verbose" = true ] && echo -e " ⛔ ${COLOR_RED}Token is invalid. Generating new token...${CoR}\n"
        generate_new_token
    fi
    return 0
}

# validate_token not verbose
check_token_notverbose() {   
    check_token false
}

################################
# Generate a new API token
generate_new_token() {
    echo -e "\n 🔄 ${COLOR_YELLOW}Generating a new API token...${CoR}"

    # check if API credentials are missing
    if [ -z "$API_USER" ] || [ -z "$API_PASS" ]; then
        echo -e " ❌ ${COLOR_RED}Error: API credentials are missing.${CoR}"
        exit 1
    fi

    # check if NPM is accessible
    if ! curl --output /dev/null --silent --head --fail --connect-timeout 5 "$BASE_URL"; then
        echo -e "\n❌ ${COLOR_RED}ERROR: Cannot connect to NPM to generate token${CoR}"
        echo -e "🔍 Please check if NPM is running and accessible at ${COLOR_YELLOW}$BASE_URL${CoR}\n"
        exit 1
    fi

    # First get a temporary token
    local temp_response=$(curl -s -w "\nHTTPSTATUS:%{http_code}" -X POST "$BASE_URL/tokens" \
        -H "Content-Type: application/json" \
        --data-raw "{\"identity\":\"$API_USER\",\"secret\":\"$API_PASS\"}")

    local temp_body=$(echo "$temp_response" | sed -e 's/HTTPSTATUS\:.*//g')
    local temp_status=$(echo "$temp_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$temp_status" -ne 200 ]; then
        echo -e " ❌ ${COLOR_RED}Failed to generate temporary token. Status: $temp_status${CoR}"
        echo -e " 📝 Response: $temp_body"
        exit 1
    fi

    # Extract the temporary token
    local temp_token=$(echo "$temp_body" | jq -r '.token')

    # Now get a long-term token using the temporary one
    local response=$(curl -s -w "\nHTTPSTATUS:%{http_code}" -X GET "$BASE_URL/tokens?expiry=$TOKEN_EXPIRY" \
        -H "Authorization: Bearer $temp_token" \
        -H "Accept: application/json")

    local body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
    local status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$status" -ne 200 ]; then
        echo -e " ❌ ${COLOR_RED}Failed to generate long-term token. Status: $status${CoR}"
        echo -e " 📝 Response: $body"
        exit 1
    fi

    # Extract token and expiry
    local token=$(echo "$body" | jq -r '.token')
    local expiry=$(echo "$body" | jq -r '.expires')

    # Ensure token directory exists with proper permissions
    if [ ! -d "$TOKEN_DIR" ]; then
        mkdir -p "$TOKEN_DIR" 2>/dev/null
        chmod 755 "$TOKEN_DIR" 2>/dev/null
    fi

    # Save token and expiry with proper permissions
    echo "$token" > "$TOKEN_FILE"
    echo "$expiry" > "$EXPIRY_FILE"
    chmod 644 "$TOKEN_FILE" "$EXPIRY_FILE" 2>/dev/null

    # Verify files were created successfully
    if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ] || \
       [ ! -r "$TOKEN_FILE" ] || [ ! -r "$EXPIRY_FILE" ]; then
        echo -e " ❌ ${COLOR_RED}Failed to save token files${CoR}"
        exit 1
    fi

    echo -e " ✅ ${COLOR_GREEN}New token successfully generated and stored.${CoR}"
    echo -e " 📅 Token expiry date: ${COLOR_YELLOW}$expiry${CoR}"
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

################################
# Colorize boolean values for display
colorize_boolean() {
    local value="$1"
    if [ "$value" = "true" ]; then
        echo "${COLOR_GREEN}true${CoR}"
    elif [ "$value" = "false" ]; then
        echo "${COLOR_RED}false${CoR}"
    else
        # If value is neither true nor false, convert to boolean
        if [ "$value" = "1" ] || [ "$value" = "yes" ] || [ "$value" = "on" ]; then
            echo "${COLOR_GREEN}true${CoR}"
        else
            echo "${COLOR_RED}false${CoR}"
        fi
    fi
}

################################
# Colorize other boolean values for display 
colorize_booleanh() {
  local value=$1
  if [ "$value" = https ]; then
    echo -e "${COLOR_GREEN}https${CoR}"
  else
    echo -e "${COLOR_YELLOW}http${CoR}"
  fi
}

# Function to sanitize names for directory
sanitize_name() {
  local name=$1
  echo "${name//[^a-zA-Z0-9]/_}"
}

################################
# Function to validate JSON files
validate_json() {
  local file=$1
  if ! jq empty "$file" 2>/dev/null; then
    echo -e "\n ⛔ Invalid JSON detected in file: $file"
    cat "$file"  # Afficher le contenu du fichier pour debug
    return 1
  fi
  return 0
}

################################
# Display help
show_help() {
  echo -e "\n Options available:\n ${COLOR_GREY}(see --examples for more details)${CoR}" 
  echo -e "   -y                                     Automatic ${COLOR_YELLOW}yes${CoR} prompts!"
  echo -e "  --info                                  Display ${COLOR_GREY}Script Variables Information${CoR}"
  echo -e "  --show-default                          Show  ${COLOR_GREY}Default settings for host creation${CoR}"
  echo -e "  --check-token                           Check ${COLOR_GREY}Check current token info${CoR}"
  echo -e "  --backup                                ${COLOR_GREEN}💾 ${CoR}Backup ${COLOR_GREY}All configurations to a different files in \$DATA_DIR${CoR}"
  #echo -e "  --clean-hosts                          ${COLOR_GREEN}📥 ${CoR}Reimport${CoR} ${COLOR_GREY}Clean Proxy ID and SSL ID in sqlite database ;)${CoR}"
  #echo -e "  --backup-host                          📦 ${COLOR_GREEN}Backup${CoR}   All proxy hosts and SSL certificates in Single file"
  #echo -e "  --backup-host 5                        📦 ${COLOR_GREEN}Backup${CoR}   Proxy host ID 5 and its SSL certificate"
  #echo -e "  --host-list-full > backup.txt          💾 ${COLOR_YELLOW}Export${CoR}   Full host configuration to file"
  #echo -e "  --restore                              📦 ${COLOR_GREEN}Restore${CoR} All configurations from a backup file"
  #echo -e "  --restore-host id                      📦 ${COLOR_GREEN}Restore${CoR} Restore single host with list with empty arguments or a Domain name"
  echo ""
  echo -e " Proxy Host Management:" 
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"   
  echo -e "  --host-search ${COLOR_CYAN}domain${CoR}                    Search ${COLOR_GREY}Proxy host by ${COLOR_YELLOW}domain name${CoR}"
  echo -e "  --host-list                             List ${COLOR_GREY}All Proxy hosts (to find ID)${CoR}"
  #echo -e "  --host-list-full                       📜 List ${COLOR_GREY}All Proxy hosts full details (JSON)${CoR}"
  echo -e "  --host-show ${COLOR_CYAN}🆔${CoR}                          Show ${COLOR_GREY}Full details for a specific host by ${COLOR_YELLOW}ID${CoR}"
  echo ""  

  echo -e "  --host-create ${COLOR_ORANGE}domain${CoR} ${COLOR_CYAN}-i ${COLOR_ORANGE}forward_host${CoR} ${COLOR_CYAN}-p ${COLOR_ORANGE}forward_port${CoR} [options]\n" 
  echo -e "     ${COLOR_RED}Required:${CoR}"
  echo -e "            domain                        Domain name (${COLOR_RED}required${CoR})"
  echo -e "       ${COLOR_CYAN}-i${CoR}   forward-host                  IP address or domain name of the target server (${COLOR_RED}required${CoR})"
  echo -e "       ${COLOR_CYAN}-p${CoR}   forward-port                  Port of the target server (${COLOR_RED}required${CoR})\n"

  echo -e "     optional: ${COLOR_GREY}(Check default settings,no argument needed if already set!)${CoR}"  
  echo -e "       ${COLOR_CYAN}-f ${COLOR_GREY}FORWARD_SCHEME${CoR}                  Scheme for forwarding (http/https, default: $(colorize_booleanh "$FORWARD_SCHEME"))"
  echo -e "       ${COLOR_CYAN}-c ${COLOR_GREY}CACHING_ENABLED${CoR}                 Enable caching (true/false, default: $(colorize_boolean "$CACHING_ENABLED"))"
  echo -e "       ${COLOR_CYAN}-b ${COLOR_GREY}BLOCK_EXPLOITS${CoR}                  Block exploits (true/false, default: $(colorize_boolean "$BLOCK_EXPLOITS"))"
  echo -e "       ${COLOR_CYAN}-w ${COLOR_GREY}ALLOW_WEBSOCKET_UPGRADE${CoR}         Allow WebSocket upgrade (true/false, default: $(colorize_boolean "$ALLOW_WEBSOCKET_UPGRADE"))"
  echo -e "       ${COLOR_CYAN}-l ${COLOR_GREY}CUSTOM_LOCATIONS${CoR}                Custom locations (${COLOR_YELLOW}JSON array${CoR} of location objects)"
  echo -e "       ${COLOR_CYAN}-a ${COLOR_GREY}ADVANCED_CONFIG${CoR}                 Advanced configuration (${COLOR_YELLOW}string${CoR})"
  #echo -e "       ${COLOR_CYAN}-h ${COLOR_GREY}HTTP2_SUPPORT${CoR}                   HTTP2 (true/false, default: $(colorize_boolean "$HTTP2_SUPPORT"))"

  echo ""
  echo -e "  --host-enable  ${COLOR_CYAN}🆔${CoR}                       Enable Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-disable ${COLOR_CYAN}🆔${CoR}                       Disable Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-delete  ${COLOR_CYAN}🆔${CoR}                       Delete Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-update  ${COLOR_CYAN}🆔${CoR} ${COLOR_CYAN}[field]=value${CoR}         Update One specific field of an existing proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "                                          (eg., --host-update 42 forward_host=foobar.local)${CoR}"
  echo ""
  echo -e "  --host-acl-enable  ${COLOR_CYAN}🆔${CoR} ${COLOR_CYAN}access_list_id${CoR}    Enable ACL for Proxy host by ${COLOR_YELLOW}ID${CoR} with Access List ID"
  echo -e "  --host-acl-disable ${COLOR_CYAN}🆔${CoR}                   Disable ACL for Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-ssl-enable  ${COLOR_CYAN}🆔${CoR} ${COLOR_CYAN}[cert_id]${CoR}         Enable SSL for host ID optionally using specific certificate ID"
  echo -e "  --host-ssl-disable ${COLOR_CYAN}🆔${CoR}                   Disable SSL, HTTP/2, and HSTS for a proxy host${CoR}"
  echo ""
  echo -e "  --cert-list                             List ALL SSL certificates" 
  echo -e "  --cert-show     ${COLOR_CYAN}domain${CoR} Or ${COLOR_CYAN}🆔${CoR}            List SSL certificates filtered by [domain name] (${COLOR_YELLOW}JSON${CoR})${CoR}" 
  echo -e "  --cert-delete   ${COLOR_CYAN}domain${CoR} Or ${COLOR_CYAN}🆔${CoR}            Delete Certificate for the given '${COLOR_YELLOW}domain${CoR}'"
 
  echo -e "  --cert-generate ${COLOR_CYAN}domain${CoR} ${COLOR_CYAN}[email]${CoR}          Generate Let's Encrypt Certificate or others Providers.${CoR}"
  echo -e "                                           • ${COLOR_YELLOW}Standard domains:${CoR} example.com, sub.example.com"
  echo -e "                                           • ${COLOR_YELLOW}Wildcard domains:${CoR} *.example.com (requires DNS challenge)${CoR}"
  echo -e "                                           • DNS Challenge:${CoR} Required for wildcard certificates"
  echo -e "                                             - ${COLOR_YELLOW}Format:${CoR} dns-provider PROVIDER dns-api-key KEY"
  echo -e "                                             - ${COLOR_YELLOW}Providers:${CoR} dynu, cloudflare, digitalocean, godaddy, namecheap, route53, ovh, gcloud"
  echo ""
  echo -e "  --user-list                             List All Users"
  echo -e "  --user-create ${COLOR_CYAN}username${CoR} ${COLOR_CYAN}password${CoR} ${COLOR_CYAN}email${CoR}   Create User with a ${COLOR_YELLOW}username${CoR}, ${COLOR_YELLOW}password${CoR} and ${COLOR_YELLOW}email${CoR}"
  echo -e "  --user-delete ${COLOR_CYAN}🆔${CoR}                        Delete User by ${COLOR_YELLOW}username${CoR}"
  echo "" 
  echo -e "  --access-list                           List All available Access Lists (ID and Name)"
  echo -e "  --access-list-show ${COLOR_CYAN}🆔${CoR}                   Show detailed information for specific access list"  
  echo -e "  --access-list-create                    Create Access Lists"
  echo -e "  --access-list-delete                    Delete Access Lists"
  echo -e "  --access-list-update                    Update Access Lists"  
  echo -e "\n    ${COLOR_CYAN}🆔${CoR} = ID Host Proxy"  
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "  --examples                             ${COLOR_ORANGE}🔖 ${CoR}Examples ${COLOR_GREY}commands, more explicits${CoR}"
  echo -e "  --help                                 ${COLOR_YELLOW}👉 ${COLOR_GREY}It's me${CoR}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 0
}

################################
# Examples CLI Commands
examples_cli() {
    echo -e "\n${COLOR_YELLOW}💡 Tips:${CoR}"
    echo -e "  • Use -y flag to skip confirmation prompts"
    echo -e "  • Check --help for complete command list"
    echo -e "  • Always backup before making major changes"
    echo -e "  • Use --host-list OR --host-search to find host IDs\n"

    echo -e "\n${COLOR_YELLOW}🔰 Common Usage Examples:${CoR}"
    # Basic commands
    echo -e "\n${COLOR_GREEN}📋 Basic Commands:${CoR}"
    echo -e "${COLOR_GREY}  # List all hosts in table format${CoR}"
    echo -e "  $0 --host-list"
    echo -e "${COLOR_GREY}  # Show detailed information about a specific host${CoR}"
    echo -e "  $0 --host-show 42"
    echo -e "${COLOR_GREY}  # Display default settings${CoR}"
    echo -e "  $0 --show-default"

    # Host Management
    echo -e "\n${COLOR_GREEN}🌐 Host Management:${CoR}"
    echo -e "${COLOR_GREY}  # Create new proxy host (basic)${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080"
    echo -e "${COLOR_GREY}  # Create host with SSL and advanced config${CoR}"
    echo -e "  $0 --host-create example.com -i 127.0.0.1 -p 6666 -f https -b true -c true --cert-generate example.com --host-ssl-enable -y"
    echo -e "${COLOR_GREY}  # Create host with custom locations${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080 -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"

    # SSL Management
    echo -e "\n${COLOR_GREEN}🔒 SSL Certificate Management:${CoR}"
    echo -e "${COLOR_GREY}  # Generate new SSL certificate${CoR}"
    echo -e "  $0 --cert-generate example.com admin@example.com"
    echo -e "${COLOR_GREY}  # Enable SSL for existing host${CoR}"
    echo -e "  $0 --host-ssl-enable 42"
    echo -e "${COLOR_GREY}  # List all SSL certificates${CoR}"
    echo -e "  $0 --cert-show"

    echo -e "${COLOR_GREY}  # List all certificates${CoR}"
    echo -e "  $0 --cert-list"
    echo -e "${COLOR_GREY}  # Generate SSL certificate${CoR}"
    echo -e "  $0 --cert-generate example.com --cert-email admin@example.com"
    
    # Add new section for Wildcard certificates
    echo -e "\n ${COLOR_GREEN}🌟 Wildcard SSL Certificates with DNS Providers:${CoR}"
    echo -e "${COLOR_GREY}  # Generate wildcard certificate with ${COLOR_CYAN}Cloudflare${CoR}"
    echo -e "  $0 --cert-generate \"*.example.com\" --cert-email admin@example.com \\"
    echo -e "    --dns-provider cloudflare \\"
    echo -e "    --dns-credentials '{\"dns_cloudflare_email\":\"your@email.com\",\"dns_cloudflare_api_key\":\"your_api_key\"}'${CoR}"
    
    echo -e "\n${COLOR_GREY}  # Generate wildcard certificate with ${COLOR_CYAN}DigitalOcean${CoR}"
    echo -e "  $0 --cert-generate \"*.example.com\" --cert-email admin@example.com \\"
    echo -e "    --dns-provider digitalocean \\"
    echo -e "    --dns-credentials '{\"dns_digitalocean_token\":\"your_token\"}'"
    
    echo -e "${COLOR_GREY}  # Generate wildcard certificate with ${COLOR_CYAN}GoDaddy${CoR}"
    echo -e "  $0 --cert-generate \"*.example.com\" --cert-email admin@example.com \\"
    echo -e "    --dns-provider godaddy \\"
    echo -e "    --dns-credentials '{\"dns_godaddy_key\":\"your_key\",\"dns_godaddy_secret\":\"your_secret\"}'"
    
    echo -e "${COLOR_GREY}  # Generate wildcard certificate with ${COLOR_CYAN}OVH${CoR}"
    echo -e " $0 --cert-generate \"*.example.com\" --cert-email admin@example.com \\"
    echo -e "    --dns-provider ovh \\"
    echo -e "    --dns-credentials '{\"dns_ovh_endpoint\":\"ovh-eu\",\"dns_ovh_app_key\":\"key\",\"dns_ovh_app_secret\":\"secret\",\"dns_ovh_consumer_key\":\"consumer_key\"}'${CoR}"
    
    echo -e "${COLOR_GREY} # Generate wildcard certificate with ${COLOR_CYAN}Dynu${CoR}"
    echo -e "  $0 --cert-generate \"*.example.com\" --cert-email admin@example.com \\"
    echo -e "    --dns-provider dynu \\"
    echo -e "    --dns-credentials '{\"dns_dynu_api_key\":\"your_key\"}'${CoR}"


    # User Management
    echo -e "\n${COLOR_GREEN}👤 User Management:${CoR}"
    echo -e "${COLOR_GREY}  # Create new user${CoR}"
    echo -e "  $0 --user-create john.doe secretpass john.doe@example.com"
    echo -e "${COLOR_GREY}  # List all users${CoR}"
    echo -e "  $0 --user-list"

    # Access Control
    echo -e "\n${COLOR_GREEN}🛡️ Access List Management Examples:${CoR}"
    echo -e "${COLOR_GREY}  # List all access lists${CoR}"
    echo -e "  $0 --access-list"
    echo
    echo -e "${COLOR_GREY}  # Show detailed information for specific access list${CoR}"
    echo -e "  $0 --access-list-show 123"
    echo
    echo -e "${COLOR_GREY}  # Create a basic access list${CoR}"
    echo -e "  $0 --access-list-create \"office\" --satisfy any"
    echo
    echo -e "${COLOR_GREY}  # Create access list with authentication${CoR}"
    echo -e "  $0 --access-list-create \"secure_area\" --satisfy all --pass-auth true"
    echo
    echo -e "${COLOR_GREY}  # Create access list with users${CoR}"
    echo -e "  $0 --access-list-create \"dev_team\" --users \"john,jane,bob\" --pass-auth true"
    echo
    echo -e "${COLOR_GREY}  # Create access list with IP rules${CoR}"
    echo -e "  $0 --access-list-create \"internal\" --allow \"192.168.1.0/24\" --deny \"192.168.1.100\""
    echo
    echo -e "${COLOR_GREY}  # Create comprehensive access list${CoR}"
    echo -e "  $0 --access-list-create \"full_config\" \\"
    echo -e "     --satisfy all \\"
    echo -e "     --pass-auth true \\"
    echo -e "     --users \"admin1,admin2\" \\"
    echo -e "     --allow \"10.0.0.0/8,172.16.0.0/12\" \\"
    echo -e "     --deny \"10.0.0.50,172.16.1.100\""
    echo
    echo -e "${COLOR_GREY}  # Update existing access list${CoR}"
    echo -e "  $0 --access-list-update 123 --name \"new_name\" --satisfy any"
    echo
    echo -e "${COLOR_GREY}  # Delete access list${CoR}"
    echo -e "  $0 --access-list-delete 123"

    echo -e "${COLOR_GREY}  # Enable ACL for a host${CoR}"
    echo -e "  $0 --host-acl-enable 42 2"

    # Advanced Configuration
    echo -e "${COLOR_GREY}  # Create host with custom headers${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP \$remote_addr;'"
    echo -e "${COLOR_GREY}  # Update specific field of existing host${CoR}"
    echo -e "  $0 --host-update 42 forward_host=new.example.com"

    echo -e "\n${COLOR_GREEN}⚙️ Advanced Configuration:${CoR}"
    echo -e "${COLOR_GREY}  # Create host with all options${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080 \\"
    echo -e "     -f https \\"
    echo -e "     -c true \\"
    echo -e "     -b true \\"
    echo -e "     -w true \\"
    echo -e "     -h true \\"
    echo -e "     -s true \\"
    echo -e "     -a 'proxy_set_header X-Real-IP \$remote_addr;' \\"
    echo -e "     -l '[{\"path\":\"/api\",\"forward_host\":\"api.local\",\"forward_port\":3000}]'"

    echo -e "\n${COLOR_YELLOW}📝 Command Parameters:${CoR}"
    echo -e "  domain                : Domain name for the proxy host"
    echo -e "  -i, --forward-host    : Target server (IP/hostname)"
    echo -e "  -p, --forward-port    : Target port"
    echo -e "  -f, --forward-scheme  : http/https"
    echo -e "  -c, --cache           : Enable cache"
    echo -e "  -b, --block-exploits  : Protection against exploits"
    echo -e "  -w, --websocket       : WebSocket support"
    echo -e "  -h, --http2           : HTTP/2 support"
    echo -e "  -s, --ssl-force       : Force SSL"
    echo -e "  -a, --advanced-config : Custom Nginx configuration"
    echo -e "  -l, --locations       : Custom location rules (JSON)\n"
    exit 0
}
################################
# Display script variables info
display_info() {
  check_token true
  echo -e "${COLOR_YELLOW}\n Script Info:  ${COLOR_GREEN}${VERSION}${CoR}"
  echo -e " ${COLOR_YELLOW}Script Variables Information:${CoR}"
  #echo -e "\n ${COLOR_GREEN}DATA_DIR${CoR} ${DATA_DIR}"
  echo -e " ${COLOR_GREEN}Config${CoR}      : ${SCRIPT_DIR}/npm-api.conf"
  echo -e " ${COLOR_GREEN}BASE  URL${CoR}   : ${BASE_URL}"
  echo -e " ${COLOR_GREEN}NGINX  IP${CoR}   : ${NGINX_IP}"
  echo -e " ${COLOR_GREEN}USER NPM${CoR}    : ${API_USER}"
  echo -e " ${COLOR_GREEN}BACKUP DIR ${CoR} : ${DATA_DIR_ID}"
  #echo -e " ${COLOR_GREEN}DOCKER Path${CoR} : ${NGINX_PATH_DOCKER}"

  DATE=$(date +"_%Y_%m_%d__%H_%M_%S")
  BACKUP_PATH="$BACKUP_DIR"

  # Vérifier si le répertoire existe et contient des fichiers
  if [ -d "$BACKUP_PATH" ] && [ -n "$(find "$BACKUP_PATH" -mindepth 1 -print -quit 2>/dev/null)" ]; then
      # Count backup files by type
      local total_files=$(find "$BACKUP_PATH" -type f \( \
          -name "*.json" -o \
          -name "*.conf" -o \
          -name "*.log" -o \
          -name "*.pem" -o \
          -name "*.key" \
      \) 2>/dev/null | wc -l)

      if [ "$total_files" -gt 0 ]; then
          echo -e "\n ${COLOR_YELLOW}Backup Statistics:${CoR}"
          local config_files=$(find "$BACKUP_PATH" -maxdepth 1 -type f -name "full_config*.json" 2>/dev/null | wc -l)
          local proxy_files=$(find "$BACKUP_PATH/.Proxy_Hosts" -type f -name "proxy_config.json" 2>/dev/null | wc -l)
          local ssl_files=$(find "$BACKUP_PATH" -type f \( \
              -name "certificate*.json" -o \
              -name "*.pem" -o \
              -name "*.key" \
          \) 2>/dev/null | wc -l)
          local access_files=$(find "$BACKUP_PATH/.access_lists" -type f -name "*.json" 2>/dev/null | wc -l)
          local settings_files=$(find "$BACKUP_PATH/.settings" -type f -name "*.json" 2>/dev/null | wc -l)
          local user_files=$(find "$BACKUP_PATH/.user" -type f -name "*.json" 2>/dev/null | wc -l)

          # Afficher les statistiques seulement s'il y a des fichiers
          [ "$config_files" -gt 0 ] && echo -e " • Full Config Files : ${COLOR_CYAN}$config_files${CoR}"
          [ "$proxy_files" -gt 0 ] && echo -e " • Proxy Host Files  : ${COLOR_CYAN}$proxy_files${CoR}"
          [ "$ssl_files" -gt 0 ] && echo -e " • SSL Files         : ${COLOR_CYAN}$ssl_files${CoR}"
          [ "$access_files" -gt 0 ] && echo -e " • Access Lists      : ${COLOR_CYAN}$access_files${CoR}"
          [ "$settings_files" -gt 0 ] && echo -e " • Settings Files    : ${COLOR_CYAN}$settings_files${CoR}"
          [ "$user_files" -gt 0 ] && echo -e " • User Files        : ${COLOR_CYAN}$user_files${CoR}"
          echo -e " • Total Files       : ${COLOR_CYAN}$total_files${CoR}"
      fi
  fi

        # Display backup locations
        echo -e "\n 📂 ${COLOR_YELLOW}Backup Locations:${CoR}"
        echo -e "  • Backup: ${COLOR_GREY}$BACKUP_PATH${CoR}"
        echo -e "  • Token: ${COLOR_GREY}$BACKUP_PATH/token/${CoR}"

  display_dashboard
}

# Function to display dashboard
display_dashboard() {
   #check_token_notverbose

    echo -e "\n ${COLOR_CYAN}📊 NGINX - Proxy Manager - Dashboard 🔧 ${CoR}"
    echo -e " ${COLOR_GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CoR}"
    # Get all data first
    local proxy_hosts=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    local redirection_hosts=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/redirection-hosts" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    local stream_hosts=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/streams" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    local certificates=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    local users=$(curl -s --max-redirs 0 -X GET "$BASE_URL/users" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    local access_lists=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/access-lists" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    
    # Calculate counts with error checking
    local proxy_count=0
    local enabled_proxy_count=0
    local redirect_count=0
    local stream_count=0
    local cert_count=0
    local expired_cert_count=0
    local user_count=0
    local access_list_count=0
 

    # Check and calculate proxy hosts
    if [ "$(echo "$proxy_hosts" | jq -r 'type')" == "array" ]; then
        proxy_count=$(echo "$proxy_hosts" | jq '. | length')
        enabled_proxy_count=$(echo "$proxy_hosts" | jq '[.[] | select(.enabled == true)] | length')
    fi
    local disabled_proxy_count=$((proxy_count - enabled_proxy_count))

    # Check and calculate redirections
    if [ "$(echo "$redirection_hosts" | jq -r 'type')" == "array" ]; then
        redirect_count=$(echo "$redirection_hosts" | jq '. | length')
    fi

    # Check and calculate streams
    if [ "$(echo "$stream_hosts" | jq -r 'type')" == "array" ]; then
        stream_count=$(echo "$stream_hosts" | jq '. | length')
    fi

    # Check and calculate certificates
    if [ "$(echo "$certificates" | jq -r 'type')" == "array" ]; then
        cert_count=$(echo "$certificates" | jq '. | length')
        expired_cert_count=$(echo "$certificates" | jq '[.[] | select(.expired == true)] | length')
    fi
    local valid_cert_count=$((cert_count - expired_cert_count))

    # Check and calculate users
    if [ "$(echo "$users" | jq -r 'type')" == "array" ]; then
        user_count=$(echo "$users" | jq '. | length')
    fi

    # Check and calculate access lists
    if [ "$(echo "$access_lists" | jq -r 'type')" == "array" ]; then
        access_list_count=$(echo "$access_lists" | jq '. | length')
   fi

    # Get version and uptime
    local uptime=$(uptime | sed 's/.*up \([^,]*\),.*/\1/')
    local version_info=$(curl -s --max-redirs 0 -X GET "${BASE_URL%/api}/version")
    local npm_version="Unknown"
    if [[ "$version_info" =~ \?v=([0-9]+\.[0-9]+\.[0-9]+) ]]; then
        npm_version="${BASH_REMATCH[1]}"
    fi

    print_row() {
        local component="$1"
        local status="$2"
        local force_color="${3:-}"  # Initialisation avec une valeur vide par défaut
        local status_color=""
        # Si une couleur est forcée, l'utiliser
        if [ -n "$force_color" ]; then
            status_color="$force_color"
        # Sinon, appliquer la logique de coloration automatique
        else
            # Liste des composants qui ne doivent pas être colorés en vert
            case "$component" in
                *"Disabled"* | *"Expired"* | *"Uptime"* | *"Version"*)
                    status_color=""
                    ;;
                *)
                    # Pour les autres, colorer en vert si > 0
                    if [[ "$status" =~ ^[0-9]+$ ]] && [ "$status" -gt 0 ]; then
                        status_color="$COLOR_GREEN"
                    fi
                    ;;
            esac
        fi

        # Calculate padding needed (20 is the max width of status column)
        local status_length=${#status}
        local padding=$((8 - status_length))
        local spaces=$(printf '%*s' "$padding" '')
        echo -e " ${COLOR_GREY}│${CoR} $component ${COLOR_GREY}│${CoR} ${status_color}$status${spaces}${CoR}${COLOR_GREY}│${CoR}"
    }
    echo -e " ${COLOR_GREY}┌─────────────────┬─────────┐${CoR}"
    echo -e " ${COLOR_GREY}│${CoR}  COMPONENT      ${COLOR_GREY}│${CoR} STATUS  ${COLOR_GREY}│${CoR}"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # Proxy Hosts
    print_row "🌐 Proxy Hosts " "$proxy_count" "$COLOR_YELLOW"
    print_row "├─ Enabled     " "$enabled_proxy_count"
    print_row "└─ Disabled    " "$disabled_proxy_count" "$COLOR_RED"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # SSL Certificates
    print_row "🔒 Certificates" "$cert_count" "$COLOR_YELLOW"
    print_row "├─ Valid       " "$valid_cert_count"
    print_row "└─ Expired     " "$expired_cert_count" "$COLOR_RED"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # Redirections & Streams
    print_row "🔄 Redirections" "$redirect_count"
    print_row "🔌 Stream Hosts" "$stream_count"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # Access Lists
    print_row "🔒 Access Lists" "$access_list_count"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # Users 
    print_row "👥 Users       " "$user_count"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # System
    print_row "⏱️ Uptime       " "$uptime" "$COLOR_YELLOW"
    print_row "📦 NPM Version " "$npm_version" "$COLOR_YELLOW"
    echo -e " ${COLOR_GREY}└─────────────────┴─────────┘${CoR}"
    echo -e "\n ${COLOR_YELLOW}💡 Use --help to see available commands${CoR}"
    echo -e "   ${COLOR_GREY} Check --examples for more help examples${CoR}\n"
}

################################
# show_default
# Display default settings for creating hosts
show_default() {
  check_token_notverbose
  echo -e "\n📝 ${COLOR_YELLOW}Default Settings for Creating Hosts:${CoR}"
  echo -e "\n ${COLOR_GREEN}Basic Settings:${CoR}"
  echo -e "  Forward Scheme:           $(colorize_booleanh "$FORWARD_SCHEME")"
  echo -e "  Caching Enabled:          $(colorize_boolean "$CACHING_ENABLED")"
  echo -e "  Block Exploits:           $(colorize_boolean "$BLOCK_EXPLOITS")"
  echo -e "  Allow Websocket Upgrade:  $(colorize_boolean "$ALLOW_WEBSOCKET_UPGRADE")"
  
  echo -e "\n ${COLOR_GREEN}SSL Settings:${CoR}"
  echo -e "  HTTP/2 Support:           $(colorize_boolean "$HTTP2_SUPPORT")"
  echo -e "  SSL Forced:               $(colorize_boolean "$SSL_FORCED")"
  echo -e "  HSTS Enabled:             $(colorize_boolean "$HSTS_ENABLED")"
  echo -e "  HSTS Subdomains:          $(colorize_boolean "$HSTS_SUBDOMAINS")"
  
  echo -e "\n ${COLOR_GREEN}Advanced Settings:${CoR}"
  if [ -n "$ADVANCED_CONFIG" ]; then
    echo -e "  Advanced Config:          ${COLOR_YELLOW}$ADVANCED_CONFIG${CoR}"
  else
    echo -e "  Advanced Config:          ${COLOR_GREY}Not configured${CoR}"
  fi
  
  if [ -n "$CUSTOM_LOCATIONS" ]; then
    echo -e "  Custom Locations:         ${COLOR_YELLOW}$CUSTOM_LOCATIONS${CoR}"
  else
    echo -e "  Custom Locations:         ${COLOR_GREY}Not configured${CoR}"
  fi
  
  echo -e "\n ${COLOR_GREEN}System Settings:${CoR}"
  echo -e "  Base URL:                 $BASE_URL"
  echo -e "  Base Directory:           $DATA_DIR"
  echo -e "  Token Directory:          $TOKEN_DIR"
  echo -e "  Backup Directory:         $BACKUP_DIR"
  echo -e "  Token Expiry:             $TOKEN_EXPIRY\n"
  
  exit 0
}
#######################################################################################


################################
# List all users
user_list() {
  check_token_notverbose
  echo -e "\n 👉 List of users..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
  echo -e "\n $RESPONSE" | jq
  exit 0
}

################################
# Create a new user
user_create() {
  check_token_notverbose
  if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$EMAIL" ]; then
    echo -e "\n 👤 ${COLOR_RED}The --user-create option requires username, password, and email.${CoR}"
    echo -e " Usage: ${COLOR_ORANGE}$0 --user-create username password email${CoR}"
    echo -e " Example:"
    echo -e "   ${COLOR_GREEN}$0 --user-create john secretpass john@domain.com${CoR}\n"
    return 1
  fi
  # check if user already exists
  EXISTING_USERS=$(curl -s -X GET "$BASE_URL/users" \
      -H "Authorization: Bearer $(cat "$TOKEN_FILE")") 
  # check if email already exists
  if echo "$EXISTING_USERS" | jq -e --arg email "$EMAIL" '.[] | select(.email == $email)' > /dev/null; then
      echo -e "\n ⛔ ${COLOR_RED}Error: A user with email $EMAIL already exists.${CoR}"
      return 1
  fi
  # check if username already exists
  if echo "$EXISTING_USERS" | jq -e --arg name "$USERNAME" '.[] | select(.name == $name)' > /dev/null; then
      echo -e "\n ⛔ ${COLOR_RED}Error: A user with name $USERNAME already exists.${CoR}"
      return 1
  fi
  # create user
  echo -e "\n 👤 Creating user ${COLOR_GREEN}$USERNAME${CoR}..."
  DATA=$(jq -n \
    --arg username "$USERNAME" \
    --arg password "$PASSWORD" \
    --arg email "$EMAIL" \
    --arg name "$USERNAME" \
    --arg nickname "$USERNAME" \
    --arg secret "$PASSWORD" \
    '{
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
    # send data to API
    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/users" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
        -H "Content-Type: application/json; charset=UTF-8" \
        --data-raw "$DATA")

    HTTP_BODY=${RESPONSE//HTTPSTATUS:*/}
    HTTP_STATUS=${RESPONSE##*HTTPSTATUS:}

    if [ "$HTTP_STATUS" -eq 201 ]; then
        # debug
        echo "Debug response: $HTTP_BODY" >> /tmp/npm_debug.log

        # get user id
        USERS_RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
        
        USER_ID=$(echo "$USERS_RESPONSE" | jq -r --arg email "$EMAIL" --arg name "$USERNAME" \
            '.[] | select(.email == $email and .name == $name) | .id')

        if [ -n "$USER_ID" ]; then
            echo -e " ✅ ${COLOR_GREEN}User $USERNAME created successfully!${CoR}"
            echo -e " 📧 Email: ${COLOR_YELLOW}$EMAIL${CoR}"
            echo -e " 🆔 User ID: ${COLOR_YELLOW}$USER_ID${CoR}\n"            
        else
            echo -e " ⚠️ ${COLOR_GREEN}User created but couldn't fetch ID${CoR}"
            echo -e " 📧 Email: ${COLOR_YELLOW}$EMAIL${CoR}\n"
        fi
        return 0
    else
        echo -e " ⛔ ${COLOR_RED}Failed to create user. Status: $HTTP_STATUS${CoR}"
        echo -e " Error: ${COLOR_RED}$HTTP_BODY${CoR}\n"
        return 1
    fi
}

################################
# Delete a user
# $1: user_id - ID of the user to delete
user_delete() {
    local USER_ID="$1"

    if [ -z "$USER_ID" ]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: User ID is required${CoR}"
        echo -e " Usage  : ${COLOR_ORANGE}$0 --user-delete <user_id> [-y]${CoR}"
        echo -e " Example: ${COLOR_GREEN}$0 --user-delete 42${CoR}"
        exit 1
    fi

    # Check if USER_ID is a number
    if ! [[ "$USER_ID" =~ ^[0-9]+$ ]]; then
        echo -e " ⛔ ${COLOR_RED}ERROR: Invalid user ID '$USER_ID' - must be a number${CoR}"
        echo -e " Usage  : ${COLOR_ORANGE}$0 --user-delete <user_id> [-y]${CoR}"
        echo -e " Example: ${COLOR_GREEN}$0 --user-delete 42${CoR}"
        exit 1
    fi
  check_token_notverbose

    # Get user details first
    local RESPONSE=$(curl -s -X GET "$BASE_URL/users/$USER_ID" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    if [ "$(echo "$RESPONSE" | jq -r '.error.code // empty')" = "404" ]; then
        echo -e " ⛔ ${COLOR_RED}User ID $USER_ID not found${CoR}"
        exit 1
    fi

    local USERNAME=$(echo "$RESPONSE" | jq -r '.name')
    local EMAIL=$(echo "$RESPONSE" | jq -r '.email')

    if [ "$AUTO_YES" = true ]; then
        echo -e " 🔔 Auto-confirming deletion of user '$USERNAME' (ID: $USER_ID)..."
    else
        echo -e " ┌───────────────────────────────────────────"
        echo -e " │ ID: ${COLOR_YELLOW}$USER_ID${CoR}"
        echo -e " │ Name: ${COLOR_GREEN}$USERNAME${CoR}"
        echo -e " │ Email: ${COLOR_CYAN}$EMAIL${CoR}"
        echo -e " └───────────────────────────────────────────"
        echo -e " ⚠️  ${COLOR_RED}WARNING: This action cannot be undone!${CoR}"
        read -n 1 -r -p " 🔔 Confirm deletion? (y/n): " CONFIRM
        echo
        if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
            echo -e " ❌ ${COLOR_RED}Operation cancelled${CoR}"
            exit 1
        fi
    fi

    # Delete user
    RESPONSE=$(curl -s -X DELETE "$BASE_URL/users/$USER_ID" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    if [ "$RESPONSE" = "true" ]; then
        echo -e " ✅ ${COLOR_GREEN}User '$USERNAME' (ID: $USER_ID) deleted successfully!${CoR}"
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete user.${CoR}"
        if [ -n "$RESPONSE" ]; then
            echo -e "    Error: $RESPONSE"
        fi
        exit 1
    fi
}


################################
# Check if a certificate exists and is valid
check_certificate_exists() {
    local DOMAIN="$1"
    local RESPONSE
    local CERT_ID

    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    if [[ "$DOMAIN" == \** ]]; then
        CERT_ID=$(echo "$RESPONSE" | jq -r --arg domain "$DOMAIN" \
            '.[] | select(.domain_names[] == $domain) | .id' | sort -n | tail -n1)
    else
        local BASE_DOMAIN="${DOMAIN#\*\.}"
        CERT_ID=$(echo "$RESPONSE" | jq -r --arg domain "$BASE_DOMAIN" \
            '.[] | select(
                (.domain_names[] == $domain) or
                (.domain_names[] | startswith("*.") and ($domain | endswith(.[2:]))) or
                ($domain | startswith("*.") and (.domain_names[] | endswith(.[2:])))
            ) | .id' | sort -n | tail -n1)
    fi

    if [ -n "$CERT_ID" ]; then
        return 0
    else
        return 1
    fi
}


##############################################################
# Function to delete all existing proxy hosts  # DEBUG
##############################################################
# Delete all existing proxy hosts
delete_all_proxy_hosts() {
  check_token_notverbose
    echo -e "\n 🗑️ ${COLOR_ORANGE}Deleting all existing proxy hosts...${CoR}"

    # Get all host IDs
    local existing_hosts=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" | jq -r '.[].id')

    local count=0
    for host_id in $existing_hosts; do
        echo -e " •  Deleting host ID ${COLOR_CYAN}$host_id${CoR}...${COLOR_GREEN}✓${CoR}"
        local response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/nginx/proxy-hosts/$host_id" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

        local http_body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
        local http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

        if [ "$http_status" -ne 200 ]; then
            echo -e " ⛔ ${COLOR_RED}Failed to delete host ID $host_id. HTTP status: $http_status. Response: $http_body${CoR}"
            return 1
        fi
        ((count++))
    done

    echo -e " ✅ ${COLOR_GREEN}Successfully deleted $count proxy hosts!${CoR}"
    return 0
}

################################
# --clean_hosts from_backup_file
# Function to reimport hosts from backup file
# Create a safety backup before major operations
create_safety_backup() {
  check_token_notverbose
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    SAFETY_BACKUP="$BACKUP_DIR/pre_reimport_SAFETY_BACKUP_${TIMESTAMP}.json" 
    echo -e "📦 Creating safety backup..."   
    # Get the list of IDs
    local host_ids=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" | jq -r '.[].id')
    # Create a table to store the complete configurations
    echo "[" > "$SAFETY_BACKUP"
    local first=true
    # Get the detailed configuration of each host
    for id in $host_ids; do
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$SAFETY_BACKUP"
        fi
        
        curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$id" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")" >> "$SAFETY_BACKUP"
    done
    
    echo "]" >> "$SAFETY_BACKUP"
    # Verify that the backup is valid
    if ! jq empty "$SAFETY_BACKUP" 2>/dev/null; then
        echo -e " ❌ ${COLOR_RED}Failed to create valid safety backup${CoR}"
        exit 1
    fi
    echo -e " ✅ ${COLOR_GREEN}Safety backup created: ${COLOR_CYAN}$SAFETY_BACKUP${CoR}"
    return 0
}

################################
# Function to display import summary
display_import_summary() {
    echo -e "\n📊 ${COLOR_YELLOW}Import Summary:${CoR}"
    echo -e " • Total hosts processed: ${COLOR_CYAN}$total${CoR}"
    echo -e " • Successfully imported: ${COLOR_GREEN}$success${CoR}"
    echo -e " • Failed imports: ${COLOR_RED}$failed${CoR}"
    echo -e "\n🔒 SSL Certificates:"
    echo -e " • Successfully configured: ${COLOR_GREEN}$ssl_success${CoR}"
    echo -e " • Failed configurations: ${COLOR_RED}$ssl_failed${CoR}"

    if [ ${#failed_ssl_domains[@]} -gt 0 ]; then
        echo -e "\n⚠️ ${COLOR_YELLOW}Domains with failed SSL setup:${CoR}"
        for domain in "${failed_ssl_domains[@]}"; do
            echo -e " • $domain"
        done
    fi

    echo -e "\n✨ ${COLOR_GREEN}Import process completed${CoR}"
}

################################
# Function to list SSL certificates by ID or domain
cert_show() {
    local search_term="$1"
    check_token_notverbose

    # If no search term is provided, show usage
    if [ -z "$search_term" ]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: Missing argument${CoR}"
        echo -e "    Usage: "
        echo -e "      ${COLOR_ORANGE}$0 --cert-show <domain>${CoR}     🔍 Search by domain name"
        echo -e "      ${COLOR_ORANGE}$0 --cert-show <id>${CoR}         🔢 Search by ID"
        echo -e "      ${COLOR_ORANGE}$0 --cert-show-all${CoR}          📜 List all certificates\n"
        exit 1
    fi
    
    # Get all certificates
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
        
    if [ -z "$RESPONSE" ] || [ "$RESPONSE" == "null" ]; then
        echo -e " ⛔ ${COLOR_RED}Error: Unable to retrieve certificates${CoR}"
        exit 1
    fi

    # Search by ID if numeric
    if [[ "$search_term" =~ ^[0-9]+$ ]]; then
        echo -e "\n 🔍 Searching for certificate with ID: ${COLOR_YELLOW}$search_term${CoR}"
        
        # Get specific certificate by ID
        CERT_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates/$search_term" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
            
        if echo "$CERT_RESPONSE" | jq -e '.error' >/dev/null; then
            echo -e " ⛔ ${COLOR_RED}Certificate not found with ID: $search_term${CoR}"
        else
            echo "$CERT_RESPONSE" | jq -r '" 🔒 ID: \(.id)\n    • Domain(s): \(.domain_names | join(", "))\n    • Provider : \(.provider)\n    • Created on: \(.created_on // "N/A")\n    • Expires on: \(.expires_on // "N/A")\n    • Status: \(if .expired then "❌ EXPIRED" else if .expires_on then "✅ VALID" else "⚠️ PENDING" end end)"' | while IFS= read -r line; do if [[ $line == *"❌ EXPIRED"* ]]; then echo -e "${line/❌ EXPIRED/${COLOR_RED}❌ EXPIRED${CoR}}"; elif [[ $line == *"✅ VALID"* ]]; then echo -e "${line/✅ VALID/${COLOR_GREEN}✅ VALID${CoR}}"; elif [[ $line == *"⚠️ PENDING"* ]]; then echo -e "${line/⚠️ PENDING/${COLOR_YELLOW}⚠️ PENDING${CoR}}"; else echo -e "$line"; fi; done        fi
            echo ""
        return 0
    fi

    # Search by domain name (partial match)
    echo -e "\n 🔍 Searching certificates for domain: ${COLOR_YELLOW}$search_term${CoR}"
    DOMAIN_CERTS=$(echo "$RESPONSE" | jq -r --arg domain "$search_term" \
        '.[] | select(.domain_names[] | contains($domain))')

    if [ -z "$DOMAIN_CERTS" ]; then
        echo -e " ℹ️ ${COLOR_YELLOW}No certificates found for domain: $search_term${CoR}"
    else
        echo "$DOMAIN_CERTS" | jq -r '" 🔒 ID: \(.id)\n    • Domain(s): \(.domain_names | join(", "))\n    • Provider : \(.provider)\n    • Created on: \(.created_on // "N/A")\n    • Expires on: \(.expires_on // "N/A")\n    • Status: \(if .expired then "❌ EXPIRED" else if .expires_on then "✅ VALID" else "⚠️ PENDING" end end)"' | while IFS= read -r line; do if [[ $line == *"❌ EXPIRED"* ]]; then echo -e "${line/❌ EXPIRED/${COLOR_RED}❌ EXPIRED${CoR}}"; elif [[ $line == *"✅ VALID"* ]]; then echo -e "${line/✅ VALID/${COLOR_GREEN}✅ VALID${CoR}}"; elif [[ $line == *"⚠️ PENDING"* ]]; then echo -e "${line/⚠️ PENDING/${COLOR_YELLOW}⚠️ PENDING${CoR}}"; else echo -e "$line"; fi; done
        echo ""
    fi
}

################################
# Function to list all SSL certificates
list_cert_all() {
    check_token_notverbose
    
    # Get all certificates
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
        
    if [ -z "$RESPONSE" ] || [ "$RESPONSE" == "null" ]; then
        echo -e " ⛔ ${COLOR_RED}Error: Unable to retrieve certificates${CoR}"
        exit 1
    fi

    echo -e "\n 📜 SSL Certificates List:"
    
    # Check if there are any certificates
    if [ "$RESPONSE" = "[]" ]; then
        echo -e " ℹ️ ${COLOR_YELLOW}No certificates found${CoR}"
        return 0
    fi

    # Process and display all certificates
    echo "$RESPONSE" | jq -r '.[] | " 🔒 ID: \(.id)\n    • Domain(s): \(.domain_names | join(", "))\n    • Provider: \(.provider)\n    • Created on: \(.created_on // "N/A")\n    • Expires on: \(.expires_on // "N/A")\n    • Status: \(if .expired then "❌ EXPIRED" else if .expires_on then "✅ VALID" else "⚠️ PENDING" end end)"' | \
    while IFS= read -r line; do
        if [[ $line == *"❌ EXPIRED"* ]]; then
            echo -e "${line/❌ EXPIRED/${COLOR_RED}❌ EXPIRED${CoR}}"
        elif [[ $line == *"✅ VALID"* ]]; then
            echo -e "${line/✅ VALID/${COLOR_GREEN}✅ VALID${CoR}}"
        elif [[ $line == *"⚠️ PENDING"* ]]; then
            echo -e "${line/⚠️ PENDING/${COLOR_YELLOW}⚠️ PENDING${CoR}}"
        else
            echo -e "$line"
        fi
    done
    # Display statistics
    TOTAL_CERTS=$(echo "$RESPONSE" | jq '. | length')
    # Check if expires_on is in the future
    VALID_CERTS=$(echo "$RESPONSE" | jq '[.[] | select(.expires_on > now)] | length')
    # Check if expires_on is in the past
    EXPIRED_CERTS=$(echo "$RESPONSE" | jq '[.[] | select(.expires_on < now)] | length')
    
    echo -e "\n 📊 Statistics"
    echo -e "    Total certs: ${COLOR_YELLOW}$TOTAL_CERTS${CoR}"
    echo -e "    • ${COLOR_GREEN}Valid${CoR}    : ${COLOR_GREEN}$VALID_CERTS${CoR}"
    echo -e "    • ${COLOR_RED}Expired${CoR}  : ${COLOR_RED}$EXPIRED_CERTS${CoR}\n"
}

# Verify Cloudflare API Key validity
verify_cloudflare_api_key() {
    local api_key="$1"
    local email="$2"
    
    echo -e " 🔍 Verifying Cloudflare API Key..."
    
    # Test API call to Cloudflare
    local response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/user" \
        -H "X-Auth-Email: $email" \
        -H "X-Auth-Key: $api_key" \
        -H "Content-Type: application/json")

    # Check if the API call was successful
    if [ "$(echo "$response" | jq -r '.success')" = "true" ]; then
        local username=$(echo "$response" | jq -r '.result.username')
        echo -e " ✅ ${COLOR_GREEN}Cloudflare API Key is valid${CoR}"
        echo -e " 👤 Connected as: ${COLOR_CYAN}$username${CoR}"
        return 0
    else
        local error_msg=$(echo "$response" | jq -r '.errors[0].message')
        echo -e " ❌ ${COLOR_RED}Invalid Cloudflare API Key${CoR}"
        echo -e " ⛔ Error: $error_msg"
        return 1
    fi
}

###############################
# Create or update a proxy host based on the existence of the domain
create_or_update_proxy_host() {
    # Add static variable to track execution
    if [ "${FUNCTION_CALLED:-0}" -eq 1 ]; then
        return 0
    fi
    FUNCTION_CALLED=1

    # Check for wildcard domains in host creation
    if [[ "$DOMAIN_NAMES" == \** ]]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: Wildcard domains (*.domain.com) are not allowed for host creation${CoR}"
        echo -e " Wildcards are only supported for SSL certificates"
        exit 1
    fi

  check_token_notverbose
    # Check if the host already exists
    #echo -e "\n 🔎 Checking if the host ${COLOR_RED}$DOMAIN_NAMES${CoR} already exists..."
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    EXISTING_HOST=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN_NAMES" '.[] | select(.domain_names[] == $DOMAIN)')
    HOST_ID=$(echo "$EXISTING_HOST" | jq -r '.id // empty')

    # Prepare JSON data for API
    if [[ -z "$CUSTOM_LOCATIONS" || "$CUSTOM_LOCATIONS" == "null" ]]; then
        CUSTOM_LOCATIONS_ESCAPED="[]"
    else
        CUSTOM_LOCATIONS_ESCAPED=$(echo "$CUSTOM_LOCATIONS" | jq -c . 2>/dev/null || echo '[]')
    fi

    # Convert boolean to JSON
    CACHING_ENABLED_JSON=$( [ "$CACHING_ENABLED" == "true" ] && echo true || echo false )
    BLOCK_EXPLOITS_JSON=$( [ "$BLOCK_EXPLOITS" == "true" ] && echo true || echo false )
    ALLOW_WEBSOCKET_UPGRADE_JSON=$( [ "$ALLOW_WEBSOCKET_UPGRADE" == "true" ] && echo true || echo false )
    HTTP2_SUPPORT_JSON=$( [ "$HTTP2_SUPPORT" == "true" ] && echo true || echo false )

    # Generate JSON
    DATA=$(jq -n \
        --arg domain "$DOMAIN_NAMES" \
        --arg host "$FORWARD_HOST" \
        --arg port "$FORWARD_PORT" \
        --arg scheme "$FORWARD_SCHEME" \
        --argjson caching "$CACHING_ENABLED_JSON" \
        --argjson block_exploits "$BLOCK_EXPLOITS_JSON" \
        --arg advanced_config "$ADVANCED_CONFIG" \
        --argjson websocket_upgrade "$ALLOW_WEBSOCKET_UPGRADE_JSON" \
        --argjson http2_support "$HTTP2_SUPPORT_JSON" \
        --argjson enabled true \
        --argjson locations "$CUSTOM_LOCATIONS_ESCAPED" \
        '{
            domain_names: [$domain],
            forward_host: $host,
            forward_port: ($port | tonumber),
            access_list_id: null,
            certificate_id: null,
            ssl_forced: false,
            caching_enabled: $caching,
            block_exploits: $block_exploits,
            advanced_config: $advanced_config,
            meta: { dns_challenge: null },
            allow_websocket_upgrade: $websocket_upgrade,
            http2_support: $http2_support,
            forward_scheme: $scheme,
            enabled: $enabled,
            locations: $locations
        }')

    # Check if the JSON is valid
    if ! echo "$DATA" | jq empty > /dev/null 2>&1; then
        echo -e " ${COLOR_RED}⛔ ERROR: Invalid JSON generated:\n$DATA${CoR}"
        exit 1
    fi

    if [ -n "$HOST_ID" ]; then
        # Update existing HOST
        #echo -e "\n ${COLOR_CYAN}🔄${CoR} Updating the proxy host for ${COLOR_GREEN}$DOMAIN_NAMES${CoR}"
        if [ "$AUTO_YES" != "true" ]; then
            echo -e " ${COLOR_YELLOW}👉 Do you want to update this host ${CoR} $DOMAIN_NAMES ${COLOR_YELLOW}?${CoR}"
            read -n 1 -r -p "   (y/n):  " answer
            echo
            if [[ ! $answer =~ ^[OoYy]$ ]]; then
                echo -e " ${COLOR_YELLOW}🚫 No changes made.${CoR}\n"
                return 0 
            fi
        fi
        echo -e "${CoR}"
        METHOD="PUT"
        URL="$BASE_URL/nginx/proxy-hosts/$HOST_ID"
    else
        # Create NEW HOST
        echo -e "\n ${COLOR_CYAN}🌍${CoR} Creating a new proxy host: ${COLOR_GREEN}$DOMAIN_NAMES${CoR}"
        METHOD="POST"
        URL="$BASE_URL/nginx/proxy-hosts"
    fi

    # Send API request
    RESPONSE=$(curl -s -X "$METHOD" "$URL" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
        -H "Content-Type: application/json; charset=UTF-8" \
        --data-raw "$DATA")

     # Check API response
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // empty')
    if [ -z "$ERROR_MSG" ]; then
        PROXY_ID=$(echo "$RESPONSE" | jq -r '.id // "unknown"')
        
    # If certificate generation is requested
    if [ "$CERT_GENERATE" = true ] ; then
        #echo -e " ${COLOR_YELLOW}🔐 Generate SSL certificate CREATE_OR_${CoR}"
        
        # Check if it's a wildcard certificate
        if [[ "$DOMAIN_NAMES" == *"*."* ]]; then
            if [ -z "$DNS_PROVIDER" ] || [ -z "$DNS_API_KEY" ]; then
                echo -e " ⚠️ ${COLOR_YELLOW}Wildcard certificate requires DNS challenge${CoR}"
                echo -e " 👉 Please provide DNS provider and API key:"
                read -p "    DNS Provider (cloudflare, dynu, etc.): " DNS_PROVIDER
                read -p "    DNS API Key: " DNS_API_KEY
            fi

            # Verify Cloudflare API key if using Cloudflare
            if [[ "${DNS_PROVIDER,,}" == "cloudflare" ]]; then
                if ! verify_cloudflare_api_key "$DNS_API_KEY" "$CERT_EMAIL"; then
                    echo -e " ⛔ ${COLOR_RED}Cannot proceed with invalid Cloudflare API Key${CoR}"
                    return 1
                fi
                
                # Verify domain is managed by Cloudflare
                local domain=${DOMAIN_NAMES#\*.}
                local zone_check=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$domain" \
                    -H "X-Auth-Email: $CERT_EMAIL" \
                    -H "X-Auth-Key: $DNS_API_KEY" \
                    -H "Content-Type: application/json")
                
                if [ "$(echo "$zone_check" | jq -r '.result | length')" -eq 0 ]; then
                    echo -e " ⛔ ${COLOR_RED}Domain $domain is not managed by Cloudflare${CoR}"
                    echo -e " 👉 Please make sure your domain is added to your Cloudflare account"
                    return 1
                fi
                
                echo -e " ✅ ${COLOR_GREEN}Domain verification successful${CoR}"
            fi
        fi
        # Set default value for DNS_CREDENTIALS_JSON if not defined
        DNS_CREDENTIALS_JSON=${DNS_CREDENTIALS_JSON:-"{}"}
        
        # Generate the certificate
        cert_generate "$CERT_DOMAIN" "$CERT_EMAIL" "$DNS_PROVIDER" "$DNS_CREDENTIALS_JSON" "$HOST_SSL_ENABLE" "$DOMAIN_NAMES"

        # Check SSL creation 
            CERT_CHECK=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
                -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
            
        CERT_ID=$(echo "$CERT_CHECK" | jq -r --arg domain "$CERT_DOMAIN" \
                '.[] | select(.domain_names[] == $domain) | .id' | sort -n | tail -n1)

            if [ -n "$CERT_ID" ]; then
            #echo -e "\n ${COLOR_YELLOW}✨ Automatic SSL Activation${CoR} $CERT_DOMAIN "
                
            # update certificat with HOST ID
                UPDATE_DATA=$(jq -n \
                    --arg cert_id "$CERT_ID" \
                    '{
                        certificate_id: $cert_id,
                        ssl_forced: true,
                        http2_support: true,
                        hsts_enabled: false,
                        hsts_subdomains: false,
                        enabled: true
                    }')

                UPDATE_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT \
                    "$BASE_URL/nginx/proxy-hosts/$PROXY_ID" \
                    -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
                    -H "Content-Type: application/json" \
                    --data "$UPDATE_DATA")

                UPDATE_STATUS=${UPDATE_RESPONSE##*HTTPSTATUS:}

            # Check if successfull
                if [ "$UPDATE_STATUS" -eq 200 ]; then
                echo -e "\n ✅ ${COLOR_GREEN}SSL Configuration Complete ${CoR}🎉"
                echo -e " 📋 CHECK  SSL Status for ${COLOR_GREEN}$DOMAIN_NAMES${CoR}:"
                    echo -e "    ├─ 🔒 SSL: ${COLOR_GREEN}Enabled${CoR}"
                    echo -e "    ├─ 📜 Certificate ID: $CERT_ID"
                    echo -e "    ├─ 🚀 HTTP/2: ${COLOR_GREEN}Active${CoR}"
                    echo -e "    ├─ 🛡️ HSTS: ${COLOR_RED}Disabled${CoR}"
                echo -e "    └─ 🌐 HSTS Subdomains: ${COLOR_RED}Disabled${CoR}\n"
                exit 0 
            else
                echo -e " ⛔ ${COLOR_RED}Failed to enable SSL. Status code: $UPDATE_STATUS${CoR}\n"
                fi
        else
            echo -e " ⛔ ${COLOR_RED}Certificate not found after generation${CoR}\n"
            fi
        fi

        if [ "$METHOD" = "PUT" ]; then
            echo -e " ✅ ${COLOR_GREEN}Proxy host 🔗$DOMAIN_NAMES (ID: ${COLOR_YELLOW}$PROXY_ID${COLOR_GREEN}) OK${CoR}\n"
        else
            echo -e " ✅ ${COLOR_GREEN}Proxy host 🔗$DOMAIN_NAMES (ID: ${COLOR_YELLOW}$PROXY_ID${COLOR_GREEN}) created successfully! 🎉${CoR}\n"
        fi
    else
        echo -e " ⛔ ${COLOR_RED}Operation failed. Error: $ERROR_MSG${CoR}\n"
        exit 1
    fi
}

 

# List all proxy hosts with basic details, including SSL certificate status and associated domain
host_list() {
  check_token_notverbose
  echo -e "\n${COLOR_ORANGE} 👉 List of proxy hosts ${CoR}\n"
  printf "  %4s %-36s %-9s %-6s %-36s\n" "ID" " DOMAIN" " STATUS" " SSL" " CERT DOMAIN"

  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

  # Clean the response to remove control characters
  CLEANED_RESPONSE=$(echo "$RESPONSE" | tr -d '\000-\031')

  echo "$CLEANED_RESPONSE" | jq -r '.[] | "\(.id) \(.domain_names | join(", ")) \(.enabled) \(.certificate_id)"' | while read -r id domain enabled certificate_id; do
		if [ "$enabled" = "true" ]; then
  		status="$(echo -e "${WHITE_ON_GREEN} enabled ${CoR}")"
		else
  		status="$(echo -e "${COLOR_RED} disable ${CoR}")"
		fi
    # Default SSL status
    ssl_status="$(pad "✘" 6)"
    ssl_color="${COLOR_RED}"
    cert_domain=""
    # Check if a valid certificate ID is present and not null
    if [ "$certificate_id" != "null" ] && [ -n "$certificate_id" ]; then
      # Fetch the certificate details using the certificate_id
      CERT_DETAILS=$(curl -s -X GET "$BASE_URL/nginx/certificates/$certificate_id" \
      -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

      # Check if the certificate details are valid and domain_names is not null
      if [ "$(echo "$CERT_DETAILS" | jq -r '.domain_names')" != "null" ]; then
        cert_domain=$(echo "$CERT_DETAILS" | jq -r '.domain_names | join(", ")')
        ssl_status="$(pad "$certificate_id" 6)"
        ssl_color="${COLOR_CYAN}"
      fi
    fi

    # Print the row with colors and certificate domain (if available)
    printf "  ${COLOR_YELLOW}%4s${CoR}  ${COLOR_GREEN}%-36s${CoR} %-9s ${ssl_color}%-6s${CoR} ${COLOR_CYAN}%-36s${CoR}\n" \
      "$id" "$(pad "$domain" 36)" "$status" "$ssl_status" "$cert_domain"
  done
  echo ""
  exit 0
}

################################
# List all proxy hosts with full details
host_list_full() {
  check_token_notverbose
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

  echo "$RESPONSE" | jq -c '.[]' | while read -r proxy; do
    echo "$proxy" | jq .
  done
  echo ""
  exit 0
}



################################
# Update an existing proxy host
update_proxy_host() {
  check_token_notverbose
  HOST_ID=$1
  echo -e "\n 🔄 Updating proxy host for $DOMAIN_NAMES..."

  # 🔥 check if the required parameters are set
  if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ] || [ -z "$FORWARD_SCHEME" ]; then
    echo -e "  ⛔${COLOR_RED} ERROR: Missing required parameters (domain, forward host, forward port, forward scheme).${CoR}"
    exit 1
  fi

  # 🔥 check if the FORWARD_PORT is a number
  if ! [[ "$FORWARD_PORT" =~ ^[0-9]+$ ]]; then
    echo -e "  ⛔${COLOR_RED} ERROR: FORWARD_PORT is not a number! Value: '$FORWARD_PORT'${CoR}"
    exit 1
  fi

  # 🔥 Correct the CUSTOM_LOCATIONS
  if [[ -z "$CUSTOM_LOCATIONS" || "$CUSTOM_LOCATIONS" == "null" ]]; then
    CUSTOM_LOCATIONS_ESCAPED="[]"
  else
    CUSTOM_LOCATIONS_ESCAPED=$(echo "$CUSTOM_LOCATIONS" | jq -c . 2>/dev/null || echo '[]')
  fi

  # correct the boolean (true / false in JSON)
  CACHING_ENABLED_JSON=$( [ "$CACHING_ENABLED" == "true" ] && echo true || echo false )
  BLOCK_EXPLOITS_JSON=$( [ "$BLOCK_EXPLOITS" == "true" ] && echo true || echo false )
  ALLOW_WEBSOCKET_UPGRADE_JSON=$( [ "$ALLOW_WEBSOCKET_UPGRADE" == "true" ] && echo true || echo false )
  HTTP2_SUPPORT_JSON=$( [ "$HTTP2_SUPPORT" == "true" ] && echo true || echo false )

	# 🔍 Debugging variables before JSON update:
	debug_var

  # 🔥 generate the JSON properly
  DATA=$(jq -n \
    --arg domain "$DOMAIN_NAMES" \
    --arg host "$FORWARD_HOST" \
    --arg port "$FORWARD_PORT" \
    --arg scheme "$FORWARD_SCHEME" \
    --argjson caching "$CACHING_ENABLED_JSON" \
    --argjson block_exploits "$BLOCK_EXPLOITS_JSON" \
    --arg advanced_config "$ADVANCED_CONFIG" \
    --argjson websocket_upgrade "$ALLOW_WEBSOCKET_UPGRADE_JSON" \
    --argjson http2_support "$HTTP2_SUPPORT_JSON" \
    --argjson enabled true \
    --argjson locations "$CUSTOM_LOCATIONS_ESCAPED" \
    '{
      domain_names: [$domain],
      forward_host: $host,
      forward_port: ($port | tonumber),
      access_list_id: null,
      certificate_id: null,
      ssl_forced: false,
      caching_enabled: $caching,
      block_exploits: $block_exploits,
      advanced_config: $advanced_config,
      meta: { dns_challenge: null },
      allow_websocket_upgrade: $websocket_upgrade,
      http2_support: $http2_support,
      forward_scheme: $scheme,
      enabled: $enabled,
      locations: $locations
    }'
  )

  # 🔍 check if the JSON is valid
  if ! echo "$DATA" | jq empty > /dev/null 2>&1; then
    echo -e "  ⛔${COLOR_RED} ERROR: Invalid JSON generated:\n$DATA ${CoR}"
    exit 1
  fi

  # 🚀 send the API request for update
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  # 📢 check if the response is valid
  ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // empty')
  if [ -z "$ERROR_MSG" ]; then
      PROXY_ID=$(echo "$RESPONSE" | jq -r '.id // "unknown"')
      echo -e "\n ✅ ${COLOR_GREEN}SUCCESS: Proxy host 🔗$DOMAIN_NAMES (ID: ${COLOR_YELLOW}$PROXY_ID${COLOR_GREEN}) was created successfully! 🎉${CoR}\n"
  else
      echo -e " ⛔ ${COLOR_RED}Failed to create proxy host. Error: $ERROR_MSG ${CoR}"
      exit 1
  fi
}

################################
# Update field of existing proxy host
host_update() {
  check_token_notverbose
  HOST_ID="$1"
  FIELD="$2"
  NEW_VALUE="$3"

  #echo -e "\n 🔄 DEBUG: host-update() function has started"
  # echo -e "    🆔 HOST_ID: $HOST_ID"
  # echo -e "    🏷  FIELD: $FIELD"
  # echo -e "    ✏️  VALUE: $NEW_VALUE"

  #  1) Vérifier que tous les paramètres sont fournis
  if [ -z "$HOST_ID" ] || [ -z "$FIELD" ] || [ -z "$NEW_VALUE" ]; then
      echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing required parameters.${CoR}"
      echo -e "    Usage: ${COLOR_ORANGE}$0 --host-update <host_id> <field=value>${CoR}"
      exit 1
  fi

  #  2) Récupérer la configuration actuelle
  CURRENT_DATA=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

  #echo -e "\n 🔄 DEBUG: API response (CURRENT_DATA):\n$CURRENT_DATA\n"

  if ! echo "$CURRENT_DATA" | jq empty > /dev/null 2>&1; then
    echo -e "  ⛔ ${COLOR_RED}ERROR:${CoR} Failed to fetch current proxy configuration."
    exit 1
  fi

  #  3) Vérifier si le champ demandé est modifiable
  FILTERED_DATA=$(echo "$CURRENT_DATA" | jq '{
    domain_names,
    forward_host,
    forward_port,
    access_list_id,
    certificate_id,
    ssl_forced,
    caching_enabled,
    block_exploits,
    advanced_config,
    meta,
    allow_websocket_upgrade,
    http2_support,
    forward_scheme,
    enabled,
    locations,
    hsts_enabled,
    hsts_subdomains
  }')

  #echo -e "\n 🔄 DEBUG: Filtered JSON before update:\n$FILTERED_DATA\n"

  if ! echo "$FILTERED_DATA" | jq -e --arg field "$FIELD" 'has($field)' > /dev/null; then
    echo -e "  ⛔ ${COLOR_RED}ERROR:${CoR} The field '$FIELD' is not a valid field for update."
    exit 1
  fi

  #  4) Modifier la configuration
  if [ "$FIELD" = "forward_port" ]; then
    UPDATED_DATA=$(echo "$FILTERED_DATA" \
      | jq --argjson newVal "$(echo "$NEW_VALUE" | jq -R 'tonumber? // 0')" \
           '.forward_port = $newVal')
  else
    UPDATED_DATA=$(echo "$FILTERED_DATA" \
      | jq --arg newVal "$NEW_VALUE" \
           ".$FIELD = \$newVal")
  fi

  #echo -e "\n 🔄 DEBUG: JSON Sent to API:\n$UPDATED_DATA\n"

  if ! echo "$UPDATED_DATA" | jq empty > /dev/null 2>&1; then
    echo -e "  ⛔ ${COLOR_RED}ERROR: Invalid JSON generated.${CoR}\n$UPDATED_DATA"
    exit 1
  fi

  #  Sending update request to API..."
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$UPDATED_DATA")

  #echo -e "\n 🔄 DEBUG: API Response:\n$RESPONSE\n"

  ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // empty')
  if [ -z "$ERROR_MSG" ]; then
    echo -e "\n ✅ ${COLOR_GREEN}SUCCESS:${CoR}  Proxy host 🆔 $HOST_ID updated successfully! 🎉"

    SUMMARY=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
      -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    if echo "$SUMMARY" | jq empty > /dev/null 2>&1; then

      echo -e "    New Value Proxy host 🆔 $HOST_ID $FIELD : $(echo "$SUMMARY" | jq -r --arg field "$FIELD" '.[$field]')\n"
      echo -e " 🔄 ${COLOR_CYAN}Summary Proxy Host:${CoR}"
      echo -e "    Domaine(s)      : $(echo "$SUMMARY" | jq -r '.domain_names | join(", ")')"
      echo -e "    Forward Host    : $(echo "$SUMMARY" | jq -r '.forward_host')"
      echo -e "    Forward Port    : $(echo "$SUMMARY" | jq -r '.forward_port')"
      echo -e "    Forward Scheme  : $(echo "$SUMMARY" | jq -r '.forward_scheme')"
      echo -e "    SSL Forced      : $(echo "$SUMMARY" | jq -r '.ssl_forced')\n"

    else
      echo -e "\n ⚠️ ${COLOR_YELLOW}WARNING:${CoR} Error to get proxy host data."
    fi

  else
    echo -e "\n ⛔ ${COLOR_RED}Failed to update proxy host. Error:${CoR} $ERROR_MSG"
    exit 1
  fi



}


################################
# Search for a proxy host by domain name
host_search() {
    #check_token false
    check_token_notverbose
    if [ -z "$HOST_SEARCHNAME" ]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: The --host-enable option requires a <host domain>.${CoR}"
        echo -e "     Usage  : ${COLOR_ORANGE}$0 --host-search domain_name${CoR}"
        echo -e "     Example: ${COLOR_GREEN}$0 --host-search example.com${CoR}\n"
        exit 1
    fi
    
    echo -e "\n ${COLOR_CYAN}🔍${CoR} Searching proxy hosts for: ${COLOR_YELLOW}$HOST_SEARCHNAME${CoR}"
    
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    
    if [ -z "$RESPONSE" ] || [ "$RESPONSE" == "null" ]; then
        echo -e " ⛔ ${COLOR_RED}Error: Unable to retrieve proxy host data.${CoR}"
        exit 1
    fi
    
    MATCHES=$(echo "$RESPONSE" | jq -c --arg search "$HOST_SEARCHNAME" '.[] | select(.domain_names[] | contains($search))')
    
    if [ -z "$MATCHES" ]; then
        echo -e " ❌ No proxy host found for: ${COLOR_YELLOW}$HOST_SEARCHNAME${CoR}"
    else
        echo "$MATCHES" | while IFS= read -r line; do
            id=$(echo "$line" | jq -r '.id')
            domain_names=$(echo "$line" | jq -r '.domain_names[]')
            printf "   ${COLOR_GREY}🆔${COLOR_YELLOW}%4s${CoR} ${COLOR_GREEN}%s${CoR}\n" "$id" "$domain_names"
        done
    fi
    echo ""
    exit 0
}

################################
# Enable a proxy host by ID
host_enable() {
    local host_id="$1"
    
    if [ -z "$host_id" ]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: The --host-enable option requires a host 🆔.${CoR}"
        echo -e "     Usage  : ${COLOR_ORANGE}$0 --host-enable <host_id>${CoR}"
        echo -e "     Example: ${COLOR_GREEN}$0 --host-enable 42${CoR}"
        return 1
    fi

    check_token_notverbose

    
    # Check if the proxy host exists and get its current configuration
    CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    
    if [ $? -eq 0 ] && [ -n "$CHECK_RESPONSE" ]; then
        # Get domain name for display
        DOMAIN_NAME=$(echo "$CHECK_RESPONSE" | jq -r '.domain_names[0]')
        
        # Create minimal payload with only the enabled property
        PAYLOAD='{"enabled":true}'
        
        # Send PUT request with minimal payload
        RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$host_id" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
            -H "Content-Type: application/json" \
            -d "$PAYLOAD")
        
        if [ $? -eq 0 ] && ! echo "$RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
            if [ "$DOMAIN_NAME" != "null" ] && [ -n "$DOMAIN_NAME" ]; then

                echo -e "\n ${COLOR_YELLOW}🔄 Enabling proxy host ${CoR} 🆔${COLOR_CYAN}$host_id${CoR} 🌐Domain: ${COLOR_CYAN}$DOMAIN_NAME${CoR}"
                echo -e " ✅ ${COLOR_GREEN}Successfully enabled ${CoR}🆔${COLOR_CYAN}$host_id${CoR} 🌐Domain: ${COLOR_CYAN}$DOMAIN_NAME${CoR}\n"
                           
            else
                echo -e " ℹ️ ${COLOR_YELLOW}No domain name associated with this host${CoR}"
            fi
        else
            ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // "Unknown error"')
            echo -e " ⛔ ${COLOR_RED}Failed to enable proxy host: $ERROR_MSG${CoR}"
        fi
    else
        echo -e " ⛔ ${COLOR_RED}Proxy host with ID $host_id does not exist${CoR}"
    fi
}

################################
# Disable a proxy host by ID
host_disable() {
    local host_id="$1"
    
    if [ -z "$host_id" ]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: The --host-disable option requires a host 🆔.${CoR}"
        echo -e " Usage  : ${COLOR_ORANGE}$0 --host-disable <host_id>${CoR}"
        echo -e " Example: ${COLOR_GREEN}$0 --host-disable 42${CoR}"
        return 1
    fi

    check_token_notverbose

    # Check if the proxy host exists and get its current configuration
    CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    
    if [ $? -eq 0 ] && [ -n "$CHECK_RESPONSE" ]; then
        # Get domain name for display
        DOMAIN_NAME=$(echo "$CHECK_RESPONSE" | jq -r '.domain_names[0]')
        
        # Create minimal payload with only the enabled property
        PAYLOAD='{"enabled":false}'
        
        # Send PUT request with minimal payload
        RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$host_id" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
            -H "Content-Type: application/json" \
            -d "$PAYLOAD")
        
        if [ $? -eq 0 ] && ! echo "$RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
            
            if [ "$DOMAIN_NAME" != "null" ] && [ -n "$DOMAIN_NAME" ]; then
                echo -e "\n ${COLOR_YELLOW}🔄 Disabling proxy host ${CoR} 🆔${COLOR_CYAN}$host_id${CoR} 🌐Domain: ${COLOR_CYAN}$DOMAIN_NAME${CoR}"
                echo -e " ✅ ${COLOR_GREEN}Successfully disabled ${CoR}🆔${COLOR_CYAN}$host_id${CoR} 🌐Domain: ${COLOR_CYAN}$DOMAIN_NAME${CoR}\n"
            else
                echo -e " ℹ️ ${COLOR_YELLOW}No domain name associated with this host${CoR}\n"
            fi
        else
            ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // "Unknown error"')
            echo -e " ⛔ ${COLOR_RED}Failed to disable proxy host: $ERROR_MSG${CoR}\n"
        fi
    else
        echo -e " ⛔ ${COLOR_RED}Proxy host with ID $host_id does not exist${CoR}\n"
    fi
}


################################
# Delete a proxy host
# $1: host_id - ID of the host to delete
host_delete() {
    local host_id="$1"
    
    # Check if ID is provided
    if [ -z "$HOST_ID" ]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: The --host-delete option requires a host 🆔${CoR}"
        echo -e " Usage  : ${COLOR_ORANGE}$0 --host-delete <host_id>${CoR}"
        echo -e " Example: ${COLOR_GREEN}$0 --host-delete 42${CoR}"        
        exit 1
    fi

    check_token_notverbose
    # Check if host exists before attempting deletion
    #echo -e "\n 🔎 Checking if host ID ${COLOR_GREEN}$HOST_ID${CoR} exists..."
    CHECK_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" 2>/dev/null)
    
    CHECK_BODY=${CHECK_RESPONSE//HTTPSTATUS:*/}
    CHECK_STATUS=${CHECK_RESPONSE##*HTTPSTATUS:}

    # Verify host existence
    if [ "$CHECK_STATUS" -eq 404 ]; then
        echo -e " ⛔ ${COLOR_RED}ERROR: Host ID ${COLOR_GREEN}$HOST_ID${COLOR_RED} not found!${CoR}"
        echo -e "\n ${COLOR_YELLOW}💡 Tip: Use --host-list to see all available hosts and their IDs${CoR}"
        exit 1
    elif [ "$CHECK_STATUS" -ne 200 ]; then
        echo -e " ⛔ ${COLOR_RED}ERROR: Failed to check host. Status: $CHECK_STATUS${CoR}"
        if [ -n "$CHECK_BODY" ]; then
            echo -e " 📝 Error details: $CHECK_BODY"
        fi
        exit 1
    fi

    # Extract domain name for confirmation
    DOMAIN_NAME=$(echo "$CHECK_BODY" | jq -r '.domain_names[0] // "unknown"')
    
    # Show confirmation prompt unless AUTO_YES is set
    if [ "$AUTO_YES" != true ]; then
        echo -e " ┌───────────────────────────────────────────"
        echo -e " │ ID: ${COLOR_YELLOW}$HOST_ID${CoR}"
        echo -e " │ Domain: ${COLOR_GREEN}$DOMAIN_NAME${CoR}"
        echo -e " └───────────────────────────────────────────"
        echo -e " ⚠️  ${COLOR_RED}WARNING: This action cannot be undone!${CoR}"
        read -n 1 -r -p " 🔔 Confirm deletion? (y/n): " CONFIRM
        echo
        if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
            echo -e " ❌ ${COLOR_RED}Operation cancelled${CoR}"
            exit 1
        fi
        echo -e " 🗑️ Deleting proxy host ${COLOR_GREEN}$DOMAIN_NAME${CoR} (ID: ${COLOR_GREEN}$HOST_ID${CoR})"
    else
        echo -e "\n ${COLOR_YELLOW}🔔 -y Auto-confirming deletion${CoR}"
        echo -e " 🗑️ Deleting proxy host ${COLOR_GREEN}$DOMAIN_NAME${CoR} (ID: ${COLOR_GREEN}$HOST_ID${CoR})..."
    fi

    # Perform deletion
     RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE \
        "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" 2>/dev/null)

    HTTP_BODY=${RESPONSE//HTTPSTATUS:*/}
    HTTP_STATUS=${RESPONSE##*HTTPSTATUS:}

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e " ✅ ${COLOR_GREEN}Proxy host ${COLOR_YELLOW}$DOMAIN_NAME${CoR} (ID: $HOST_ID) deleted successfully!${CoR}\n"
        exit 0
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete proxy host. Status: $HTTP_STATUS${CoR}"
        if [ -n "$HTTP_BODY" ]; then
            echo -e " 📝 Error details: $HTTP_BODY"
        fi
        exit 1
    fi
}

################################
# ACL  proxy host 
host_acl_enable() {
  # Vérifier que les deux arguments sont fournis
  if [ -z "$HOST_ID" ] || [ -z "$ACCESS_LIST_ID" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Error: HOST_ID and ACCESS_LIST_ID are required to enable the ACL.${CoR}"
    echo -e " Usage: ${COLOR_ORANGE}$0 --host-acl-enable <host_id> <access_list_id>${CoR}"
    echo -e " Example: ${COLOR_GREEN}$0 --host-acl-enable 42 5${CoR}"
    exit 1
  fi
  
  check_token_notverbose
  echo -e "\n ${COLOR_YELLOW}🔓 Enabling ACL${CoR} host 🆔${COLOR_CYAN}$HOST_ID${CoR} with access list 🆔${COLOR_CYAN}$ACCESS_LIST_ID${CoR}"

  DATA=$(jq -n \
    --argjson access_list_id "$ACCESS_LIST_ID" \
    --argjson enabled true \
    '{
      access_list_id: $access_list_id,
      enabled: $enabled
    }')

  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

  if [ "$(echo "$RESPONSE" | jq -r '.error | length')" -eq 0 ]; then
    echo -e " ✅ ${COLOR_GREEN}ACL successfully enabled access list ${CoR}🆔${COLOR_CYAN}$ACCESS_LIST_ID${CoR} for host🆔${COLOR_CYAN}$HOST_ID${CoR}\n"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to enable ACL. Error: $(echo "$RESPONSE" | jq -r '.message')${CoR}\n"
  fi
}

################################
# Disable ACL for a given proxy host
host_acl_disable() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Error: HOST_ID is required to disable the ACL.${CoR}"
    echo -e "    Usage: $0 --host-acl-disable <host_id>"
    exit 1
  fi
  check_token_notverbose  

  DATA=$(jq -n \
    --argjson access_list_id null \
    --argjson enabled false \
    '{
      access_list_id: $access_list_id,
      enabled: $enabled
    }')
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")
  if [ "$(echo "$RESPONSE" | jq -r '.error | length')" -eq 0 ]; then
    echo -e "\n 🔒 ${COLOR_ORANGE}Disabling ACL for host${CoR}🆔${COLOR_CYAN} $HOST_ID${CoR}"
    echo -e " ✅ ${COLOR_GREEN}ACL successfully disabled ACL for host ${CoR}🆔${COLOR_CYAN}$HOST_ID${CoR}\n"
  else
    echo -e "\n ⛔ ${COLOR_RED}Failed to disable ACL. Error: $(echo "$RESPONSE" | jq -r '.message')${CoR}\n"
  fi
}

################################
# Show details of a specific proxy host
host_show() {
    #local host_id="$1"
    if [ -z "$host_id" ]; then
        echo -e "\n ⛔ ${COLOR_RED}The --host-show option requires a host ID.${CoR}"
        echo -e " Usage: ${COLOR_ORANGE}$0 --host-show <ID>${CoR}"
        echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
        return 1
    fi
  check_token_notverbose    
    echo -e "\n 🔍 Fetching details for proxy host ID: ${COLOR_YELLOW}$host_id${CoR}..."
    # get host details
    local response=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    # Check if the response contains an error
    if echo "$response" | jq -e '.error' >/dev/null; then
        echo -e " ⛔ ${COLOR_RED}Error: $(echo "$response" | jq -r '.error.message')${CoR}\n"
        return 1
    fi
    # Formater et afficher les détails
    echo -e "\n📋 ${COLOR_YELLOW}Host Details:${CoR}"
    echo -e "┌───────────────────────────────────"
    echo -e "│ 🆔 ID: ${COLOR_GREEN_b}$(echo "$response" | jq -r '.id')${CoR}"
    echo -e "│ 🌐 Domains: ${COLOR_GREEN_b}$(echo "$response" | jq -r '.domain_names[]' | tr '\n' ' ')${CoR}"
    echo -e "│ 🔄 Forward Configuration:"
    echo -e "│   • Host: ${COLOR_GREEN_b}$(echo "$response" | jq -r '.forward_host')${CoR}"
    echo -e "│   • Port: ${COLOR_GREEN_b}$(echo "$response" | jq -r '.forward_port')${CoR}"
    echo -e "│   • Scheme: $(colorize_boolean $(echo "$response" | jq -r '.forward_scheme'))"
    echo -e "│ ✅ Status: $(colorize_boolean $(echo "$response" | jq -r '.enabled | if . then "Enabled" else "Disabled" end'))"
    echo -e "│ 🔒 SSL Configuration:"
    echo -e "│    • Certificate ID: ${COLOR_ORANGE}$(echo "$response" | jq -r '.certificate_id')${CoR}"
    echo -e "│    • SSL Forced: $(colorize_boolean $(echo "$response" | jq -r '.ssl_forced | if . then "true" else "false" end'))"
    echo -e "│    • HTTP/2: $(colorize_boolean $(echo "$response" | jq -r '.http2_support | if . then "true" else "false" end'))"
    echo -e "│    • HSTS: $(colorize_boolean $(echo "$response" | jq -r '.hsts_enabled | if . then "true" else "false" end'))"
    echo -e "│ 🛠️ Features:"
    echo -e "│    • Block Exploits: $(colorize_boolean $(echo "$response" | jq -r '.block_exploits | if . then "true" else "false" end'))"
    echo -e "│    • Caching: $(colorize_boolean $(echo "$response" | jq -r '.caching_enabled | if . then "true" else "false" end'))"
    echo -e "│    • Websocket Upgrade: $(colorize_boolean $(echo "$response" | jq -r '.websockets_enabled | if . then "true" else "false" end'))"
    echo -e "│ 🔑 Access List ID: ${COLOR_ORANGE}$(echo "$response" | jq -r '.access_list_id')${CoR}"
    
    # Vérifier et afficher la configuration avancée
    if [ "$(echo "$response" | jq -r '.advanced_config')" != "null" ]; then
        echo -e "│ ⚙️ Advanced Config: ${COLOR_GREEN}Yes${CoR}"
        echo -e "│"
        echo "$response" | jq -r '.advanced_config' | while IFS= read -r line; do
            if [ -n "$line" ]; then
                echo -e "│ ${COLOR_GRAY}$line${CoR}"
            else
                echo -e "│"
            fi
        done
    else
        echo -e "│ ⚙️ Advanced Config: ${COLOR_RED}No${CoR}"
    fi
    
    echo -e "└────────────────────────────────────"
    return 0
}




################################
# Delete a certificate in NPM
cert_delete() {
  local CERT_IDENTIFIER="$1"
  
  if [ -z "$CERT_IDENTIFIER" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Error: Please specify a domain or certificate ID${CoR}"
    echo -e "Usage: --cert-delete <domain.com or ID>"
    exit 1
  fi

  check_token_notverbose

  # Get certificates list from API
  CERTIFICATES=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

  # Check if input is a number (ID) or domain
  if [[ "$CERT_IDENTIFIER" =~ ^[0-9]+$ ]]; then
    # It's an ID
    CERT_ID="$CERT_IDENTIFIER"
    CERT_EXISTS=$(echo "$CERTIFICATES" | jq -r --arg id "$CERT_ID" '.[] | select(.id == ($id|tonumber)) | .id')
    
    # Add verification for CERT_EXISTS
    if [ -z "$CERT_EXISTS" ]; then
      echo -e "\n ⛔ ${COLOR_RED}No certificate found with ID: $CERT_ID${CoR}"
      exit 1
    fi
    #echo -e "  ✅ Certificate ID $CERT_ID found"
  else
    # It's a domain - Get all matching certificates
    MATCHING_CERTS=$(echo "$CERTIFICATES" | jq -r --arg domain "$CERT_IDENTIFIER" \
      '[.[] | select(.domain_names[] == $domain or .nice_name == $domain)]')
    
    CERT_COUNT=$(echo "$MATCHING_CERTS" | jq 'length')

    if [ "$CERT_COUNT" -eq 0 ]; then
      echo -e " ⛔ ${COLOR_RED}No certificates found for domain: $CERT_IDENTIFIER${CoR}"
      exit 1
    elif [ "$CERT_COUNT" -eq 1 ]; then
      CERT_ID=$(echo "$MATCHING_CERTS" | jq -r '.[0].id')
    else
      # Multiple certificates found, let user choose
      echo -e " 📜 Multiple certificates found for $CERT_IDENTIFIER:"
      echo "$MATCHING_CERTS" | jq -r '.[] | "ID: \(.id) - Provider: \(.provider) - Expires: \(.expires_on) - Domains: \(.domain_names|join(", "))"' | \
        awk '{print NR ") " $0}'
      
      if [ "$AUTO_YES" = true ]; then
        echo -e " ⚠️ Multiple certificates found with -y option. Please specify certificate ID instead."
        exit 1
      fi

      read -r -p "Enter the number of the certificate to delete (1-$CERT_COUNT): " CHOICE
      if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || [ "$CHOICE" -lt 1 ] || [ "$CHOICE" -gt "$CERT_COUNT" ]; then
        echo -e " ⛔ ${COLOR_RED}Invalid selection${CoR}"
        exit 1
      fi
      
      CERT_ID=$(echo "$MATCHING_CERTS" | jq -r --arg idx "$((CHOICE-1))" '.[$idx|tonumber].id')
    fi
  fi

  if [ -z "$CERT_ID" ]; then
    echo -e " ⛔ ${COLOR_RED}No valid certificate found${CoR}"
    exit 1
  fi

  # Ask for confirmation unless AUTO_YES is set
  if [ "$AUTO_YES" = true ]; then
    #echo -e " 🔔 The -y option was provided. Skipping confirmation prompt..."
    CONFIRM="y"
  else
  echo -e "${COLOR_YELLOW}"
    read -n 1 -r -p "  ⚠️ Are you sure you want to delete certificate ID: $CERT_ID ? (y/n): " CONFIRM
    echo -e "${CoR}"
  fi

  if [[ "$CONFIRM" != "y" ]]; then
    echo -e "${COLOR_RED}  ❌ Certificate deletion aborted.${CoR}\n"
    exit 1
  fi

  echo -e "\n  🗑️ Deleting certificate ID: $CERT_ID..."

  # Delete certificate through API
  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE \
    "$BASE_URL/nginx/certificates/$CERT_ID" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

  HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
  HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e "  ✅ ${COLOR_GREEN}Certificate successfully deleted!${CoR}\n"
  else
    echo -e "  ⛔ ${COLOR_RED}Deletion failed. Status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
  fi
}

################################
# Generate Let's Encrypt certificate if not exists
cert_generate() {
    # 1. Local variables
    DOMAIN_NAMES="${1:-}"
    DOMAIN=$DOMAIN_NAMES
    EMAIL="${2:-}"
    DNS_PROVIDER="${3:-}"
    DNS_CREDENTIALS_JSON="${4:-}"
    EXISTING_CERT=""
    IS_WILDCARD=false

    # 2. Basic validation
    if [ -z "$DOMAIN_NAMES" ]; then
            echo -e "\n ${COLOR_RED}❌${CoR} Error: Domain is required $DOMAIN"
            echo -e "    Usage: $0 --cert-generate <domain> [email] [dns_provider] [dns_credentials]\n"
        exit 1
    fi

    if [ -z "$EMAIL" ]; then
        EMAIL="$DEFAULT_EMAIL"
            echo -e "\n 📧 Using default email: ${COLOR_YELLOW}$EMAIL${CoR}"
    fi

    check_token_notverbose

    # 3. Check if wildcard and validate requirements
    if [[ "$DOMAIN" == \** ]]; then
        IS_WILDCARD=true
        if [ -z "$DNS_PROVIDER" ] || [ -z "$DNS_CREDENTIALS_JSON" ]; then
            echo -e " ⛔ ${COLOR_RED}DNS provider and credentials are required for wildcard certificates${CoR}\n"
            exit 1
        fi

        # JSON format validation
        if ! echo "$DNS_CREDENTIALS_JSON" | jq '.' >/dev/null 2>&1; then
            echo -e " ⛔ ${COLOR_RED}Invalid JSON format for DNS credentials${CoR}\n"
            exit 1
        fi


    else
        # Seulement vérifier le domaine dans NPM si ce n'est pas un wildcard
        PROXY_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
        
        DOMAIN_EXISTS=$(echo "$PROXY_RESPONSE" | jq -r --arg DOMAIN "$DOMAIN" \
            '.[] | select(.domain_names[] == $DOMAIN) | .id')

        if [ -z "$DOMAIN_EXISTS" ]; then
            echo -e "\n ${COLOR_RED}❌${CoR} Domain ${COLOR_YELLOW}$DOMAIN${CoR} is not configured in NPM."
            echo -e " ${COLOR_YELLOW}💡${CoR} First create a proxy host with:"
            echo -e "   ${COLOR_CYAN}$0 --host-create $DOMAIN -i <forward_host> -p <forward_port>${CoR}\n"
            exit 1
        fi
    fi

    # Ensuite vérifier les certificats existants
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
  
    EXISTING_CERT=$(echo "$RESPONSE" | jq -r --arg domain "$DOMAIN" \
        '.[] | select(.domain_names[] == $domain) | select(.expired == false)')
    

    if [ -n "$EXISTING_CERT" ]; then
        CERT_ID=$(echo "$EXISTING_CERT" | jq -r '.id')
        CERT_EXPIRES=$(echo "$EXISTING_CERT" | jq -r '.expires_on')
        echo -e " ${COLOR_GREEN}🔔${CoR} Valid certificate found for ${COLOR_YELLOW}$DOMAIN${CoR} (Certificate ID: ${COLOR_ORANGE}$CERT_ID${CoR}, expires in ${COLOR_YELLOW}$(( ($(date -d "$CERT_EXPIRES" +%s) - $(date +%s)) / 86400 ))${CoR} days)"
        return 0
    fi

    # 4. Check for existing certificate
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
  
    EXISTING_CERT=$(echo "$RESPONSE" | jq -r --arg domain "$DOMAIN" \
        '.[] | select(.domain_names[] == $domain) | select(.expired == false)')

    if [ -n "$EXISTING_CERT" ]; then
        CERT_ID=$(echo "$EXISTING_CERT" | jq -r '.id')
        CERT_EXPIRES=$(echo "$EXISTING_CERT" | jq -r '.expires_on')
        echo -e " ${COLOR_GREEN}🔔${CoR} Valid certificate found for ${COLOR_YELLOW}$DOMAIN${CoR} (Certificate ID: ${COLOR_ORANGE}$CERT_ID${CoR}, expires in ${COLOR_YELLOW}$(( ($(date -d "$CERT_EXPIRES" +%s) - $(date +%s)) / 86400 ))${CoR} days)"
        return 0
    fi

    # 5. Display parameters and confirmation
    echo -e "\n ${COLOR_CYAN}📝${CoR} Certificate generation parameters:"
    echo -e "    • Domain: ${COLOR_YELLOW}$DOMAIN${CoR}"
    echo -e "    • Email: ${COLOR_YELLOW}$EMAIL${CoR}"
    if [ -n "$DNS_PROVIDER" ]; then
        echo -e "  • DNS Provider: ${COLOR_YELLOW}$DNS_PROVIDER${CoR}"
    fi

    # 6. Confirmation
    if [ "$AUTO_YES" = true ]; then
            echo -e "\n ${COLOR_YELLOW}🔔 The -y option was provided.${CoR} AUTO Yes activate.${CoR}"
        CONFIRM="y"
    else
        echo -en " ${COLOR_RED}❓${CoR} No existing certificate found for ${COLOR_YELLOW}$DOMAIN${CoR}. Create new Let's Encrypt certificate? (y/n): "
            read -n 1 -r CONFIRM
            echo  # New line after response
            CONFIRM=${CONFIRM:-y}  # Default to 'y' if empty
            CONFIRM=$(echo "$CONFIRM" | tr '[:upper:]' '[:lower:]')  # Convert to lowercase
    fi

    if [[ "$CONFIRM" != "y" ]]; then
        echo -e "${COLOR_RED} ❌ Certificate creation aborted.${CoR}\n"
        exit 0
    fi

    # 7. Prepare request data
    echo -e " ${COLOR_YELLOW}🔔 Initiating certificate generation ${COLOR_GREEN}$DOMAIN${CoR}"
    echo -e " ${COLOR_CYAN}🚀 Sending certificate generation request${CoR}"
    echo -e " ${COLOR_ORANGE}⏳ This process may take a few minutes...${CoR}"

    if [ "$IS_WILDCARD" = true ]; then
        echo -e " 🔑 Using DNS challenge with provider: $DNS_PROVIDER"
        REQUEST_DATA=$(jq -n \
            --arg domain "$DOMAIN" \
            --arg email "$EMAIL" \
            --arg dns_provider "$DNS_PROVIDER" \
            --arg credentials "$DNS_CREDENTIALS_JSON" \
            '{
                provider: "letsencrypt",
                domain_names: [$domain],
                meta: {
                    dns_challenge: true,
                    dns_provider: $dns_provider,
                    dns_provider_credentials: $credentials,
                    letsencrypt_agree: true,
                    letsencrypt_email: $email,
                    propagation_seconds: 60
                }
            }')
    else
        REQUEST_DATA=$(jq -n \
            --arg domain "$DOMAIN" \
            --arg email "$EMAIL" \
            '{
                provider: "letsencrypt",
                domain_names: [$domain],
                meta: {
                    letsencrypt_agree: true,
                    letsencrypt_email: $email
                }
            }')
    fi

    # 8. Send request and handle response
    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
        -H "Content-Type: application/json" \
        --data "$REQUEST_DATA")

    HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
    HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

    if [ "$HTTP_STATUS" -eq 201 ]; then
        CERT_ID=$(echo "$HTTP_BODY" | jq -r '.id')
        echo -e "\n ✅ ${COLOR_GREEN}Certificate generation initiated successfully!${CoR}"
        echo -e " 📋 Certificate Details:"
        echo -e "  • Certificate ID: ${COLOR_YELLOW}$CERT_ID${CoR}"
        echo -e "  • Status: ${COLOR_GREEN}Created${CoR}"
        echo -e "  • Domain: ${COLOR_YELLOW}$DOMAIN${CoR}"
        echo -e "  • Provider: ${COLOR_YELLOW}Let's Encrypt${CoR}\n"

        # Export variables for host_ssl_enable
        export GENERATED_CERT_ID="$CERT_ID"
        export DOMAIN_EXISTS

        if [ "$HOST_SSL_ENABLE" = true ]; then
            echo -e "\n ⏳ ${COLOR_YELLOW}Waiting for certificate propagation (30 seconds)...${CoR}"
            sleep 30
            
            if ! check_certificate_exists "$DOMAIN"; then
                echo -e "\n ⛔ ${COLOR_RED}ERROR: Certificate not found after generation${CoR}"
                exit 1
            fi

        fi
        #return 0
    else
        echo -e "\n ❌ ${COLOR_RED}Certificate generation failed!${CoR}"
        ERROR_MSG=$(echo "$HTTP_BODY" | jq -r '.error.message // "Unknown error"')
        echo -e " ⛔ Error: ${COLOR_RED}$ERROR_MSG${CoR}"
        
        DEBUG_STACK=$(echo "$HTTP_BODY" | jq -r '.debug.stack[]? // empty')
        if [ -n "$DEBUG_STACK" ]; then
            echo -e "\n 🔍 Debug Stack:"
            echo "$DEBUG_STACK" | while read -r line; do
                echo -e "  • ${COLOR_YELLOW}$line${CoR}"
            done
        fi

        echo -e "\n ${COLOR_CYAN}🔍${CoR} Troubleshooting suggestions:"
        echo -e "  • Verify domain DNS records are properly configured"
        echo -e "  • Ensure domain is accessible via HTTP/HTTPS"
        echo -e "  • Check if Let's Encrypt rate limits are not exceeded"
        echo -e "  • Verify Nginx Proxy Manager is properly configured"
        echo -e "  • Check if port 80 is open and accessible"
        echo -e "  • Ensure no firewall is blocking access"
        echo -e "  • Check Nginx Proxy Manager logs for more details"
        
        echo -e "\n ${COLOR_CYAN}💡${CoR} You can try:"
        echo -e "  • Wait a few minutes and try again (DNS propagation)"
        echo -e "  • Check Nginx Proxy Manager logs:"
        echo -e "    ${COLOR_GREEN}docker logs nginx-proxy-manager${CoR}"
        echo -e "  • Check Let's Encrypt logs:"
        echo -e "    ${COLOR_GREEN}docker exec nginx-proxy-manager cat /tmp/letsencrypt-log/letsencrypt.log${CoR}"

        echo -e "\n 📋 Debug Information:"
        echo -e "  • HTTP Status: $HTTP_STATUS"
        echo -e "  • Response: $HTTP_BODY"
        echo -e "  • Request Data: $REQUEST_DATA"
     
        return 1
  fi
}

################################
# Enable SSL for a proxy host
host_ssl_enable() {
    local HOST_ID="${1:-}"
    local CERT_ID="${2:-}"

    if [ "$CERT_GENERATE" = true ]; then
        if [ -z "$DOMAIN_EXISTS" ]; then
            echo -e "\n ⛔ ${COLOR_RED}ERROR: No domain found in NPM${CoR}"
            exit 1
        fi
        if [ -z "$GENERATED_CERT_ID" ]; then
            echo -e "\n ⛔ ${COLOR_RED}ERROR: No certificate ID available${CoR}"
            exit 1
        fi
        HOST_ID="$DOMAIN_EXISTS"
        CERT_ID="$GENERATED_CERT_ID"
    else
        if [ -z "$HOST_ID" ]; then
            echo -e "\n ⛔ ${COLOR_RED}ERROR  : The --host-ssl-enable option requires a host 🆔${CoR}"
            echo -e "    Usage  : ${COLOR_ORANGE}$0 --host-ssl-enable <host_id> <cert_id>${CoR}"
            echo -e "    Example: ${COLOR_GREEN}$0 --host-ssl-enable 42 240${CoR}\n"
            exit 1
        fi
        if [ -z "$CERT_ID" ]; then
            echo -e "\n ⛔ ${COLOR_RED}ERROR: Certificate ID is required${CoR}"
            echo -e "    Usage  : ${COLOR_ORANGE}$0 --host-ssl-enable <host_id> <cert_id>${CoR}"
            echo -e "    Example: ${COLOR_GREEN}$0 --host-ssl-enable 42 240${CoR}\n"
            exit 1
        fi
    fi
    # Quick check if host exists
  check_token_notverbose
        local CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    if [ "$(echo "$CHECK_RESPONSE" | jq -r .id)" = "null" ]; then
        echo -e " ${COLOR_RED}❌${CoR} Host ID $HOST_ID not found"
        return 1
    fi

    # Get host domain and current certificate ID
    local HOST_DOMAIN=$(echo "$CHECK_RESPONSE" | jq -r '.domain_names[0]')
 
    # Update SSL configuration
    local DATA=$(jq -n \
        --arg cert_id "$CERT_ID" \
        '{
            "certificate_id": ($cert_id|tonumber),
            "ssl_forced": true,
            "http2_support": true
        }')

    local HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

    local HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
    local HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}
    
    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e "\n ✅ ${COLOR_GREEN}SSL enabled successfully for${CoR} ${COLOR_YELLOW}$HOST_DOMAIN${CoR} (ID: ${COLOR_CYAN}$HOST_ID${CoR}) (Cert ID: ${COLOR_CYAN}$CERT_ID${CoR})\n"
        return 0 
        #exit 0
    else
        echo -e "\n ⛔ ${COLOR_RED}Failed to enable SSL. HTTP status: $HTTP_STATUS${CoR}\n"
        echo -e " 📋 Error details: $HTTP_BODY \n"
        return 1
  fi
  
}

################################  
# disable_ssl
host_ssl_disable() {
    if [ -z "$HOST_ID" ]; then
        echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing argument${CoR}"
        echo -e "    Usage  : ${COLOR_ORANGE}$0 --host-ssl-disable <host_id>${CoR}"
        echo -e "    Find ID: ${COLOR_ORANGE}$0 --host-list${CoR}\n"
        exit 1
    fi
  check_token_notverbose

    CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    if echo "$CHECK_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
        DATA=$(jq -n --argjson cert_id null '{
            certificate_id: $cert_id,
            ssl_forced: false,
            http2_support: false,
            hsts_enabled: false,
            hsts_subdomains: false
        }')

        HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
        -H "Content-Type: application/json; charset=UTF-8" \
        --data-raw "$DATA")

        HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
        HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

        if [ "$HTTP_STATUS" -eq 200 ]; then
            echo -e "\n 🚫 Disabling 🔓 SSL for proxy 🆔${COLOR_YELLOW}$HOST_ID${CoR}"
            echo -e " ✅ ${COLOR_GREEN}SSL disabled successfully!${CoR} 🆔${COLOR_CYAN}$HOST_ID${CoR}\n"
        else
            echo " Data sent: $DATA"  # Log the data sent
            echo -e " ⛔ ${COLOR_RED}Failed to disable SSL. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
        fi
    else
        echo -e " ⛔ ${COLOR_RED}Proxy host with ID $HOST_ID does not exist.${CoR}\n"
    fi
}


################################
# Create a new access list with various options
# Usage:
#   access_list_create <name> [options]
# Options:
#   --auth <username> <password>  Add basic authentication
#   --access allow|deny <ip>      Add IP access rule
#   --satisfy any|all            Set satisfy condition (default: all)
#   --pass-auth                  Enable pass auth
access_list_create() {
    check_token_notverbose

    if [ $# -lt 3 ]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: Arguments insuffisants${CoR}"
        echo -e "   ${COLOR_CYAN}Usage:${CoR}"
        echo -e "    1. ${COLOR_GREEN}Basic Authentication:${CoR}"
        echo -e "       ${COLOR_ORANGE}$0 --access-list-create <name> --auth <username> <password> [--pass-auth] [--satisfy any|all]${CoR}"
        echo -e "    2. ${COLOR_GREEN}IP Access Rules:${CoR}"
        echo -e "       ${COLOR_ORANGE}$0 --access-list-create <name> --access allow|deny <ip> [--satisfy any|all]${CoR}"
        echo -e "    3. ${COLOR_GREEN}Combined Rules:${CoR}"
        echo -e "       ${COLOR_ORANGE}$0 --access-list-create <name> --auth <user> <pass> --access allow <ip> --satisfy any --pass-auth${CoR}"
        echo -e "\n   ${COLOR_CYAN}Examples:${CoR}"
        echo -e "    ${COLOR_GREEN}$0 --access-list-create secure_area --auth admin secret123${CoR}"
        echo -e "    ${COLOR_GREEN}$0 --access-list-create office --access allow 192.168.1.0/24${CoR}"
        echo -e "    ${COLOR_GREEN}$0 --access-list-create full_options --auth user1 pass1 --access allow 127.0.0.1 --satisfy any --pass-auth${CoR}\n"
        return 1
    fi

    local NAME="$1"
    shift
    
    # Initialize variables
    local SATISFY_ANY="false"
    local PASS_AUTH="false"
    local AUTH_ITEMS="[]"
    local IP_CLIENTS="[]"

    echo -e "\n🔑 Creating access list: ${COLOR_GREEN}$NAME${CoR}"

    # Process all arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --auth)
                if [ $# -lt 3 ]; then
                    echo -e "\n ⛔ ${COLOR_RED}ERROR: --auth requires username and password${CoR}"
                    return 1
                fi
                AUTH_ITEMS=$(echo "$AUTH_ITEMS" | jq --arg user "$2" --arg pass "$3" '. + [{
                    username: $user,
                    password: $pass
                }]')
                shift 3
                ;;
            --access)
                if [ $# -lt 3 ]; then
                    echo -e "\n ⛔ ${COLOR_RED}ERROR: --access requires allow/deny and IP${CoR}"
                    return 1
                fi
                if [[ ! "$2" =~ ^(allow|deny)$ ]]; then
                    echo -e "\n ⛔ ${COLOR_RED}ERROR: Invalid access type. Must be 'allow' or 'deny'${CoR}"
                    return 1
                fi
                IP_CLIENTS=$(echo "$IP_CLIENTS" | jq --arg ip "$3" --arg dir "$2" '. + [{
                    address: $ip,
                    directive: $dir
                }]')
                shift 3
                ;;
            --satisfy)
                if [ $# -lt 2 ]; then
                    echo -e "\n ⛔ ${COLOR_RED}ERROR: --satisfy requires any/all${CoR}"
                    return 1
                fi
                if [ "$2" = "any" ]; then
                    SATISFY_ANY="true"
                elif [ "$2" = "all" ]; then
                    SATISFY_ANY="false"
                else
                    echo -e "\n ⛔ ${COLOR_RED}ERROR: Invalid satisfy value. Must be 'any' or 'all'${CoR}"
                    return 1
                fi
                shift 2
                ;;
            --pass-auth)
                PASS_AUTH="true"
                shift
                ;;
            *)
                echo -e "\n ⛔ ${COLOR_RED}ERROR: Unknown option $1${CoR}"
                return 1
                ;;
        esac
    done

    # Vérifier qu'au moins une règle est définie
    if [ "$AUTH_ITEMS" = "[]" ] && [ "$IP_CLIENTS" = "[]" ]; then
        echo -e "\n ⛔ ${COLOR_RED}ERROR: At least one --auth or --access rule is required${CoR}"
        return 1
    fi

    # Build payload
    local PAYLOAD=$(jq -n \
        --arg name "$NAME" \
        --argjson satisfy_any "$SATISFY_ANY" \
        --argjson pass_auth "$PASS_AUTH" \
        --argjson items "$AUTH_ITEMS" \
        --argjson clients "$IP_CLIENTS" \
        '{
            name: $name,
            satisfy_any: $satisfy_any,
            pass_auth: $pass_auth,
            items: $items,
            clients: $clients
        }')

    # Create access list via API
    RESPONSE=$(curl -s -X POST "$BASE_URL/nginx/access-lists" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    # Check for errors
    if [ "$(echo "$RESPONSE" | jq -r '.error.message // empty')" != "" ]; then
        echo -e " ⛔ ${COLOR_RED}Failed to create access list${CoR}"
        echo -e "    Error: $(echo "$RESPONSE" | jq -r '.error.message')"
        return 1
    fi

    # Display results
    local NEW_ID=$(echo "$RESPONSE" | jq -r '.id')
    echo -e " ✅ ${COLOR_GREEN}Access list created successfully!${CoR}"
    echo -e " ┌───────────────────────────────────────────"
    echo -e " │ ID: ${COLOR_YELLOW}$NEW_ID${CoR}"
    echo -e " │ Name: ${COLOR_GREEN}$NAME${CoR}"
    echo -e " │ Satisfy: ${COLOR_CYAN}$([ "$SATISFY_ANY" = "true" ] && echo "any" || echo "all")${CoR}"
    echo -e " │ Pass Auth: ${COLOR_CYAN}$([ "$PASS_AUTH" = "true" ] && echo "yes" || echo "no")${CoR}"
    
    if [ "$AUTH_ITEMS" != "[]" ]; then
        echo -e " │ 👤 Authentication Rules:"
        echo "$AUTH_ITEMS" | jq -r '.[] | " │  • User: \(.username)"'
    fi

    if [ "$IP_CLIENTS" != "[]" ]; then
        echo -e " │ 🌐 Access Rules:"
        echo "$IP_CLIENTS" | jq -r '.[] | " │  • \(.directive) \(.address)"'
    fi
    echo -e " └───────────────────────────────────────────"
}

access_list_update() {
    check_token_notverbose
    echo -e "\n🔑 ${COLOR_CYAN}Updating access list...${CoR}"
    echo -e "Enter the ID of the access list to update:"
    read -r access_list_id

    # Get the current access list details
    local current_list=$(curl -s -X GET "$BASE_URL/nginx/access-lists/$access_list_id" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    if [ "$(echo "$current_list" | jq -r '.error | length')" -ne 0 ]; then
        echo -e " ⛔ ${COLOR_RED}Failed to fetch access list details. Error: $(echo "$current_list" | jq -r '.error')${CoR}"
        return 1
    fi

    # Extract current values
    local current_name=$(echo "$current_list" | jq -r '.name')
    local current_auth_type=$(echo "$current_list" | jq -r '.auth_type')
    local current_satisfy=$(echo "$current_list" | jq -r '.satisfy')
    local current_pass_auth=$(echo "$current_list" | jq -r '.pass_auth')
    
    echo -e "\n${COLOR_CYAN}Current Access List Details:${CoR}"
    echo -e "Name: $current_name"
    echo -e "Auth Type: $current_auth_type"
    echo -e "Satisfy Rule: $current_satisfy"
    echo -e "Pass Auth: $current_pass_auth"
    
    # Update name
    echo -e "\nCurrent name is: ${COLOR_GREEN}$current_name${CoR}"
    echo -e "Enter new name (or press Enter to keep current):"
    read -r new_name
    new_name=${new_name:-$current_name}
    
    # Update auth type
    echo -e "\nCurrent auth type is: ${COLOR_GREEN}$current_auth_type${CoR}"
    echo -e "Select new authorization type:"
    echo "1) Basic Authentication"
    echo "2) None (Allow All)"
    echo "3) Keep current"
    read -r auth_type_choice
    
    local auth_type="$current_auth_type"
    local pass_auth=$current_pass_auth
    local satisfy="$current_satisfy"
    local clients=$(echo "$current_list" | jq '.clients')
    local whitelist=$(echo "$current_list" | jq '.whitelist')
    
    case $auth_type_choice in
        1)
            auth_type="basic"
            pass_auth=true
            ;;
        2)
            auth_type="none"
            pass_auth=false
            clients="[]"
            whitelist="[]"
            ;;
    esac
    
    if [ "$auth_type" = "basic" ]; then
        # Update satisfy rule
        echo -e "\nCurrent satisfy rule is: ${COLOR_GREEN}$current_satisfy${CoR}"
        echo -e "Select new satisfy rule:"
        echo "1) Any (OR) - Client needs to match any of the rules"
        echo "2) All (AND) - Client needs to match all rules"
        echo "3) Keep current"
        read -r satisfy_choice
        
        case $satisfy_choice in
            1)
                satisfy="any"
                ;;
            2)
                satisfy="all"
                ;;
        esac
        
        # Update basic auth users
        echo -e "\nDo you want to modify basic auth users? (y/n)"
        read -r modify_users
        
        if [ "$modify_users" = "y" ]; then
            echo -e "\nCurrent users:"
            echo "$current_list" | jq -r '.clients[] | "Username: \(.username)"'
            
            echo -e "\nDo you want to:"
            echo "1) Add new users to existing ones"
            echo "2) Replace all users"
            echo "3) Keep current users"
            read -r users_action
            
            case $users_action in
                1|2)
                    [ "$users_action" = "2" ] && clients="["
                    while true; do
                        echo -e "\nEnter username:"
                        read -r username
                        echo -e "Enter password:"
                        read -r -s password
                        
                        if [ "$users_action" = "1" ]; then
                            clients=$(echo "$clients" | jq '. += [{"username":"'"$username"'","password":"'"$password"'"}]')
                        else
                            if [ "$clients" != "[" ]; then
                                clients="$clients,"
                            fi
                            clients="$clients{\"username\":\"$username\",\"password\":\"$password\"}"
                        fi
                        
                        echo -e "\nAdd another user? (y/n)"
                        read -r more_users
                        [ "$more_users" != "y" ] && break
                    done
                    [ "$users_action" = "2" ] && clients="$clients]"
                    ;;
            esac
        fi
        
        # Update IP whitelist
        echo -e "\nDo you want to modify IP whitelist? (y/n)"
        read -r modify_ips
        
        if [ "$modify_ips" = "y" ]; then
            echo -e "\nCurrent whitelisted IPs:"
            echo "$current_list" | jq -r '.whitelist[] | "IP: \(.address)"'
            
            echo -e "\nDo you want to:"
            echo "1) Add new IPs to existing ones"
            echo "2) Replace all IPs"
            echo "3) Keep current IPs"
            read -r ips_action
            
            case $ips_action in
                1|2)
                    [ "$ips_action" = "2" ] && whitelist="["
                    while true; do
                        echo -e "\nEnter IP address (with optional CIDR, e.g., 192.168.1.0/24):"
                        read -r ip
                        
                        if [ "$ips_action" = "1" ]; then
                            whitelist=$(echo "$whitelist" | jq '. += [{"address":"'"$ip"'","owner":"User"}]')
                        else
                            if [ "$whitelist" != "[" ]; then
                                whitelist="$whitelist,"
                            fi
                            whitelist="$whitelist{\"address\":\"$ip\",\"owner\":\"User\"}"
                        fi
                        
                        echo -e "Add another IP address? (y/n)"
                        read -r more_ips
                        [ "$more_ips" != "y" ] && break
                    done
                    [ "$ips_action" = "2" ] && whitelist="$whitelist]"
                    ;;
            esac
        fi
    fi
    
    # Prepare the JSON payload
    local payload="{
        \"name\": \"$new_name\",
        \"satisfy\": \"$satisfy\",
        \"pass_auth\": $pass_auth,
        \"auth_type\": \"$auth_type\",
        \"clients\": $clients,
        \"whitelist\": $whitelist
    }"
    
    # Update the access list
    local response=$(curl -s -X PUT "$BASE_URL/nginx/access-lists/$access_list_id" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
        -H "Content-Type: application/json; charset=UTF-8" \
        -d "$payload")
    
    if [ "$(echo "$response" | jq -r '.error | length')" -eq 0 ]; then
        echo -e "\n ✅ ${COLOR_GREEN}Access list updated successfully!${CoR}"
        echo -e "\n${COLOR_CYAN}Updated Access List Details:${CoR}"
        echo -e "ID: $access_list_id"
        echo -e "Name: $new_name"
        echo -e "Auth Type: $auth_type"
        echo -e "Satisfy: $satisfy"
    else
        echo -e "\n ⛔ ${COLOR_RED}Failed to update access list. Error: $(echo "$response" | jq -r '.error')${CoR}"
    fi
} 

################################
# Delete an access list
access_list_delete() {
       
    if [ -z "$ACCESS_LIST_ID" ]; then
        echo -e "\n ⛔ ${COLOR_RED}Error: ACCESS_LIST_ID is required.${CoR}"
        echo -e "    Usage: $0 --access-list-delete <access_list_id> [-y]"
        exit 1
    fi
    check_token_notverbose
    echo -e " 🔍 Checking access list ID: ${COLOR_YELLOW}$ACCESS_LIST_ID${CoR}"

    # Check if access list exists
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/access-lists/$ACCESS_LIST_ID" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    if [ "$(echo "$RESPONSE" | jq -r '.error.code')" = "404" ]; then
        echo -e " ⛔ ${COLOR_RED}Access list ID $ACCESS_LIST_ID not found${CoR}"
        exit 1
    fi

    # Show details before deletion
    echo -e " ┌───────────────────────────────────────────"
    echo -e " │ ID: ${COLOR_YELLOW}$ACCESS_LIST_ID${CoR}"
    echo -e " │ Name: ${COLOR_GREEN}$(echo "$RESPONSE" | jq -r '.name')${CoR}"
    echo -e " └───────────────────────────────────────────"

    # Confirm unless AUTO_YES
    if [ "$AUTO_YES" != true ]; then
        echo -e " ⚠️  ${COLOR_RED}WARNING: This action cannot be undone!${CoR}"
        read -n 1 -r -p " 🔔 Confirm deletion? (y/n): " CONFIRM
        echo
        if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
        echo -e " ❌ ${COLOR_RED}Operation cancelled${CoR}"
        exit 1
        fi
    fi


    # Delete access list
    RESPONSE=$(curl -s -X DELETE "$BASE_URL/nginx/access-lists/$ACCESS_LIST_ID" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    if [ "$RESPONSE" = "true" ]; then
        echo -e " ✅ ${COLOR_GREEN}Access list successfully deleted! ${CoR}🗑️ "
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete access list.${CoR}"
        if [ -n "$RESPONSE" ]; then
        echo -e "    Error: $RESPONSE"
        fi
        exit 1
    fi
}

################################
# Show all access lists with detailed information

################################
# Show all access lists with detailed information
access_list() {
    check_token_notverbose
    echo -e "\n📋 ${COLOR_CYAN}Access Lists Management${CoR}\n"

    # Get all access lists
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
        
    # Check for API errors
    if [ "$(echo "$RESPONSE" | jq -r 'if type=="object" then .error.message else empty end')" != "" ]; then
        echo -e " ⛔ ${COLOR_RED}Failed to fetch access lists${CoR}"
        echo -e "    Error: $(echo "$RESPONSE" | jq -r '.error.message')"
        return 1
    fi

    # Display table header
    echo "┌════════════════════════════════════════════════════════════════════════════════════┐"
    echo -e "│ ${COLOR_CYAN}ID  │ Name                   │ Authorization │ Access   │ Satisfy │ Proxy Hosts    ${CoR}│"
    echo "├════════════════════════════════════════════════════════════════════════════════════┤"

    # Process each access list and format output
    echo "$RESPONSE" | jq -r '.[] | "\(.id)|\(.name)|\(if .items then .items|length else 0 end) User\(if (.items|length//0) != 1 then "s" else "" end)|\(if .clients then .clients|length else 0 end) Rule\(if (.clients|length//0) != 1 then "s" else "" end)|\(.satisfy_any)|\(.proxy_host_count)"' | \
    while IFS="|" read -r id name users rules satisfy proxy_hosts; do
        # Format satisfy display (Any/All)
        satisfy_display=$([ "$satisfy" = "true" ] && echo "Any" || echo "All")

        # Print formatted line
        printf "│ %-3s │ %-22s │ %-13s │ %-8s │ %-7s │ %d Proxy Hosts  │\n" \
            "$id" \
            "$name" \
            "$users" \
            "$rules" \
            "$satisfy_display" \
            "$proxy_hosts"
    done

    # Close table
    echo "└════════════════════════════════════════════════════════════════════════════════════┘"

    # Display creation date info
    echo -e "\n${COLOR_CYAN}Note:${CoR} Use --access-list-show <id> to see detailed information about a specific access list\n"
}


################################
# Show detailed information for a specific access list
access_list_show() {
    local id="$1"
    check_token_notverbose

    if [ -z "$id" ]; then
        echo -e "\n⛔ ${COLOR_RED}Error: Access List ID is required${CoR}"
        echo -e "Usage: $0 --access-list-show <id>"
        return 1
    fi

    echo -e "\n📋 ${COLOR_CYAN}Access List Details${CoR}"
    
    # Get specific access list
    local response=$(curl -s -X GET "$BASE_URL/nginx/access-lists/$id" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

    # Check if response is valid JSON
    if ! echo "$response" | jq empty 2>/dev/null; then
        echo -e "\n⛔ ${COLOR_RED}Invalid response from API${CoR}"
        return 1
    fi

    # Check if access list exists
    if [ "$(echo "$response" | jq 'has("error")')" = "true" ]; then
        echo -e "\n⛔ ${COLOR_RED}Access List not found${CoR}"
        return 1
    fi

    # Create horizontal border
    local h_border=$(printf '%*s' "80" '' | tr ' ' "=")

    # Display basic information
    echo -e "\n${COLOR_GREY}┌$h_border┐${CoR}"
    echo -e "${COLOR_GREY}│${CoR} ${COLOR_CYAN}Basic Information${CoR}"
    echo -e "${COLOR_GREY}├$h_border┤${CoR}"
    echo -e "${COLOR_GREY}│${CoR} ID:         ${COLOR_GREEN}$(echo "$response" | jq -r '.id')${CoR}"
    echo -e "${COLOR_GREY}│${CoR} Name:       ${COLOR_YELLOW}$(echo "$response" | jq -r '.name')${CoR}"
    echo -e "${COLOR_GREY}│${CoR} Auth Type:  ${COLOR_ORANGE}$(echo "$response" | jq -r '.auth_type // "none"')${CoR}"
    
    # Display authentication settings
    local pass_auth=$(echo "$response" | jq -r '.pass_auth')
    local satisfy=$(echo "$response" | jq -r '.satisfy_any')
    echo -e "${COLOR_GREY}│${CoR} Pass Auth:  $([ "$pass_auth" = "true" ] && echo "${COLOR_GREEN}✓${CoR}" || echo "${COLOR_RED}✗${CoR}")"
    echo -e "${COLOR_GREY}│${CoR} Satisfy:    ${COLOR_YELLOW}$([ "$satisfy" = "true" ] && echo "Any" || echo "All")${CoR}"

    # Display users
    echo -e "${COLOR_GREY}├$h_border┤${CoR}"
    echo -e "${COLOR_GREY}│${CoR} ${COLOR_CYAN}Authorized Users${CoR}"
    echo -e "${COLOR_GREY}├$h_border┤${CoR}"
    if [ "$(echo "$response" | jq 'has("items")')" = "true" ] && [ "$(echo "$response" | jq '.items != null')" = "true" ]; then
        local users_count=$(echo "$response" | jq '.items | length')
        if [ "$users_count" -gt 0 ]; then
            echo "$response" | jq -r '.items[] | "│ • \(.username)"'
            else
                echo -e "${COLOR_GREY}│${CoR} No users configured"
            fi
        else
            echo -e "${COLOR_GREY}│${CoR} No users configured"
        fi
        
    # Display IP whitelist
    echo -e "${COLOR_GREY}├$h_border┤${CoR}"
    echo -e "${COLOR_GREY}│${CoR} ${COLOR_CYAN}IP Whitelist${CoR}"
    echo -e "${COLOR_GREY}├$h_border┤${CoR}"
    if [ "$(echo "$response" | jq 'has("clients")')" = "true" ] && [ "$(echo "$response" | jq '.clients != null')" = "true" ]; then
        local ips_count=$(echo "$response" | jq '.clients | length')
        if [ "$ips_count" -gt 0 ]; then
            echo "$response" | jq -r '.clients[] | "│ • \(.address) (\(.directive // "allow"))"' | \
            while IFS= read -r line; do
                if [[ $line == *"allow"* ]]; then
                    echo -e "${COLOR_GREY}│${CoR} • ${COLOR_GREEN}${line#* • }${CoR}"
                else
                    echo -e "${COLOR_GREY}│${CoR} • ${COLOR_RED}${line#* • }${CoR}"
                fi
            done
            else
                echo -e "${COLOR_GREY}│${CoR} No IPs whitelisted"
            fi
        else
            echo -e "${COLOR_GREY}│${CoR} No IPs whitelisted"
        fi

    # Close the box
    echo -e "${COLOR_GREY}└$h_border┘${CoR}"

    # Display legend
    echo -e "\n${COLOR_YELLOW}Legend:${CoR}"
    echo -e "  • Pass Auth: ${COLOR_GREEN}✓${CoR} = Enabled, ${COLOR_RED}✗${CoR} = Disabled"
    echo -e "  • IP Rules:  ${COLOR_GREEN}allow${CoR} = Allowed, ${COLOR_RED}deny${CoR} = Denied\n"
} 


################################
## backup
# Function to make a full backup

full_backup() {
    check_dependencies
    check_nginx_access
    check_token_notverbose
    DATE=$(date +"_%Y_%m_%d__%H_%M_%S")
    echo -e "\n📦 ${COLOR_YELLOW}Starting full backup...${CoR}"  
    # Initialize counters
    local users_count=0
    local certs_count=0
    local hosts_count=0
    local custom_certs_count=0
    local letsencrypt_certs_count=0
    local access_lists_count=0
    local success_count=0
    local error_count=0

    # Create main backup directory with timestamp
    BACKUP_PATH="$BACKUP_DIR"
    mkdir -p "$BACKUP_PATH"

    # Create required subdirectories
    echo -e "\n📂 ${COLOR_CYAN}Creating backup directories...${CoR}"
    for dir in ".user" ".settings" ".access_lists" ".Proxy_Hosts" ".ssl"; do
        mkdir -p "$BACKUP_PATH/$dir" || {
            echo -e " ⛔ ${COLOR_RED}Failed to create $dir directory${CoR}"
            return 1
        }
        echo -e " ✓ Created: ${COLOR_GREY}$BACKUP_PATH/$dir${CoR}"
    done

    # Initialize empty JSON for full configuration
    echo "{}" > "$BACKUP_PATH/full_config${DATE}.json"
    echo -e "\n🔄 ${COLOR_CYAN}Starting configuration backup...${CoR}"

    # 1. Backup Users
 #   trap 'echo "Error on line $LINENO"' ERR
 #   set -x  # Debug mode ON
    echo -e "\n👥 ${COLOR_CYAN}Backing up users...${CoR}"
    USERS_RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    
    if [ -n "$USERS_RESPONSE" ] && echo "$USERS_RESPONSE" | jq empty 2>/dev/null; then
        users_count=$(echo "$USERS_RESPONSE" | jq '. | length')
        # Save users to dedicated file
        echo "$USERS_RESPONSE" | jq '.' > "$BACKUP_PATH/.user/users_${NGINX_IP//./_}$DATE.json"
        # Add users to full configuration
        jq --argjson users "$USERS_RESPONSE" '. + {users: $users}' \
            "$BACKUP_PATH/full_config${DATE}.json" > "$BACKUP_PATH/full_config${DATE}.json.tmp"
        mv "$BACKUP_PATH/full_config${DATE}.json.tmp" "$BACKUP_PATH/full_config${DATE}.json"
        echo -e " ✅ ${COLOR_GREEN}Backed up $users_count users${CoR}"
        success_count=$((success_count + 1))
    else
        echo -e " ⚠️ ${COLOR_YELLOW}No users found or invalid response${CoR}"
        error_count=$((error_count + 1))
    fi
#    trap - ERR  # Reset trap
#    set +x  # Debug mode OFF


    # 2. Backup settings
    echo -e "\n⚙️  ${COLOR_CYAN}Backing up settings...${CoR}"
    SETTINGS_RESPONSE=$(curl -s -X GET "$BASE_URL/settings" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    #echo -e "\n🔍 DEBUG Settings Response: $SETTINGS_RESPONSE"  # Debug line
    if [ -n "$SETTINGS_RESPONSE" ] && echo "$SETTINGS_RESPONSE" | jq empty 2>/dev/null; then
        # Save settings to dedicated file
        echo "$SETTINGS_RESPONSE" | jq '.' > "$BACKUP_PATH/.settings/settings_${NGINX_IP//./_}$DATE.json"
        # Add settings to full configuration
        jq --argjson settings "$SETTINGS_RESPONSE" '. + {settings: $settings}' \
            "$BACKUP_PATH/full_config${DATE}.json" > "$BACKUP_PATH/full_config${DATE}.json.tmp"
        mv "$BACKUP_PATH/full_config${DATE}.json.tmp" "$BACKUP_PATH/full_config${DATE}.json"
        echo -e " ✅ ${COLOR_GREEN}Settings backed up successfully${CoR}"
        ((success_count++))
    else
        echo -e " ⚠️ ${COLOR_YELLOW}Invalid settings response${CoR}"
        ((error_count++))
    fi

    # 3. Backup access lists
    echo -e "\n🔑 ${COLOR_CYAN}Backing up access lists...${CoR}"
    ACCESS_LISTS_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    if [ -n "$ACCESS_LISTS_RESPONSE" ] && echo "$ACCESS_LISTS_RESPONSE" | jq empty 2>/dev/null; then
        access_lists_count=$(echo "$ACCESS_LISTS_RESPONSE" | jq '. | length')
        # Save access lists to dedicated file
        echo "$ACCESS_LISTS_RESPONSE" | jq '.' > "$BACKUP_PATH/.access_lists/access_lists_${NGINX_IP//./_}$DATE.json"
        # Add access lists to full configuration
        jq --argjson lists "$ACCESS_LISTS_RESPONSE" '. + {access_lists: $lists}' \
            "$BACKUP_PATH/full_config${DATE}.json" > "$BACKUP_PATH/full_config${DATE}.json.tmp"
        mv "$BACKUP_PATH/full_config${DATE}.json.tmp" "$BACKUP_PATH/full_config${DATE}.json"
        echo -e " ✅ ${COLOR_GREEN}Backed up $access_lists_count access lists${CoR}"
        ((success_count++))
    else
        echo -e " ⚠️ ${COLOR_YELLOW}No access lists found or invalid response${CoR}"
        ((error_count++))
    fi


    # 4. Backup proxy hosts
    echo -e "\n🌐 ${COLOR_CYAN}Backing up proxy hosts...${CoR}"
    ALL_HOSTS_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
    
    if [ -n "$ALL_HOSTS_RESPONSE" ] && echo "$ALL_HOSTS_RESPONSE" | jq empty 2>/dev/null; then
        hosts_count=$(echo "$ALL_HOSTS_RESPONSE" | jq '. | length')
        
        # Save all hosts metadata
        echo "$ALL_HOSTS_RESPONSE" | jq '.' > "$BACKUP_PATH/.Proxy_Hosts/all_hosts_${NGINX_IP//./_}$DATE.json"
        
        # Process each proxy host - Utiliser while read avec un pipe pour préserver les variables
        while IFS= read -r host; do
            local host_id=$(echo "$host" | jq -r '.id')
            local domain_name=$(echo "$host" | jq -r '.domain_names[0]' | sed 's/[^a-zA-Z0-9.]/_/g')
            local cert_id=$(echo "$host" | jq -r '.certificate_id')
            
            echo -e "\n 📥 Processing host: ${COLOR_GREEN}$domain_name${CoR} (ID: ${COLOR_YELLOW}$host_id${CoR})"
            
            # Create directory for this proxy host
            local PROXY_DIR="$BACKUP_PATH/.Proxy_Hosts/$domain_name"
            mkdir -p "$PROXY_DIR/ssl" "$PROXY_DIR/logs"
            
            # Save proxy host configuration
            echo "$host" | jq '.' > "$PROXY_DIR/proxy_config.json"

            # Get and save nginx configuration
            local NGINX_CONFIG
            NGINX_CONFIG=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id/nginx" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
            if [ -n "$NGINX_CONFIG" ]; then
                echo "$NGINX_CONFIG" > "$PROXY_DIR/nginx.conf"
            fi

            # Get and save logs if they exist
            curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id/access.log" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")" > "$PROXY_DIR/logs/access.log"
            curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id/error.log" \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")" > "$PROXY_DIR/logs/error.log"

            # Process SSL certificate if exists
            if [ -n "$cert_id" ] && [ "$cert_id" != "null" ] && [ "$cert_id" != "0" ]; then
                echo -e "   🔒 Downloading SSL certificate (ID: $cert_id)"
                
                # Get certificate metadata first
                local CERT_META
                CERT_META=$(curl -s -X GET "$BASE_URL/nginx/certificates/$cert_id" \
                -H "Authorization: Bearer $(cat "$TOKEN_FILE")")
                
                if [ -n "$CERT_META" ] && echo "$CERT_META" | jq empty 2>/dev/null; then
                    echo "$CERT_META" | jq '.' > "$PROXY_DIR/ssl/certificate_meta.json"
                    
                    # Get certificate content
                    local CERT_CONTENT
                    CERT_CONTENT=$(curl -s -X GET "$BASE_URL/nginx/certificates/$cert_id/certificates" \
                    -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
                    -H "Accept: application/json")
                    
                    if [ -n "$CERT_CONTENT" ] && echo "$CERT_CONTENT" | jq empty 2>/dev/null; then
                        # Save certificate files in proxy host directory
                        echo "$CERT_CONTENT" | jq -r '.certificate' > "$PROXY_DIR/ssl/certificate.pem"
                        echo "$CERT_CONTENT" | jq -r '.private' > "$PROXY_DIR/ssl/private.key"
                        chmod 600 "$PROXY_DIR/ssl/private.key"
                        
                        if echo "$CERT_CONTENT" | jq -r '.intermediate' > /dev/null 2>&1; then
                            echo "$CERT_CONTENT" | jq -r '.intermediate' > "$PROXY_DIR/ssl/chain.pem"
                        fi

                        # Create centralized SSL directory structure
                        local CERT_NAME
                        CERT_NAME=$(echo "$CERT_META" | jq -r '.nice_name // .domain_names[0]' | sed 's/[^a-zA-Z0-9.]/_/g')
                        local CENTRAL_SSL_DIR="$BACKUP_PATH/.ssl/$CERT_NAME"
                        mkdir -p "$CENTRAL_SSL_DIR"

                        # Save metadata and create symbolic links
                        echo "$CERT_META" | jq '.' > "$CENTRAL_SSL_DIR/certificate_meta.json"
                        ln -sf "$PROXY_DIR/ssl/certificate.pem" "$CENTRAL_SSL_DIR/certificate.pem"
                        ln -sf "$PROXY_DIR/ssl/private.key" "$CENTRAL_SSL_DIR/private.key"
                        [ -f "$PROXY_DIR/ssl/chain.pem" ] && ln -sf "$PROXY_DIR/ssl/chain.pem" "$CENTRAL_SSL_DIR/chain.pem"

                        # Add symlink to latest version
                        ln -sf "$CENTRAL_SSL_DIR" "$BACKUP_PATH/.ssl/${CERT_NAME}_latest"
                        
                        echo -e "   ✅ ${COLOR_GREEN}SSL certificate backed up successfully${CoR}"
                        ((success_count++))
                        
                        # Count certificate type - maintenant les compteurs fonctionneront
                        if echo "$CERT_META" | jq -e '.provider // empty | contains("letsencrypt")' >/dev/null 2>&1; then
                            letsencrypt_certs_count=$((letsencrypt_certs_count + 1))
                        else
                            custom_certs_count=$((custom_certs_count + 1))
                        fi
                        certs_count=$((certs_count + 1))
                        success_count=$((success_count + 1))
                    else
                        echo -e "   ⚠️ ${COLOR_YELLOW}Failed to download certificate content${CoR}"
                        ((error_count++))
                    fi
                else
                    echo -e "   ⚠️ ${COLOR_YELLOW}Failed to get certificate metadata${CoR}"
                    ((error_count++))
                fi
            fi

            echo -e " ✅ ${COLOR_GREEN}Host $domain_name backed up successfully${CoR}"
        done < <(echo "$ALL_HOSTS_RESPONSE" | jq -c '.[]')

        # Create latest symlink for hosts
        ln -sf "$BACKUP_PATH/.Proxy_Hosts/all_hosts_${NGINX_IP//./_}$DATE.json" \
            "$BACKUP_PATH/.Proxy_Hosts/all_hosts_latest.json"
        
        echo -e "\n ✅ ${COLOR_GREEN}Backed up $hosts_count proxy hosts${CoR}"
    else
        echo -e " ⚠️ ${COLOR_YELLOW}No proxy hosts found or invalid response${CoR}"
        ((error_count++))
    fi

    # Generate backup report and statistics
    echo -e "\n📊 ${COLOR_YELLOW}Backup Summary:${CoR}"
    echo -e " • ${COLOR_CYAN}Users:${CoR} $users_count"
    echo -e " • ${COLOR_CYAN}Proxy Hosts:${CoR} $hosts_count"
    echo -e " • ${COLOR_CYAN}SSL Certificates:${CoR} $certs_count"
    echo -e "   ├─ Custom: $custom_certs_count"
    echo -e "   └─ Let's Encrypt: $letsencrypt_certs_count"
    echo -e " • ${COLOR_CYAN}Access Lists:${CoR} $access_lists_count"
    echo -e " • ${COLOR_CYAN}Success/Error:${CoR} $success_count/$error_count"

    # Count backup files by type
    local total_files=$(find "$BACKUP_PATH" -type f \( \
        -name "*.json" -o \
        -name "*.conf" -o \
        -name "*.log" -o \
        -name "*.pem" -o \
        -name "*.key" \
    \) | wc -l)
    local config_files=$(find "$BACKUP_PATH" -maxdepth 1 -type f -name "full_config*.json" | wc -l)
    local proxy_files=$(find "$BACKUP_PATH/.Proxy_Hosts" -type f -name "proxy_config.json" | wc -l)
    local ssl_files=$(find "$BACKUP_PATH" -type f \( \
        -name "certificate*.json" -o \
        -name "*.pem" -o \
        -name "*.key" \
    \) | wc -l)
    local access_files=$(find "$BACKUP_PATH/.access_lists" -type f -name "*.json" | wc -l)
    local settings_files=$(find "$BACKUP_PATH/.settings" -type f -name "*.json" | wc -l)
    local user_files=$(find "$BACKUP_PATH/.user" -type f -name "*.json" | wc -l)

    echo -e "\n📁 ${COLOR_YELLOW}Backup Files Count:${CoR}"
    echo -e " • Full Configurations: ${COLOR_GREY}$config_files files${CoR}"
    echo -e " • Proxy Host Files: ${COLOR_GREY}$proxy_files files${CoR}"
    echo -e " • SSL Certificate Files: ${COLOR_GREY}$ssl_files files${CoR}"
    echo -e " • Access List Files: ${COLOR_GREY}$access_files files${CoR}"
    echo -e " • Settings Files: ${COLOR_GREY}$settings_files files${CoR}"
    echo -e " • User Files: ${COLOR_GREY}$user_files files${CoR}"
    echo -e " • ${COLOR_GREEN}Total Backup Files: ${COLOR_GREY}$total_files files${CoR}"

    # Display backup locations
    echo -e "\n📂 ${COLOR_YELLOW}Backup Locations:${CoR}"
    echo -e " • Full config: ${COLOR_GREY}$BACKUP_PATH/full_config${DATE}.json${CoR}"
    echo -e " • Latest symlink: ${COLOR_GREY}$BACKUP_PATH/full_config_latest.json${CoR}"
    echo -e " • Proxy configs: ${COLOR_GREY}$BACKUP_PATH/.Proxy_Hosts/${CoR}"
    echo -e " • Host list full: ${COLOR_GREY}$BACKUP_PATH/.Proxy_Hosts/all_hosts_latest.json${CoR}"

    # Calculate and display total backup size
    local backup_size=$(du -sh "$BACKUP_PATH" | cut -f1)
    echo -e "\n💾 ${COLOR_YELLOW}Backup Size:${CoR} ${COLOR_GREY}$backup_size${CoR}"

    # Create latest symlink for full configuration
    ln -sf "$BACKUP_PATH/full_config${DATE}.json" "$BACKUP_PATH/full_config_latest.json"

    # Check for any errors during backup
    if [ $error_count -gt 0 ]; then
        echo -e "\n⚠️  ${COLOR_YELLOW}Backup completed with $error_count errors${CoR}"
        echo -e "   Please check the logs above for details."
    else
        echo -e "\n✅ ${COLOR_GREEN}Backup completed successfully!${CoR}"
    fi

    echo -e "\n📝 ${COLOR_GREY}Backup completed at: $(date '+%Y-%m-%d %H:%M:%S')${CoR}\n"
    return $error_count
}


######################################
# Main menu logic
######################################
for arg in "$@"; do
    if [ "$arg" = "-y" ]; then
        AUTO_YES=true
        #echo "Debug global: Setting AUTO_YES=true"
        break
    fi
done

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -O) echo "todo" # WITHOUT output
            shift
            ;;
        -J) echo "todo" # JSON ouput
            shift
            ;;            
        -y) AUTO_YES=true; shift;;
        --help) SHOW_HELP=true; shift;;
        --examples) EXAMPLES=true; shift;;
        --info) INFO=true; shift;;
        --show-default) SHOW_DEFAULT=true; shift;;
        --check-token) CHECK_TOKEN=true; shift;;
        --backup) BACKUP=true; shift;;
        --backup-host)
            shift
            if [[ -n "$1" && "$1" != -* ]]; then
                HOST_ID="$1"
                shift
            fi
           BACKUP_HOST=true            
            ;;
        --backup-host-list) BACKUP_LIST=true; shift;;
        --restore-host)
            shift
            if [[ -n "$1" && "$1" != -* ]]; then
                DOMAIN="$1"
                shift
            else
                list_backups
                echo -n "Enter domain to restore: "
                read -r DOMAIN
            fi
            RESTORE_HOST=true            
            ;;
        --restore-backup) RESTORE_BACKUP=true; shift;;
        --clean-hosts)
            exit 1 # not use !            
            CLEAN_HOSTS=true
            shift
            if [[ -n "$1" && "$1" != -* ]]; then
                BACKUP_FILE="$1"
                shift
            else
                BACKUP_FILE="$DEFAULT_BACKUP_FILE"
            fi
            ;;
        --user-list) USER_LIST=true; shift;;
        --user-create)
            shift
            if [[ $# -lt 3 ]]; then
                echo -e "\n 👤 ${COLOR_RED}The --user-create option requires username, password, and email.${CoR}"
                echo -e " Usage: ${COLOR_ORANGE}$0 --user-create <username> <password> <email>${CoR}"
                echo -e " Example:"
                echo -e "   ${COLOR_GREEN}$0 --user-create john secretpass john@domain.com${CoR}\n"
                exit 1
            fi

            USERNAME="$1"
            PASSWORD="$2"
            EMAIL="$3"
            USER_CREATE=true
            shift 3
            ;;
        --user-delete)
            shift
            if [[ $# -eq 0 ]]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: The --user-delete option requires a user 🆔.${CoR}"
                echo -e " Usage: ${COLOR_ORANGE}$0 --user-delete <user_id>${CoR}"
                exit 1
            fi

            USER_ID="$1"
            USER_DELETE=true
            shift 
            ;;
        --host-show)
            shift
            if [[ $# -eq 0 ]]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: The --host-show option requires a host ${CoR}🆔"
                echo -e "    Usage  : ${COLOR_ORANGE}$0 --host-show <ID>${CoR}"            
                echo -e "    Example: $0 --host-show 42"
                echo -e "    Find ID: $0 --host-list\n"   
                exit 1
            fi
            host_id="$1"
            HOST_SHOW=true
            shift
            ;;
        --host-list) HOST_LIST=true; shift;;
        --host-list-full) HOST_LIST_FULL=true; shift;;
        --host-search)
            shift           
            HOST_SEARCHNAME="${1:-}"
            if [ -z "$HOST_SEARCHNAME" ]; then
              echo -e "\n ⛔ ${COLOR_RED}INVALID: The --host-search option requires a host name.${CoR}"
              echo -e "    Usage  : ${COLOR_ORANGE}$0 --host-search hostname${CoR}"
              echo -e "    Example: $0 --host-search domain.com ${COLOR_YELLOW}or${CoR} dom ${COLOR_YELLOW}or${CoR} .com"
              echo -e "    Find ID: $0 --host-list\n"                
              exit 1
            fi            
            HOST_SEARCH=true            
            shift           
            ;;
        --host-enable)
            shift
            if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: The --host-enable option requires a host${CoR} 🆔"
                echo -e "    Usage  : ${COLOR_ORANGE}$0 --host-enable <host_id>${CoR}"
                echo -e "    Example: $0 --host-enable 42"
                echo -e "    Find ID: $0 --host-list\n"                
                exit 1
            fi
            HOST_ID="$1"
            HOST_ENABLE=true            
            shift 
            ;;
        --host-disable)
            shift
            if [[ $# -eq 0 ]]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: The --host-disable option requires host${CoR} 🆔"
                echo -e "    Usage  : ${COLOR_GREEN}$0 --host-disable <host_id>${CoR}"
                echo -e "    Example: $0 --host-disable 42"
                echo -e "    Find ID: $0 --host-list\n"                 
                exit 1
            fi

            HOST_ID="$1"
            HOST_DISABLE=true
            shift
            ;;
        --host-delete)
            shift
            if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: The --host-delete option requires a host${CoR} 🆔"
                echo -e "   ${COLOR_CYAN}Usage:${CoR}"
                echo -e "   ${COLOR_ORANGE}$0 --host-delete <host_id> [-y]${CoR}"
                echo -e "   ${COLOR_CYAN}Examples:${CoR}"
                echo -e "   ${COLOR_GREEN}$0 --host-delete 42${CoR}"
                echo -e "   ${COLOR_GREEN}$0 --host-delete 42 -y${CoR} ${COLOR_GREY}# Skip confirmation${CoR}"
                echo -e "\n ${COLOR_YELLOW}💡 Tip: Use --host-list to see all available hosts and their IDs${CoR}"
                exit 1
            fi

            if [[ "$1" =~ ^[0-9]+$ ]]; then
                HOST_ID="$1"
                HOST_DELETE=true
                shift               
            else
                echo -e "\n ⛔ ${COLOR_RED}INVALID: Invalid host ID '$1' - must be a number${CoR}"
                echo -e "\n${COLOR_CYAN}Example:${CoR}"
                echo -e " ${COLOR_GREEN}$0 --host-delete 42${CoR}"
                echo -e "\n${COLOR_YELLOW}💡 Tip: Use --host-list to see all available hosts and their IDs${CoR}"
                exit 1
            fi
            ;;
        --host-update)
          if [[ "$#" -lt 3 ]]; then
              echo -e "\n ⛔ ${COLOR_RED}INVALID: L'option --host-update requiert un host 🆔 et une paire field=value.${CoR}"
              echo -e "    Usage  : ${COLOR_GREEN}$0 --host-update <host_id> <field=value>${CoR}"
              echo -e "    Find ID: $0 --host-list${CoR}\n"
              exit 1
          fi
          # Check if  $2  is a number
          if [[ "$2" =~ ^[0-9]+$ ]]; then
              HOST_ID="$2"
              FIELD_VALUE="$3"
              # On sépare FIELD et VALUE
              if [[ "$FIELD_VALUE" == *"="* ]]; then
                  FIELD=$(echo "$FIELD_VALUE" | cut -d '=' -f1)
                  VALUE=$(echo "$FIELD_VALUE" | cut -d '=' -f2-)
                  HOST_UPDATE=true
              else
                  echo -e "\n ⛔ ${COLOR_RED}INVALID: La paire field=value est incorrecte.${CoR}"
                  echo -e "   Exemple: $0 --host-update 42 forward_host=new.backend.local"
                  exit 1
              fi

              shift 3
              #host_update "$HOST_ID" "$FIELD" "$VALUE"
              #HOST_UPDATE=true
          else
              echo -e "\n ⛔ ${COLOR_RED}INVALID: L'option --host-update requiert un host 🆔 valide (numérique).${CoR}"
              exit 1
          fi
          ;;

        --host-create)
            HOST_CREATE=true
            shift
            # Check if there are any remaining arguments after shift
            if [ $# -eq 0 ]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: The --host-create option requires arguments${CoR}"
                echo -e "\n Required options:"
                echo -e "  • Domain name ${COLOR_GREY}(positional argument)${CoR}"
                echo -e "  • -i, --forward-host     ${COLOR_GREY}Forward host (e.g., 127.0.0.1)${CoR}"
                echo -e "  • -p, --forward-port     ${COLOR_GREY}Forward port (e.g., 8080)${CoR}"
                echo -e "\n Optional:"
                echo -e "  • -f, --forward-scheme   ${COLOR_GREY}Protocol (http/https, default: http)${CoR}"
                echo -e "  • -b, --block-exploits   ${COLOR_GREY}Block common exploits (true/false)${CoR}"
                echo -e "  • -c, --cache            ${COLOR_GREY}Enable caching (true/false)${CoR}"
                echo -e "  • -w, --websocket        ${COLOR_GREY}Allow websocket upgrade (true/false)${CoR}"
                echo -e "  • -h, --http2            ${COLOR_GREY}Enable HTTP/2 support (true/false)${CoR}"
                echo -e "  • -s, --ssl-force        ${COLOR_GREY}Force SSL (true/false)${CoR}"
                echo -e "\n Can be combined with:"
                echo -e "  • --cert-generate        ${COLOR_GREY}Generate SSL certificate${CoR}"
                echo -e "  • --host-ssl-enable      ${COLOR_GREY}Enable SSL after creation${CoR}"
                echo -e "  • -y                     ${COLOR_GREY}Skip all confirmations${CoR}"
                echo -e "\n Examples:"
                echo -e " ${COLOR_GREEN}$0 --host-create example.com -i 127.0.0.1 -p 8080${CoR}"
                echo -e " ${COLOR_GREEN}$0 --host-create example.com -i 127.0.0.1 -p 8080 --cert-generate --host-ssl-enable -y${CoR}\n"
                exit 1
            fi
            
            # Check if first argument is a valid domain (not starting with -)
            if [[ "$1" == -* ]]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: First argument after --host-create must be a domain name${CoR}"
                exit 1
            fi

            DOMAIN_NAMES="$1"
            shift

            # Process remaining options
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -i|--forward-host)
                        if [[ -n "$2" && "$2" != -* ]]; then
                            FORWARD_HOST="$2"
                            shift 2
                        else
                            echo -e "\n ⛔ ${COLOR_RED}INVALID: The --forward-host option requires a valid value${CoR}"
                            echo -e "\n Required options:"
                            echo -e "  • Domain name ${COLOR_GREY}(positional argument)${CoR}"
                            echo -e "  • -i, --forward-host     ${COLOR_GREY}Forward host (e.g., 127.0.0.1)${CoR}"
                            echo -e "  • -p, --forward-port     ${COLOR_GREY}Forward port (e.g., 8080)${CoR}"
                            echo -e "\n Optional:"
                            echo -e "  • -f, --forward-scheme   ${COLOR_GREY}Protocol (http/https, default: http)${CoR}"
                            echo -e "  • -b, --block-exploits   ${COLOR_GREY}Block common exploits (true/false, default: false)${CoR}"
                            echo -e "  • -c, --cache            ${COLOR_GREY}Enable caching (true/false, default: false)${CoR}"
                            echo -e "  • -w, --websocket        ${COLOR_GREY}Allow websocket upgrade (true/false, default: false)${CoR}"
                            echo -e "  • -h, --http2            ${COLOR_GREY}Enable HTTP/2 support (true/false, default: false)${CoR}"
                            echo -e "  • -s, --ssl-force        ${COLOR_GREY}Force SSL (true/false, default: false)${CoR}"
                            exit 1
                        fi
                        ;;
                    -p|--forward-port)
                        if [[ -n "$2" && "$2" != -* && "$2" =~ ^[0-9]+$ ]]; then
                            FORWARD_PORT="$2"
                            shift 2
                        else
                            echo -e "\n ⛔ ${COLOR_RED}INVALID: The --forward-port option requires a valid number${CoR}"
                            echo -e "\n Required options:"
                            echo -e "  • Domain name ${COLOR_GREY}(positional argument)${CoR}"
                            echo -e "  • -i, --forward-host     ${COLOR_GREY}Forward host (e.g., 127.0.0.1)${CoR}"
                            echo -e "  • -p, --forward-port     ${COLOR_GREY}Forward port (e.g., 8080)${CoR}"
                            exit 1
                        fi
                        ;;
                    -f|--forward-scheme)
                        if [[ -n "$2" && "$2" != -* && "$2" =~ ^(http|https)$ ]]; then
                            FORWARD_SCHEME="$2"
                            shift 2
                        else
                            echo -e "\n ⛔ ${COLOR_RED}INVALID: The --forward-scheme option must be 'http' or 'https'${CoR}"
                            exit 1
                        fi
                        ;;
                    -b|--block-exploits|-c|--cache|-w|--websocket|-h|--http2|-s|--ssl-force)
                        # Process boolean options
                        opt_name=${1#-?}
                        opt_name=${opt_name#--}
                        if [[ "$2" =~ ^(true|false)$ ]]; then
                            case "$opt_name" in
                                block-exploits) BLOCK_EXPLOITS="$2" ;;
                                cache) CACHE_ENABLED="$2" ;;
                                websocket) WEBSOCKET_SUPPORT="$2" ;;
                                http2) HTTP2_SUPPORT="$2" ;;
                                ssl-force) SSL_FORCED="$2" ;;
                            esac
                            shift 2
                        else
                            echo -e "\n ⛔ ${COLOR_RED}INVALID: The $1 option must be 'true' or 'false'${CoR}"
                            exit 1
                        fi
                        ;;
 
                      # Support for chaining commands
                    --cert-generate|--host-ssl-enable|-y|--cert-email|--dns-provider|--dns-credentials)
                        # Just store these flags, they'll be processed later
                        case "$1" in
                            --cert-generate)
                                CERT_GENERATE=true
                                shift
                                if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
                                    CERT_DOMAIN="$1"
                                    shift
                                else
                                    # Si pas d'argument spécifique pour --cert-generate, utiliser le domaine du host
                                    CERT_DOMAIN="$DOMAIN_NAMES"
                                fi
                                ;;
                            --cert-email) shift; CERT_EMAIL="$1"; shift ;;
                            --dns-provider) shift; CERT_DNS_PROVIDER="$1"; shift ;;
                            --dns-credentials) shift; CERT_DNS_CREDENTIALS="$1"; shift ;;
                            --host-ssl-enable) HOST_SSL_ENABLE=true; shift  ;;
                            -y) AUTO_YES=true; shift ;;
                        esac
                        ;;                                                      
                    *)
 
                        if [[ "$1" == -* ]]; then
                            echo -e "\n ⚠️ ${COLOR_YELLOW}WARNING: Unknown option ignored -> $1${CoR}"
                        fi
                        shift
                        ;;
                esac
            done
        
            # check settings
            if [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: Missing required parameters${CoR}"
                echo -e " Required options:"
                echo -e "    • Domain name: ${COLOR_GREEN}$DOMAIN_NAMES${CoR} ${COLOR_GREY}(provided)${CoR}"
                [ -z "$FORWARD_HOST" ] && echo -e "    • -i, --forward-host     ${COLOR_RED}Missing${CoR}"
                [ -z "$FORWARD_PORT" ] && echo -e "    • -p, --forward-port     ${COLOR_RED}Missing${CoR}"
                echo -e "\n Example:"
                echo -e "   ${COLOR_GREEN}$0 --host-create example.com -i 127.0.0.1 -p 8080${CoR}\n"
                exit 1
            fi

            # Create proxy host
            create_or_update_proxy_host "$DOMAIN_NAMES" "$FORWARD_HOST" "$FORWARD_PORT" \
                       "${FORWARD_SCHEME:-http}" "${BLOCK_EXPLOITS:-false}" "${CACHE_ENABLED:-false}" \
                       "${WEBSOCKET_SUPPORT:-false}" "${HTTP2_SUPPORT:-false}" "${SSL_FORCED:-false}"
        ;;
        --host-ssl-enable)
            shift
            if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
                echo -e "\n ⛔ ${COLOR_RED}The --host-ssl-enable option requires a host ID and certificate ID.${CoR}"
                echo -e "\n  ${COLOR_CYAN}Usage:${CoR}"
                echo -e "    ${COLOR_ORANGE}$0 --host-ssl-enable <host_id> <cert_id>${CoR}"
                echo -e "  ${COLOR_CYAN}Examples:${CoR}"
                echo -e "    ${COLOR_GREEN}$0 --host-ssl-enable 42 240${CoR}"
                echo -e "    ${COLOR_GREEN}$0 --host-ssl-enable 42 240 -y${CoR} ${COLOR_GREY}# Skip confirmation${CoR}"
                echo -e "  ${COLOR_YELLOW}💡 Tips:${CoR}"
                echo -e "    • Use ${COLOR_GREEN}--host-list${CoR} to see all available hosts"
                echo -e "    • Use ${COLOR_GREEN}--cert-list${CoR} to see all available certificates\n"
                exit 1
            fi

            if [[ "$1" =~ ^[0-9]+$ ]]; then
                HOST_ID="$1"
                shift
                # Check for mandatory cert_id
                if [ $# -gt 0 ] && [[ "$1" =~ ^[0-9]+$ ]]; then
                    CERT_ID="$1"
                    shift
                else
                    echo -e "\n ⛔ ${COLOR_RED}ERROR: Certificate ID is required${CoR}"
                    echo -e " ${COLOR_CYAN}Usage:${CoR} $0 --host-ssl-enable <host_id> <cert_id>"
                    echo -e " ${COLOR_YELLOW}💡 Use --cert-list to see all available certificates${CoR}\n"
                    exit 1
                fi
                HOST_SSL_ENABLE=true
            else
                echo -e "\n ⛔ ${COLOR_RED}ERROR: Invalid host ID '$1' - must be a number${CoR}"
                echo -e "    ${COLOR_CYAN}Usage:${CoR} $0 --host-ssl-enable <host_id> <cert_id>"
                echo -e "    ${COLOR_YELLOW}💡 Use --host-list to see all available hosts${CoR}\n"
                exit 1
            fi
            ;;
        --host-ssl-disable)
            HOST_SSL_DISABLE=true
            shift
            if [ $# -gt 0 ]; then
                HOST_ID="$1"
                shift
            else
                echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing argument${CoR}"
                echo -e "    Usage      : ${COLOR_ORANGE}$0 --host-ssl-disable <host_id>${CoR}"
                echo -e "    Find HostID: ${COLOR_GREEN}$0 --host-list${CoR}\n"
                exit 1
            fi
            ;;                    
        --host-acl-enable)
            HOST_ACL_ENABLE=true
            shift
            if [ $# -lt 2 ]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID: The --host-acl-enable option requires two arguments: host_id and access_list_id${CoR}"
                echo -e "    Usage  : ${COLOR_ORANGE}$0 --host-acl-enable <host_id> <access_list_id>${CoR}"
                echo -e "    Example: ${COLOR_GREEN}$0 --host-acl-enable 42 5${CoR}"
                echo -e "    Find ID: ${COLOR_ORANGE}$0 --host-list${CoR} AND ${COLOR_ORANGE}--access-list${CoR}\n"
                exit 1
            fi
            HOST_ID="$1"
            ACCESS_LIST_ID="$2"
            shift 2
            ;;
        --host-acl-disable)
            HOST_ACL_DISABLE=true
            shift
            if [ $# -gt 0 ]; then
                HOST_ID="$1"
                shift
            else
                echo -e "\n ⛔ ${COLOR_RED}The --host-acl-disable option requires a host ID.${CoR}"
                echo -e "    Usage: $0 --host-acl-disable <host_id>\n"
                exit 1
            fi
            #host_acl_disable "$HOST_ID"
            ;;
        --cert-generate)
            shift
            if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
                echo -e "\n 🛡️ ${COLOR_RED}The --cert-generate option requires a domain.${CoR}"
                echo -e "\n    ${COLOR_ORANGE}Usage: $0 --cert-generate domain [email] [dns-provider <provider>] [dns-credentials <json>]${CoR}"
                echo -e "\n    ${COLOR_YELLOW}Options${CoR}:"
                echo -e "      • --dns-provider <provider>     : DNS provider for wildcard certificates"
                echo -e "      • --dns-credentials <json>      : DNS credentials in JSON format"
                echo -e "      • --host-ssl-enable             : Enable SSL after certificate generation"
                echo -e "      • -y                            : Skip confirmations"
                echo -e "    ${COLOR_YELLOW}Note${CoR}:\n      • If email is not provided, default email ${COLOR_YELLOW}$DEFAULT_EMAIL${CoR} will be used"
                echo -e "      • For wildcard certificates (${COLOR_YELLOW}*.domain.com${CoR}), DNS challenge is required\n"
                echo -e "   Examples:"
                echo -e "     ${COLOR_GREEN}$0 --cert-generate example.com${CoR}"
                echo -e "     ${COLOR_GREEN}$0 --cert-generate example.com admin@example.com${CoR}"
                echo -e "     ${COLOR_GREEN}$0 --cert-generate *.example.com --dns-provider cloudflare --dns-credentials '{\"dns_cloudflare_email\":\"your@email.com\",\"dns_cloudflare_api_key\":\"your-api-key\"}'${CoR}\n"
                exit 1
            fi
            # Store domain
            CERT_DOMAIN="$1"
            CERT_DNS_PROVIDER=""
            CERT_DNS_CREDENTIALS=""
            HOST_SSL_ENABLE=false 
            shift
            # Check and store email
            if [ $# -gt 0 ] && [[ "$1" != -* ]]; then
                CERT_EMAIL="$1"
                shift
            else
                CERT_EMAIL="$DEFAULT_EMAIL"
            fi

            # Parse DNS options
            while [ $# -gt 0 ] && [[ "$1" == --* ]]; do
                case "$1" in
                    --dns-provider)
                        shift
                        if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
                            CERT_DNS_PROVIDER="$1"
                            shift
                        else
                            echo -e "\n ⛔ ${COLOR_RED}Missing DNS provider value${CoR}"
                            exit 1
                        fi
                        ;;
                    --dns-credentials)
                        shift
                        if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
                            CERT_DNS_CREDENTIALS="$1"
                            shift
                        else
                            echo -e "\n ⛔ ${COLOR_RED}Missing DNS credentials${CoR}"
                            exit 1
                        fi
                        ;;
                    --host-ssl-enable)
                        HOST_SSL_ENABLE=true
                        shift
                        ;;
                    *)
                        echo -e "\n ⚠️ ${COLOR_YELLOW}Unknown option: $1${CoR}"
                        shift
                        ;;
                esac
            done

            # Validate wildcard certificate requirements
            if [[ "$CERT_DOMAIN" == \** ]]; then
                if [ -z "$CERT_DNS_PROVIDER" ] || [ -z "$CERT_DNS_CREDENTIALS" ]; then
                    echo -e "\n ⛔ ${COLOR_RED}Wildcard certificates require DNS challenge. Please provide --dns-provider and --dns-credentials.${CoR}"
                    echo -e " Example: ${COLOR_GREEN}$0 --cert-generate *.example.com --dns-provider cloudflare --dns-credentials '{\"dns_cloudflare_email\":\"your@email.com\",\"dns_cloudflare_api_key\":\"your-api-key\"}'${CoR}\n"
                exit 1
                fi
            fi

            # Set flag after validating all arguments
            CERT_GENERATE=true
            ;;
        --cert-delete)
            shift
            if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
                echo -e "\n ⛔ ${COLOR_RED}The --cert-delete option requires a certificate ID.${CoR}"
                echo -e "\n   ${COLOR_CYAN}Usage:${CoR}"
                echo -e "    ${COLOR_ORANGE}$0 --cert-delete <cert_id> [-y]${CoR}"
                echo -e "\n   ${COLOR_CYAN}Examples:${CoR}"
                echo -e "    ${COLOR_GREEN}$0 --cert-delete 240${CoR}"
                echo -e "    ${COLOR_GREEN}$0 --cert-delete 240 -y${CoR} ${COLOR_GREY}# Skip confirmation${CoR}"
                echo -e "\n   ${COLOR_YELLOW}💡 Tips:${CoR}"
                echo -e "    • Use ${COLOR_GREEN}--cert-list${CoR} to see all certificates and their IDs\n"
                exit 1
            fi
            CERT_DELETE=true
            CERT_ID="$1"
            shift
            ;;
        --cert-show)
            shift
            search_term="${1:-}"
            CERT_SHOW=true
            if [ -n "$search_term" ]; then
                shift
            fi
            ;;
        --cert-list) LIST_CERT_ALL=true; shift;;
        --access-list) ACCESS_LIST=true; shift;;
        --access-list-show)
            ACCESS_LIST_SHOW=true
            shift
            ACCESS_LIST_ID="$1"
            shift
            ;;      
        --access-list-create)
            shift
            if access_list_create "$@"; then
                exit 0
            else
                exit 1
            fi
            ;;
        --access-list-update) ACCESS_LIST_UPDATE=true; shift ;;      
        --access-list-delete)        
            shift
            if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
                echo -e "\n ⛔ ${COLOR_RED}The --access-list-delete option requires an access list ID.${CoR}"
                echo -e "   ${COLOR_CYAN}Usage:${CoR}"
                echo -e "    ${COLOR_ORANGE}$0 --access-list-delete <access_list_id> [-y]${CoR}"
                echo -e "   ${COLOR_CYAN}Examples:${CoR}"
                echo -e "    ${COLOR_GREEN}$0 --access-list-delete 42${CoR}"
                echo -e "    ${COLOR_GREEN}$0 --access-list-delete 42 -y${CoR} ${COLOR_GREY}# Skip confirmation${CoR}"
                echo -e "   ${COLOR_YELLOW}💡 Tip: Use --access-list to see all available access lists${CoR}"
                exit 1
            fi

            if [[ "$1" =~ ^[0-9]+$ ]]; then
                ACCESS_LIST_ID="$1"
            ACCESS_LIST_DELETE=true
                shift
            else
                echo -e "\n ⛔ ${COLOR_RED}INVALID: Invalid access list ID '$1' - must be a number${CoR}"
                echo -e "  ${COLOR_CYAN}Examples:${CoR}"
                echo -e "   ${COLOR_GREEN}$0 --access-list-delete 42${CoR}"
                echo -e "   ${COLOR_GREEN}$0 --access-list-delete 42 -y${CoR} ${COLOR_GREY}# Skip confirmation${CoR}"
                echo -e "  ${COLOR_YELLOW}💡 Tip: Use --access-list to see all available access lists${CoR}"
                exit 1
            fi
            ;;
        *)
            echo -e "\n ${COLOR_RED}⛔ Unknown option:${CoR} $1"
            echo -e "    ${COLOR_GREY}Use --help to see available commands.${CoR}\n"            
            exit 1
            ;;
    esac
    #shift
done

##############################################################
# logic 
##############################################################
#echo "Debug after case: ACCESS_LIST_DELETE=$ACCESS_LIST_DELETE ACCESS_LIST_ID=$ACCESS_LIST_ID AUTO_YES=$AUTO_YES"   


if [ "$SHOW_HELP" = true ]; then
  show_help
elif [ "$SHOW_DEFAULT" = true ]; then
  show_default
elif [ "$EXAMPLES" = true ]; then
  examples_cli
elif [ "$CHECK_TOKEN" = true ]; then
    check_token true
# Actions users
elif [ "$USER_CREATE" = true ]; then
  user_create "$USERNAME" "$PASSWORD" "$EMAIL"
elif [ "$USER_DELETE" = true ]; then
  user_delete "$USER_ID"
elif [ "$USER_LIST" = true ]; then
  user_list



elif [ "$CERT_DELETE" = true ]; then
    cert_delete "$CERT_ID"
elif [ "$CERT_SHOW" = true ]; then
    cert_show "$search_term"
elif [ "$LIST_CERT_ALL" = true ]; then
    list_cert_all

elif [ "$ACCESS_LIST" = true ]; then
   access_list
elif [ "$ACCESS_LIST_CREATE" = true ]; then
   access_list_create   
elif [ "$ACCESS_LIST_UPDATE" = true ]; then
   access_list_update
elif [ "$ACCESS_LIST_DELETE" = true ]; then
   access_list_delete      
elif [ "$ACCESS_LIST_SHOW" = true ]; then
    access_list_show   "$ACCESS_LIST_ID"  

# Actions hotes
elif [ "$HOST_LIST" = true ]; then
  host_list
elif [ "$HOST_LIST_FULL" = true ]; then
  host_list_full
elif [ "$HOST_SEARCH" = true ]; then
  host_search
elif [ "$HOST_SHOW" = true ]; then
  host_show "$HOST_ID"

elif [ "$HOST_CREATE" = true ]; then
    create_or_update_proxy_host "$DOMAIN_NAMES" "$FORWARD_HOST" "$FORWARD_PORT"
    # Set CERT_DOMAIN if cert generation is requested
    if [ "$CERT_GENERATE" = true ]; then
        cert_generate "$DOMAIN_NAMES" "$CERT_EMAIL" "$CERT_DNS_PROVIDER" "$CERT_DNS_CREDENTIALS"
        if [ "$HOST_SSL_ENABLE" = true ]; then
            echo "DEBUG: HOST_ID=$HOST_ID"
            echo "DEBUG: GENERATED_CERT_ID=$GENERATED_CERT_ID"
            host_ssl_enable "$HOST_ID" "$GENERATED_CERT_ID" 
        fi
    fi
    exit 0 

# Actions SSL
elif [ "$CERT_GENERATE" = true ] && [ "$HOST_CREATE" != true ]; then  # ✅ Ajout de la condition
    cert_generate "$CERT_DOMAIN" "$CERT_EMAIL" "$CERT_DNS_PROVIDER" "$CERT_DNS_CREDENTIALS"
    if [ "$HOST_SSL_ENABLE" = true ]; then
        host_ssl_enable "$HOST_ID"
        exit 0 
    fi

#elif [ "$CERT_GENERATE" = true ]; then
#    cert_generate "$CERT_DOMAIN" "$CERT_EMAIL" "$CERT_DNS_PROVIDER" "$CERT_DNS_CREDENTIALS"
    #  If --host-ssl-enable
#    if [ "$HOST_SSL_ENABLE" = true ]; then
#        host_ssl_enable "$HOST_ID"
#        exit 0 
#    fi


elif [ "$HOST_DELETE" = true ]; then
  host_delete "$HOST_ID"
elif [ "$HOST_ENABLE" = true ]; then
  host_enable "$HOST_ID"
elif [ "$HOST_DISABLE" = true ]; then
  host_disable "$HOST_ID"

elif [ "$HOST_UPDATE" = true ]; then
    host_update "$HOST_ID" "$FIELD" "$VALUE"
    exit 0

# Actions ACL
elif [ "$HOST_ACL_ENABLE" = true ]; then
  host_acl_enable
elif [ "$HOST_ACL_DISABLE" = true ]; then
  host_acl_disable


elif [ "$HOST_SSL_ENABLE" = true ]; then
    host_ssl_enable "$HOST_ID" "$CERT_ID"
elif [ "$HOST_SSL_DISABLE" = true ]; then
    host_ssl_disable
elif [ "$SSL_RESTORE" = true ]; then
  restore_ssl_certificates

# Actions backup/restore
elif [ "$BACKUP" = true ]; then
  full_backup
elif [ "$BACKUP_HOST" = true ]; then
  backup_host
elif [ "$BACKUP_LIST" = true ]; then
  list_backups

# restore all configurations or specific domain or certificates only
elif [ "$RESTORE_BACKUP" = true ]; then
  restore_backup
elif [ "$RESTORE_HOST" = true ]; then
  restore_host
elif [ "$CLEAN_HOSTS" = true ]; then
   clean-hosts
   #reimport_hosts "$@"
   #reimport_hosts "$BACKUP_FILE"
   #exit $?
   #check_validity_of_backup_file "$BACKUP_FILE"

else
  display_info
  exit 0 
    #
    # echo -e "\n ⛔ ${COLOR_RED}No valid option provided${CoR}"
    # echo -e " Use --help to see available commands."
    # exit 1
fi


