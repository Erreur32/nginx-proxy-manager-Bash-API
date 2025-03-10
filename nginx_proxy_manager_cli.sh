#!/bin/bash

# Nginx Proxy Manager CLI Script
#   Github [ https://github.com/Erreur32/nginx-proxy-manager-Bash-API ]
#   By Erreur32 - July 2024
#   NPM api https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema

VERSION="2.8.0"
# Debug
set -u 
#set -x  # Activer le mode de débogage
#set -eu -o pipefail

#################################
# This script allows you to manage Nginx Proxy Manager via the API. It provides
# functionalities such as creating proxy hosts, managing users, listing hosts,
# backing up configurations, and more.
#
# TIPS: Create manually a Config file for persistent variables 'nginx_proxy_manager_cli.conf' :
#       With these variables:
#          NGINX_IP="127.0.0.1"
#          API_USER="admin@example.com"
#          API_PASS="changeme"
#          BASE_DIR="/path/nginx_proxy_script/data"
#
################################
# Common Examples
# 
#
# 1. Create a new proxy host:
#    ./nginx_proxy_manager_cli.sh --host-create example.com -i 192.168.1.10 -p 8080
#
# 2. Enable SSL for a host:
#    ./nginx_proxy_manager_cli.sh --host-ssl-enable 1
#
# 3. Create a new user:
#    ./nginx_proxy_manager_cli.sh --create-user admin admin@example.com password123
#
# 4. List all proxy hosts:
#    ./nginx_proxy_manager_cli.sh --host-list
#
# 5. Generate SSL certificate:
#    ./nginx_proxy_manager_cli.sh --generate-cert *.example.com admin@example.com
#
# 6. Show host details:
#    ./nginx_proxy_manager_cli.sh --host-show 1
#

################################
# Variables to Edit (required) #
#   or create a config file    #
################################

# Check if config file nginx_proxy_manager_cli.conf exist
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/nginx_proxy_manager_cli.conf"

# set default variables
DEFAULT_NGINX_IP="127.0.0.1"
DEFAULT_NGINX_PORT="81"
DEFAULT_API_USER="user@nginx"
DEFAULT_API_PASS="pass nginx"
DEFAULT_BASE_DIR="$SCRIPT_DIR/data"

# Colors Custom
COLOR_GREEN="\033[32m"
COLOR_RED="\033[91m"
COLOR_RED_FULL="\033[41;1m"
COLOR_ORANGE="\033[38;5;202m"
COLOR_YELLOW="\033[93m"
COLOR_CYAN="\033[36m"
CoR="\033[0m"
COLOR_GREY="\e[90m"
WHITE_ON_GREEN="\033[30;48;5;83m"

# load config file if exists
if [ -f "$CONFIG_FILE" ]; then
  # First set default values
  NGINX_IP="$DEFAULT_NGINX_IP"
  NGINX_PORT="$DEFAULT_NGINX_PORT"
  API_USER="$DEFAULT_API_USER"
  API_PASS="$DEFAULT_API_PASS"
  BASE_DIR="$DEFAULT_BASE_DIR"
  # Then load config file which will override defaults
  source "$CONFIG_FILE"
  # Finally set variables as read only
  declare -r NGINX_IP
  declare -r NGINX_PORT
  declare -r API_USER
  declare -r API_PASS
  declare -r BASE_DIR
else
  # Use default values
  NGINX_IP="$DEFAULT_NGINX_IP"
  NGINX_PORT="$DEFAULT_NGINX_PORT"
  API_USER="$DEFAULT_API_USER"
  API_PASS="$DEFAULT_API_PASS"
  BASE_DIR="$DEFAULT_BASE_DIR"

  # Check if using default API user
  if [ "$API_USER" = "$DEFAULT_API_USER" ]; then
    echo -e "\n⚠️ ${COLOR_RED}Using default API credentials - Please configure the script!${CoR}"
    echo -e "\n📝 Create configuration file: $CONFIG_FILE with content:"
    echo -e "${COLOR_GREY}NGINX_IP=\"$NGINX_IP\"${CoR}     ${COLOR_YELLOW}(current default)${CoR}"
    echo -e "${COLOR_GREY}NGINX_PORT=\"$NGINX_PORT\"${CoR}  ${COLOR_YELLOW}(current default)${CoR}"
    echo -e "${COLOR_RED}API_USER=\"admin@example.com\"${CoR}  ${COLOR_RED}(required)${CoR}"
    echo -e "${COLOR_RED}API_PASS=\"your_password\"${CoR}     ${COLOR_RED}(required)${CoR}"
    echo -e "${COLOR_GREY}BASE_DIR=\"$BASE_DIR\"${CoR}    ${COLOR_YELLOW}(current default)${CoR}"
    echo -e "\n❌ ${COLOR_RED}Cannot continue with default API credentials${CoR}\n"
    exit 1
  fi
fi
################################
# PERSISTENT Config
# Create config file  $SCRIPT_DIR/nginx_proxy_manager_cli.conf and Edit Variables (required)
# NGINX_IP="127.0.0.1"
# NGINX_PORT="81"
# API_USER="admin@example.com"
# API_PASS="changeme"
# BASE_DIR="/path/nginx_proxy_script/dir"
################################

# API Endpoints
BASE_URL="http://$NGINX_IP:$NGINX_PORT/api"
TOKEN_API_ENDPOINT="/tokens"
# Directory will be create automatically.
TOKEN_DIR="$BASE_DIR/token"
if [ ! -d "$TOKEN_DIR" ]; then
  mkdir -p "$TOKEN_DIR"
fi

BACKUP_DIR="$BASE_DIR/backups/${NGINX_IP}_${NGINX_PORT}"
TOKEN_FILE="$TOKEN_DIR/token_${NGINX_IP}_${NGINX_PORT}.txt"
EXPIRY_FILE="$TOKEN_DIR/expiry_${NGINX_IP}_${NGINX_PORT}.txt"

if [ -f "$TOKEN_FILE" ]; then
  token=$(get_token)
else
  #echo -e "  Create $TOKEN_DIR"
  mkdir -p "$TOKEN_DIR"
  CHECK_TOKEN=true
fi

if [ -f "$EXPIRY_FILE" ]; then
  expires=$(cat "$EXPIRY_FILE")
else
  #echo -e "  Create $EXPIRY_FILE"
  touch "$EXPIRY_FILE"
  CHECK_TOKEN=true
fi

# Set Token duration validity.
#TOKEN_EXPIRY="365d"
#TOKEN_EXPIRY="31536000s"
TOKEN_EXPIRY="1y"

# Default backup file 
DEFAULT_BACKUP_FILE="$BACKUP_DIR/.Proxy_Hosts/all_hosts_latest.json"
#NGINX_PATH_DOCKER="/home/docker/nginx_proxy/nginx"
# Default configuration
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
# host variable gestion
DOMAIN=""
DOMAIN_NAMES=""
FORWARD_HOST=""
FORWARD_PORT=""
CUSTOM_LOCATIONS=""
HOST_ID=""
HOST_SEARCHNAME=""

# User variables gestion
DEFAULT_EMAIL="$API_USER"
USERNAME=""
PASSWORD=""
EMAIL=""

# Update variables gestion
FIELD=""
VALUE=""
FIELD_VALUE=""
ACCESS_LIST_ID=""

# Host variables gestion
HOST_SHOW=false
HOSTS_LIST=false
HOSTS_LIST_FULL=false
HOST_SEARCH=false
HOST_UPDATE=false
HOST_ENABLE=false
HOST_DISABLE=false
HOST_DELETE=false

# SSL variables gestion
LIST_SSL_CERT=false
GENERATE_CERT=false
DELETE_CERT=false
SSL_REGENERATE=false
SSL_RESTORE=false
ENABLE_SSL=false
DISABLE_SSL=false
# User variables gestion
LIST_USERS=false
CREATE_USER=false
DELETE_USER=false
# ACL variables gestion
HOST_ACL_ENABLE=false
HOST_ACL_DISABLE=false
ACCESS_LIST=false
# Backup   variables gestion
BACKUP=false
BACKUP_LIST=false
BACKUP_HOST=false
RESTORE_HOST=false
RESTORE_BACKUP=false
CLEAN_HOSTS=false
# General variables gestion
AUTO_YES=false
CHECK_TOKEN=false
EXAMPLES=false
INFO=false
SHOW_DEFAULT=false
# API response variables gestion
RESPONSE=""
HTTP_RESPONSE=""
HTTP_BODY=""
HTTP_STATUS=""
ERROR_MSG=""
PROXY_ID=""

###############################################
# Check if necessary dependencies are installed
check_dependencies() {
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
  # Check if directories exist and create them if they don't
  for dir in "$BASE_DIR" "$TOKEN_DIR" "$BACKUP_DIR"; do
    if [ ! -d "$dir" ]; then
      echo -e "  📢 ${COLOR_YELLOW}Creating directory: $dir${CoR}"
      mkdir -p "$dir"
      if ! mkdir -p "$dir"; then
        echo -e "\n  ${COLOR_RED}Error: Failed to create directory $dir${CoR}"
        exit 1
      fi
    fi
  done
}
check_dependencies

# Check if the Nginx Proxy Manager API is accessible
check_nginx_access() {
    local max_retries=3
    local retry_count=0
    local timeout=5
    #echo -e "\n🔍 Checking NPM availability..."
    #echo -e " • Attempting to connect to: ${COLOR_YELLOW}$BASE_URL${CoR}"
    echo -e "\n ✅ Loading variables from file $CONFIG_FILE"
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

# !!! Filter only directory name !
# Function to list available backups
list_backups() {
  echo "Available backups:"
  for domain in "$BACKUP_DIR/.Proxy_Hosts"/*/; do
    domain_name=${domain%/}
    domain_name=${domain_name##*/}
    echo "  - ${domain_name//_/.}"
  done
}

################################
# Display help
help() {
  echo -e "\n Options available:\n ${COLOR_GREY}(see -examples for more details)${CoR}" 
  echo -e "  -y                                      Automatic ${COLOR_YELLOW}yes${CoR} prompts!"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "  --info                                  Display ${COLOR_GREY}Script Variables Information${CoR}"
  echo -e "  --show-default                          Show  ${COLOR_GREY}Default settings for host creation${CoR}"
  echo -e "  --check-token                           Check ${COLOR_GREY}Check current token info${CoR}"
  echo -e "  --host-search ${COLOR_GREY}hostname${CoR}                  Search ${COLOR_GREY}Proxy host by ${COLOR_YELLOW}hostname${CoR}"
  echo -e "  --backup                                ${COLOR_GREEN}💾 ${CoR}Backup ${COLOR_GREY}All configurations to a different files in \$BACKUP_DIR${CoR}"
  #echo -e "  --clean-hosts                          ${COLOR_GREEN}📥 ${CoR}Reimport${CoR} ${COLOR_GREY}Clean Proxy ID and SSL ID in sqlite database ;)${CoR}"
  #echo -e "  --backup-host                          📦 ${COLOR_GREEN}Backup${CoR}   All proxy hosts and SSL certificates in Single file"
  #echo -e "  --backup-host 5                        📦 ${COLOR_GREEN}Backup${CoR}   Proxy host ID 5 and its SSL certificate"
  #echo -e "  --host-list-full > backup.txt          💾 ${COLOR_YELLOW}Export${CoR}   Full host configuration to file"
  #echo -e "  --restore                              📦 ${COLOR_GREEN}Restore${CoR} All configurations from a backup file"
  #echo -e "  --restore-host id                      📦 ${COLOR_GREEN}Restore${CoR} Restore single host with list with empty arguments or a Domain name"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "Proxy Host Management:" 
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"   
  echo -e "  --host-search ${COLOR_GREY}domain${CoR}                    Search ${COLOR_GREY}Proxy host by ${COLOR_YELLOW}domain name${CoR}"
  echo -e "  --host-list                             List ${COLOR_GREY}All Proxy hosts (to find ID)${CoR}"
  #echo -e "  --host-list-full                       📜 List ${COLOR_GREY}All Proxy hosts full details (JSON)${CoR}"
  echo -e "  --host-show ${COLOR_GREY}ID${CoR}                          Show ${COLOR_GREY}Full details for a specific host by ${COLOR_YELLOW}ID${CoR}"
  echo ""  
  echo -e "  --host-create ${COLOR_GREY}domain${CoR} -i ${COLOR_GREY}forward_host${CoR} -p ${COLOR_GREY}forward_port${CoR}" 
  echo -e "     ${COLOR_ORANGE}DOMAIN_NAMES${CoR}                         Domain name (${COLOR_RED}required${CoR})"
  echo -e "     -i ${COLOR_ORANGE}FORWARD_HOST${CoR}                      IP address or domain name of the target server (${COLOR_RED}required${CoR})"
  echo -e "     -p ${COLOR_ORANGE}FORWARD_PORT${CoR}                      Port of the target server (${COLOR_RED}required${CoR})\n"

  echo -e "     optional: ${COLOR_GREY}(Check default settings,no argument needed if already set!)${CoR}"  
  echo -e "     -f ${COLOR_GREY}FORWARD_SCHEME${CoR}                    Scheme for forwarding (http/https, default: $(colorize_booleanh "$FORWARD_SCHEME"))"
  echo -e "     -c ${COLOR_GREY}CACHING_ENABLED${CoR}                   Enable caching (true/false, default: $(colorize_boolean "$CACHING_ENABLED"))"
  echo -e "     -b ${COLOR_GREY}BLOCK_EXPLOITS${CoR}                    Block exploits (true/false, default: $(colorize_boolean "$BLOCK_EXPLOITS"))"
  echo -e "     -w ${COLOR_GREY}ALLOW_WEBSOCKET_UPGRADE${CoR}           Allow WebSocket upgrade (true/false, default: $(colorize_boolean "$ALLOW_WEBSOCKET_UPGRADE"))"
  echo -e "     -l ${COLOR_GREY}CUSTOM_LOCATIONS${CoR}                  Custom locations (${COLOR_YELLOW}JSON array${CoR} of location objects)"
  echo -e "     -a ${COLOR_GREY}ADVANCED_CONFIG${CoR}                   Advanced configuration (${COLOR_YELLOW}string${CoR})"
  echo ""

  echo -e "  --host-enable ${COLOR_GREY}ID${CoR}                        Enable Proxy ${COLOR_GREY}host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-disable ${COLOR_GREY}ID${CoR}                       Disable Proxy ${COLOR_GREY}host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-delete ${COLOR_GREY}ID${CoR}                        Delete ${COLOR_GREY}Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-update ${COLOR_GREY}ID${CoR} ${COLOR_GREY}field=value${CoR}            Update ${COLOR_GREY}One specific field of an existing proxy host by ${COLOR_YELLOW}ID${CoR} (e.g., --host-update 42 forward_host=foobar.local)${CoR}"
  echo ""

  echo -e "  --host-acl-enable ${COLOR_GREY}ID${CoR},${COLOR_GREY}access_list_id${CoR}     Enable ACL ${COLOR_GREY}for Proxy host by ${COLOR_YELLOW}ID${CoR} with ${COLOR_GREY}Access List ID ${CoR}(e.g., --host-acl-enable 16,2)"
  echo -e "  --host-acl-disable ${COLOR_GREY}ID${CoR}                   Disable ACL ${COLOR_GREY}for Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-ssl-enable ${COLOR_GREY}ID${CoR} ${COLOR_GREY}[cert_id]${CoR}          Enable SSL for host ID ${COLOR_GREY}optionally using ${CoR}specific certificate ID"
  echo -e "  --host-ssl-disable ${COLOR_GREY}ID${CoR}                   Disable SSL${COLOR_GREY}, HTTP/2, and HSTS for a proxy host${CoR}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "  --list-ssl-cert ${COLOR_GREY}[domain]${CoR}                List ${COLOR_GREY}All ${CoR}SSL ${COLOR_GREY}certificates availables or filtered by [domain name]  (JSON)${CoR}"  
  echo -e "  --generate-cert ${COLOR_GREY}domain${CoR} ${COLOR_GREY}[email]${CoR}          Generate ${COLOR_GREY}Let's Encrypt Certificate${CoR}"
  echo -e "                                           • ${COLOR_GREY}Standard domains:${CoR} example.com, sub.example.com"
  echo -e "                                           • ${COLOR_GREY}Wildcard domains:${CoR} *.example.com ${COLOR_GREY}(requires DNS challenge)${CoR}"
  echo -e "                                           • ${COLOR_GREY}DNS Challenge:${CoR} Required for wildcard certificates"
  echo -e "                                            - ${COLOR_GREY}Format:${CoR} dns-provider PROVIDER dns-api-key KEY"
  echo -e "                                            - ${COLOR_GREY}Providers:${CoR} dynu, cloudflare, digitalocean, godaddy, namecheap, route53, ovh, gcloud"
  echo -e "  --delete-cert ${COLOR_GREY}domain${CoR}                    Delete ${COLOR_GREY}Certificate for the given '${COLOR_YELLOW}domain${CoR}'"
 echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "  --list-users                            List ${COLOR_GREY}All Users${CoR}"
  echo -e "  --create-user ${COLOR_GREY}username${CoR} ${COLOR_GREY}password${CoR} ${COLOR_GREY}email${CoR}   Create ${COLOR_GREY}User with a ${COLOR_YELLOW}username${CoR}, ${COLOR_YELLOW}password${CoR} and ${COLOR_YELLOW}email${CoR}"
  echo -e "  --delete-user ${COLOR_GREY}ID${CoR}                        Delete ${COLOR_GREY}User by ${COLOR_YELLOW}username${CoR}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" 
  echo -e "  --access-list                           List ${COLOR_GREY}All available Access Lists (ID and Name)${CoR}"
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
    # Commandes de base
    echo -e "\n${COLOR_GREEN}📋 Basic Commands:${CoR}"
    echo -e "${COLOR_GREY}  # List all proxy hosts${CoR}"
    echo -e "  $0 --host-list"
    echo -e "${COLOR_GREY}  # Search hosts by domain${CoR}"
    echo -e "  $0 --host-search example.com"
    echo -e "${COLOR_GREY}  # Show detailed information for host ID 42${CoR}"
    echo -e "  $0 --host-show 42"

    echo -e "\n${COLOR_GREEN}🌐 Host Management:${CoR}"
    echo -e "${COLOR_GREY}  # Create basic proxy host${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080"
    echo -e "${COLOR_GREY}  # Create host with SSL (auto-generates certificate)${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080 --generate-cert example.com admin@example.com"
    echo -e "${COLOR_GREY}  # Create host with custom location${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080 -l '[{\"path\":\"/api\",\"forward_host\":\"api.local\",\"forward_port\":3000}]'"
    echo -e "${COLOR_GREY}  # Update host configuration${CoR}"
    echo -e "  $0 --host-update 42 forward_host=new.example.com"
    echo -e "${COLOR_GREY}  # Enable/Disable host${CoR}"
    echo -e "  $0 --host-enable 42"
    echo -e "  $0 --host-disable 42"

    echo -e "\n${COLOR_GREEN}🔒 SSL Certificate Management:${CoR}"
    echo -e "${COLOR_GREY}  # List all certificates${CoR}"
    echo -e "  $0 --list-ssl-cert"
    echo -e "${COLOR_GREY}  # List certificates for specific domain${CoR}"
    echo -e "  $0 --list-ssl-cert example.com"
    echo -e "${COLOR_GREY}  # Generate standard certificate${CoR}"
    echo -e "  $0 --generate-cert example.com admin@example.com"
    echo -e "${COLOR_GREY}  # Generate wildcard certificate with DNS challenge${CoR}"
    echo -e "  $0 --generate-cert *.example.com admin@example.com dns-provider cloudflare dns-api-key CF_API_KEY"
    echo -e "${COLOR_GREY}  # Enable SSL with auto certificate selection${CoR}"
    echo -e "  $0 --host-ssl-enable 42"
    echo -e "${COLOR_GREY}  # Enable SSL with specific certificate${CoR}"
    echo -e "  $0 --host-ssl-enable 42 123"

    echo -e "\n${COLOR_GREEN}🔑 Access Control:${CoR}"
    echo -e "${COLOR_GREY}  # List all access lists${CoR}"
    echo -e "  $0 --access-list"
    echo -e "${COLOR_GREY}  # Enable ACL for host (host_id,acl_id)${CoR}"
    echo -e "  $0 --host-acl-enable 42,2"
    echo -e "${COLOR_GREY}  # Disable ACL for host${CoR}"
    echo -e "  $0 --host-acl-disable 42"

    echo -e "\n${COLOR_GREEN}📦 Backup & Maintenance:${CoR}"
    echo -e "${COLOR_GREY}  # Create full backup${CoR}"
    echo -e "  $0 --backup"
    echo -e "${COLOR_GREY}  # Check token status${CoR}"
    echo -e "  $0 --check-token"
    echo -e "${COLOR_GREY}  # Display script information${CoR}"
    echo -e "  $0 --info"

    echo -e "\n${COLOR_GREEN}⚙️ Advanced Configuration Example:${CoR}"
    echo -e "${COLOR_GREY}  # Create host with all options${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080 \\"
    echo -e "     -f https \\"
    echo -e "     -c true \\"
    echo -e "     -b true \\"
    echo -e "     -w true \\"
    echo -e "     -a 'proxy_set_header X-Real-IP \$remote_addr;' \\"
    echo -e "     -l '[{\"path\":\"/api\",\"forward_host\":\"api.local\",\"forward_port\":3000}]'"

    echo -e "\n${COLOR_YELLOW}📝 Command Parameters:${CoR}"
    echo -e "  domain                : New domaine "
    echo -e "  -i, --forward-host    : Target server (IP/hostname)"
    echo -e "  -p, --forward-port    : Target port"
    echo -e "  -f, --forward-scheme  : http/https"
    echo -e "  -c, --cache-enabled   : Enable cache"
    echo -e "  -b, --block-exploits  : Protection against exploits"
    echo -e "  -w, --websocket       : WebSocket support"
    echo -e "  -a, --advanced-config : Custom Nginx configuration"
    echo -e "  -l, --locations       : Custom location rules (JSON)\n"

   exit 0
}

################################
# Display script variables info
display_info() {
  check_dependencies
  check_nginx_access
  echo -e "${COLOR_YELLOW}\n Script Info:  ${COLOR_GREEN}${VERSION}${CoR}"
  echo -e " ${COLOR_YELLOW}Script Variables Information:${CoR}"
  echo -e "\n  ${COLOR_GREEN}BASE_DIR${CoR}  ${BASE_DIR}"
  echo -e "  ${COLOR_YELLOW}Config${CoR}  ${BASE_DIR}/nginx_proxy_manager_cli.conf"
  echo -e "  ${COLOR_GREEN}BASE_URL${CoR}  ${BASE_URL}"
  echo -e "  ${COLOR_GREEN}NGINX_IP${CoR}   ${NGINX_IP}"
  echo -e "  ${COLOR_GREEN}API_USER${CoR}    ${API_USER}"
  echo -e "  ${COLOR_GREEN}BACKUP_DIR${CoR}  ${BACKUP_DIR}"
  echo -e "  ${COLOR_GREEN}DOCKER Path${CoR}  ${NGINX_PATH_DOCKER}"

  if [ -d "$BACKUP_DIR" ]; then
    backup_count=$(find "$BACKUP_DIR" -maxdepth 1 -type f | wc -l)
    echo -e "  ${COLOR_GREEN}BACKUP HOST  ${COLOR_YELLOW}$backup_count ${CoR}"
  else
    echo -e "  ${COLOR_RED}Backup directory does not exist.${CoR}"
  fi
  if [ -f "$TOKEN_FILE" ]; then
    echo -e "  ${COLOR_GREEN}Token NPM  ${CoR} $TOKEN_FILE"
    check_token true
  else
    echo -e "\n  ${COLOR_RED}Generating new token... ${CoR}"
		# check if empty file
		if [ ! -s "$TOKEN_FILE" ]; then
		  	echo -e "  Create $TOKEN_DIR"
		  	rm -rf "$TOKEN_DIR"
				mkdir "$TOKEN_DIR"
		else
		  echo -e " File $TOKEN_FILE ✅"
		fi
    echo -e "  🔖${COLOR_YELLOW} Check token 🆔${CoR}"

   generate_token
	 #validate_token
  fi

  display_dashboard
}

# Function to display dashboard
display_dashboard() {
    echo -e "\n${COLOR_CYAN}📊 NGINX - Proxy Manager - Dashboard 🔧 ${CoR}"
    echo -e "${COLOR_GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CoR}"
    # Get all data first
    local proxy_hosts=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(get_token)")
    local redirection_hosts=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/redirection-hosts" \
        -H "Authorization: Bearer $(get_token)")
    local stream_hosts=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/streams" \
        -H "Authorization: Bearer $(get_token)")
    local certificates=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(get_token)")
    local users=$(curl -s --max-redirs 0 -X GET "$BASE_URL/users" \
        -H "Authorization: Bearer $(get_token)")
    local access_lists=$(curl -s --max-redirs 0 -X GET "$BASE_URL/nginx/access-lists" \
        -H "Authorization: Bearer $(get_token)")
    
    # Calculate counts with error checking
    local proxy_count=0
    local enabled_proxy_count=0
    local redirect_count=0
    local stream_count=0
    local cert_count=0
    local expired_cert_count=0
    local user_count=0
    local access_list_count=0
    local access_list_clients=0

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
        access_list_clients=$(echo "$access_lists" | jq '[.[].clients | length] | add // 0')
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
    # Redirections & Streams
    print_row "🔄 Redirections" "$redirect_count"
    print_row "🔌 Stream Hosts" "$stream_count"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # SSL Certificates
    print_row "🔒 Certificates" "$cert_count" "$COLOR_YELLOW"
    print_row "├─ Valid       " "$valid_cert_count"
    print_row "└─ Expired     " "$expired_cert_count" "$COLOR_RED"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # Access Lists
    print_row "🔒 Access Lists" "$access_list_count"
    print_row "└─ Clients     " "$access_list_clients"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # Users 
    print_row "👥 Users       " "$user_count"
    echo -e " ${COLOR_GREY}├─────────────────┼─────────┤${CoR}"
    # System
    print_row "⏱️  Uptime      " "$uptime" "$COLOR_YELLOW"
    print_row "📦 Version     " "$npm_version" "$COLOR_YELLOW"
    echo -e " ${COLOR_GREY}└─────────────────┴─────────┘${CoR}"
    echo -e "\n${COLOR_YELLOW}💡 Use --help to see available commands${CoR}\n"
}
################################
# Colorize boolean values for display
colorize_boolean() {
  local value=$1
  if [ "$value" = true ]; then
    echo -e "${COLOR_GREEN}true${CoR}"
  else
    echo -e "${COLOR_YELLOW}false${CoR}"
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

# validate_token not verbose
validate_token() {
    check_token false
}

################################
# Generate a new API token
generate_new_token() {
  # First check if NPM is accessible
    if ! curl --output /dev/null --silent --head --fail --connect-timeout 5 "$BASE_URL"; then
        echo -e "\n❌ ${COLOR_RED}ERROR: Cannot connect to NPM to generate token${CoR}"
        echo -e "🔍 Please check if NPM is running and accessible at ${COLOR_YELLOW}$BASE_URL${CoR}\n"
        exit 1
    fi
    # Try to get initial token
    local initial_response
    initial_response=$(curl -s -X POST "$BASE_URL$TOKEN_API_ENDPOINT" \
        -H "Content-Type: application/json; charset=UTF-8" \
        --data-raw "{\"identity\":\"$API_USER\",\"secret\":\"$API_PASS\"}")

    local initial_token=$(echo "$initial_response" | jq -r '.token')
    if [ "$initial_token" = "null" ] || [ -z "$initial_token" ]; then
        echo -e "\n ❌ ${COLOR_RED}Failed to get initial token${CoR}"
        echo -e "🔍 Details:"
        echo -e " • Response: ${COLOR_YELLOW}$initial_response${CoR}"
        echo -e "\n📋 Possible issues:"
        echo -e " 1. Invalid credentials"
        echo -e " 2. NPM service issues"
        echo -e " 3. Network connectivity problems"
        exit 1
    fi
    # Try to renew with desired expiry
    local renew_response=$(curl -s -w "\nHTTPSTATUS:%{http_code}" -X GET "$BASE_URL$TOKEN_API_ENDPOINT?expiry=$TOKEN_EXPIRY" \
        -H "Authorization: Bearer $initial_token" \
        -H "Accept: application/json")
    local http_body=$(echo "$renew_response" | sed -e 's/HTTPSTATUS\:.*//g')
    local http_status=$(echo "$renew_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$http_status" = "200" ]; then
        local new_token=$(echo "$http_body" | jq -r '.token')
        local new_expires=$(echo "$http_body" | jq -r '.expires')

        if [ "$new_token" != "null" ] && [ -n "$new_token" ]; then
            echo "$new_token" > "$TOKEN_FILE"
            echo "$new_expires" > "$EXPIRY_FILE"
            echo -e "  ✅ ${COLOR_GREEN}New token generated, valid until: $new_expires${CoR}"
        else
            echo -e "\n❌ ${COLOR_RED}Invalid token response${CoR}"
            echo -e " 🔍 Response: ${COLOR_YELLOW}$http_body${CoR}"
            exit 1
        fi
    else
        echo -e "\n❌ ${COLOR_RED}Failed to renew token${CoR}"
        echo -e "🔍 Details:"
        echo -e " • Status: ${COLOR_YELLOW}$http_status${CoR}"
        echo -e " • Response: ${COLOR_YELLOW}$http_body${CoR}"
        echo -e "\n📋 Troubleshooting:"
        echo -e " 1. Check NPM status"
        echo -e " 2. Verify network connectivity"
        echo -e " 3. Check NPM logs"
        exit 1
    fi
}

################################
# Generate and/or validate token
# $1: boolean - true pour afficher les messages, false pour mode silencieux
check_token() {
    local verbose=${1:-false}
    [ "$verbose" = true ] && echo -e "\n 🔑 Checking token validity..."
    # Check if token files exist
    if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ]; then
        [ "$verbose" = true ] && echo -e " ⛔ ${COLOR_RED}No token files found. Generating new token...${CoR}"
        generate_new_token
        return
    fi
 
    if [ ! -s "$TOKEN_FILE" ] || [ ! -s "$EXPIRY_FILE" ]; then
        [ "$verbose" = true ] && echo -e " ⛔ ${COLOR_RED}Token files are empty. Generating new token...${CoR}"
        generate_new_token
        return
    fi
    token=$(cat "$TOKEN_FILE")
    expires=$(cat "$EXPIRY_FILE")
    current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
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
        [ "$verbose" = true ] && echo -e " 📅 Expires: ${COLOR_YELLOW}$expires${CoR}"
    else
        [ "$verbose" = true ] && echo -e " ⛔ ${COLOR_RED}Token is invalid. Generating new token...${CoR}"
        generate_new_token
    fi
}

################################
# Get token with validation
# Returns the current valid token
get_token() {
    check_token false
    if [ ! -f "$TOKEN_FILE" ]; then
        echo "Error: Token file not found after check_token" >&2
        exit 1
    fi
    cat "$TOKEN_FILE"
}

################################
# Create a new proxy host
create_new_proxy_host() {
  echo -e " 🌍 Creating proxy host for $DOMAIN_NAMES..."
    # Vérifier que les variables obligatoires sont bien définies
    if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ] || [ -z "$FORWARD_SCHEME" ]; then
      echo -e "  ⛔${COLOR_RED} ERROR: Missing required parameters ${CoR}(domain, forward host, forward port, forward scheme)."
      exit 1
    fi

    # Vérifier que FORWARD_PORT est bien un nombre
    if ! [[ "$FORWARD_PORT" =~ ^[0-9]+$ ]]; then
      echo -e "  ⛔${COLOR_RED} ERROR: FORWARD_PORT is not a number! Value: '$FORWARD_PORT'${CoR}"
      exit 1
    fi

    # 🔥 Correction : S'assurer que `CUSTOM_LOCATIONS` est toujours un JSON valide
    if [[ -z "$CUSTOM_LOCATIONS" || "$CUSTOM_LOCATIONS" == "null" ]]; then
      CUSTOM_LOCATIONS_ESCAPED="[]"
    else
      CUSTOM_LOCATIONS_ESCAPED=$(echo "$CUSTOM_LOCATIONS" | jq -c . 2>/dev/null || echo '[]')
    fi
  # Correction des booléens (true / false en JSON)
  CACHING_ENABLED_JSON=$( [ "$CACHING_ENABLED" == "true" ] && echo true || echo false )
  BLOCK_EXPLOITS_JSON=$( [ "$BLOCK_EXPLOITS" == "true" ] && echo true || echo false )
  ALLOW_WEBSOCKET_UPGRADE_JSON=$( [ "$ALLOW_WEBSOCKET_UPGRADE" == "true" ] && echo true || echo false )
  HTTP2_SUPPORT_JSON=$( [ "$HTTP2_SUPPORT" == "true" ] && echo true || echo false )

  #🔍 Debugging variables before JSON update:
	#debug_var
  # 🔥 clean JSON
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
  # check if the JSON is valid before sending
  if ! echo "$DATA" | jq empty > /dev/null 2>&1; then
    echo -e " ${COLOR_RED} ⛔ ERROR: Invalid JSON generated:\n$DATA ${CoR}"
    exit 1
  fi

  # 🚀 Send API payload
  RESPONSE=$(curl -s -X POST "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(get_token)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  # 📢 Check answer from API
  ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // empty')
  if [ -z "$ERROR_MSG" ]; then
      PROXY_ID=$(echo "$RESPONSE" | jq -r '.id // "unknown"')
      echo -e "\n ✅ ${COLOR_GREEN}SUCCESS: Proxy host 🔗$DOMAIN_NAMES (ID: ${COLOR_YELLOW}$PROXY_ID${COLOR_GREEN}) was created successfully! 🎉${CoR}\n"
  else
      echo -e " ⛔ ${COLOR_RED}Failed to create proxy host. Error: $ERROR_MSG ${CoR}"
      exit 1
  fi
	# 🔥 Debug JSON generate
	#echo -e "\n📝 JSON send to PI :"
	#echo "$DATA" | jq .
}


################################
# Check if a proxy host with the given domain names already exists
check_existing_proxy_host() {
  echo -e "\n 🔎 Checking if proxy host $DOMAIN_NAMES already exists..."

  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(get_token)")

#  echo -e "\n 🔍 Raw API Response: $RESPONSE"  # Debugging API response
  EXISTING_HOST=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN_NAMES" '.[] | select(.domain_names[] == $DOMAIN)')

  if [ -n "$EXISTING_HOST" ]; then
    echo -e "\n 🔔 Proxy host for $DOMAIN_NAMES already exists."
    if [ "$AUTO_YES" = true ]; then
        REPLY="y"
        echo -e "🔔 Option -y detected. Skipping confirmation prompt and proceeding with update..."
    else
        read -r -p " 👉 Do you want to update it? (y/n): " -r
    fi
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      HOST_ID=$(echo "$EXISTING_HOST" | jq -r '.id')
      update_proxy_host "$HOST_ID"
    else
      echo -e " ${COLOR_YELLOW}🚫 No changes made.${CoR}"
      exit 0
    fi
  else
    create_new_proxy_host
  fi
}

 
for arg in "$@"; do
    if [ "$arg" = "-y" ]; then
        AUTO_YES=true
        break
    fi
done

################################
# Function to handle host creation options
process_host_creation_options() {
    local OPTIND=1
    local has_error=false

    # Réinitialiser les variables (sauf DOMAIN_NAMES qui est déjà défini)
    FORWARD_HOST=""
    FORWARD_PORT=""
    FORWARD_SCHEME="http"
    CACHING_ENABLED="false"
    BLOCK_EXPLOITS="false"
    ALLOW_WEBSOCKET_UPGRADE="false"
    ADVANCED_CONFIG=""
    CUSTOM_LOCATIONS=""

    while getopts "i:p:f:c:b:w:a:l:y" opt; do
        case $opt in
            i) FORWARD_HOST="$OPTARG" ;;
            p) 
                if [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
                    FORWARD_PORT="$OPTARG"
                else
                    echo -e "\n ⛔ ${COLOR_RED}Error: Port must be a number${CoR}"
                    has_error=true
                fi
                ;;
            f) 
                if [[ "$OPTARG" =~ ^(http|https)$ ]]; then
                    FORWARD_SCHEME="$OPTARG"
                else
                    echo -e "\n ⛔ ${COLOR_RED}Error: Scheme must be 'http' or 'https'${CoR}"
                    has_error=true
                fi
                ;;
            c) 
                if [[ "$OPTARG" =~ ^(true|false)$ ]]; then
                    CACHING_ENABLED="$OPTARG"
                else
                    echo -e "\n ⛔ ${COLOR_RED}Error: Caching must be 'true' or 'false'${CoR}"
                    has_error=true
                fi
                ;;
            b)
                if [[ "$OPTARG" =~ ^(true|false)$ ]]; then
                    BLOCK_EXPLOITS="$OPTARG"
                else
                    echo -e "\n ⛔ ${COLOR_RED}Error: Block exploits must be 'true' or 'false'${CoR}"
                    has_error=true
                fi
                ;;
            w)
                if [[ "$OPTARG" =~ ^(true|false)$ ]]; then
                    ALLOW_WEBSOCKET_UPGRADE="$OPTARG"
                else
                    echo -e "\n ⛔ ${COLOR_RED}Error: Websocket upgrade must be 'true' or 'false'${CoR}"
                    has_error=true
                fi
                ;;
            a) ADVANCED_CONFIG="$OPTARG" ;;
            l) CUSTOM_LOCATIONS="$OPTARG" ;;
            y) AUTO_YES=true ;;
            ?)
                show_host_create_usage
                exit 1
                ;;
        esac
    done

    # Vérifier les erreurs de validation
    if [ "$has_error" = true ]; then
        exit 1
    fi

    # Vérifier et demander les paramètres requis manquants
    if [ -z "$DOMAIN_NAMES" ]; then
        echo -e "\n${COLOR_YELLOW}📝 Entrez le nom de domaine :${CoR}"
        read -r -p " > " DOMAIN_NAMES
    fi

    if [ -z "$FORWARD_HOST" ]; then
        echo -e "\n${COLOR_YELLOW}📝 Entrez l'adresse IP du serveur :${CoR}"
        read -r -p " > " FORWARD_HOST
    fi

    if [ -z "$FORWARD_PORT" ]; then
        echo -e "\n${COLOR_YELLOW}📝 Entrez le port :${CoR}"
        read -r -p " > " FORWARD_PORT
    fi

    # Vérifier une dernière fois les paramètres requis
    if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ]; then
        show_host_create_usage
        exit 1
    fi

    # Créer ou mettre à jour l'hôte
    create_or_update_proxy_host
}

# Affiche l'aide pour la création d'hôte
show_host_create_usage() {
    echo -e "\n${COLOR_RED}⚠️  Usage pour --host-create :${CoR}"
    echo -e " Format: $0 --host-create <domain> -i <host> -p <port> [options]"
    echo -e "\n Options requises :"
    echo -e "   <domain>     : Nom de domaine ${COLOR_GREY}(ex: example.com)${CoR}"
    echo -e "   -i <host>    : Serveur cible ${COLOR_GREY}(ex: 192.168.1.10)${CoR}"
    echo -e "   -p <port>    : Port cible ${COLOR_GREY}(ex: 8080)${CoR}"
    echo -e "\n Options facultatives :"
    echo -e "   -f SCHEME    : Schéma ${COLOR_GREY}(http ou https)${CoR}"
    echo -e "   -c CACHE     : Activer le cache ${COLOR_GREY}(true ou false)${CoR}"
    echo -e "   -b EXPLOITS  : Bloquer les exploits ${COLOR_GREY}(true ou false)${CoR}"
    echo -e "   -w WEBSOCKET : Autoriser websocket ${COLOR_GREY}(true ou false)${CoR}"
    echo -e "   -a CONFIG    : Configuration avancée"
    echo -e "   -l LOCATIONS : Locations personnalisées"
    echo -e "   -y           : Auto-confirmation\n"
    echo -e "\n${COLOR_YELLOW}📝 Exemple :${CoR}"
    echo -e "  $0 --host-create example.com -i 192.168.1.10 -p 8080\n"
}

# Create or update a proxy host based on the existence of the domain
create_or_update_proxy_host() {
    # Check if the host already exists
    echo -e "\n 🔎 Checking if the host $DOMAIN_NAMES already exists..."
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
    -H "Authorization: Bearer $(get_token)")

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
        # Update existing host
        echo -e "\n 🔄 Updating the proxy host for $DOMAIN_NAMES..."
        if [ "$AUTO_YES" != true ]; then
            read -r -p " 👉 Do you want to update this host? (o/n): " -r
            if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
                echo -e " ${COLOR_YELLOW}🚫 No changes made.${CoR}"
                exit 0
            fi
        fi
        
        METHOD="PUT"
        URL="$BASE_URL/nginx/proxy-hosts/$HOST_ID"
    else
        # Create a new host
        echo -e "\n 🌍 Creating a new proxy host for $DOMAIN_NAMES..."
        METHOD="POST"
        URL="$BASE_URL/nginx/proxy-hosts"
    fi

    # Send API request
    RESPONSE=$(curl -s -X "$METHOD" "$URL" \
        -H "Authorization: Bearer $(get_token)" \
        -H "Content-Type: application/json; charset=UTF-8" \
        --data-raw "$DATA")

    # Check API response
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // empty')
    if [ -z "$ERROR_MSG" ]; then
        PROXY_ID=$(echo "$RESPONSE" | jq -r '.id // "unknown"')
        if [ "$METHOD" = "PUT" ]; then
            echo -e "\n ✅ ${COLOR_GREEN}SUCCESS: Proxy host 🔗$DOMAIN_NAMES (ID: ${COLOR_YELLOW}$PROXY_ID${COLOR_GREEN}) updated successfully! 🎉${CoR}\n"
        else
            echo -e "\n ✅ ${COLOR_GREEN}SUCCESS: Proxy host 🔗$DOMAIN_NAMES (ID: ${COLOR_YELLOW}$PROXY_ID${COLOR_GREEN}) created successfully! 🎉${CoR}\n"
        fi
    else
        echo -e " ⛔ ${COLOR_RED}Operation failed. Error: $ERROR_MSG${CoR}"
        exit 1
    fi
}

######################################
# Main menu logic
######################################

# If no argument is provided, display the dashboard
if [ $# -eq 0 ]; then
    check_token false
    display_dashboard
    exit 0
fi

# Process long options
case "$1" in
    --help) help ;;
    --examples) EXAMPLES=true ;;
    --info) INFO=true ;;
    --show-default) SHOW_DEFAULT=true ;;
    --check-token) CHECK_TOKEN=true ;;
    --host-create)
        shift
        if [ -z "$1" ] || [[ "$1" == -* ]]; then
            echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing domain argument${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --host-create <domain> -i <host> -p <port> [options]${CoR}"
            echo -e " Example:"
            echo -e "   ${COLOR_GREEN}$0 --host-create example.com -i 192.168.1.10 -p 8080${CoR}\n"
            exit 1
        fi
        DOMAIN_NAMES="$1"
        shift
        process_host_creation_options "$@"
        validate_token
        create_or_update_proxy_host
        exit 0
        ;;
    --backup) BACKUP=true ;;
    --backup-host)
        if [ -n "$2" ] && [[ "$2" != -* ]]; then
            HOST_ID="$2"
            shift
        fi
        BACKUP_HOST=true
        validate_token
        ;;

    --backup-host-list)  BACKUP_LIST=true; validate_token ;;
    --restore-host)
        if [ -n "${!OPTIND}" ] && [[ "${!OPTIND}" != -* ]]; then
            RESTORE_HOST=true
            DOMAIN="${!OPTIND}"; shift
        else
            list_backups
            echo -n "Enter domain to restore: "
            read -r DOMAIN
            RESTORE_HOST=true
        fi
        ;;
    --restore-backup)
        RESTORE_BACKUP=true
        validate_token
        shift
        ;;
    --clean-hosts)
        NEXT_ARG=$((OPTIND))
        if [ -n "${*:$NEXT_ARG:1}" ] && [[ "${*:$NEXT_ARG:1}" != -* ]]; then
            BACKUP_FILE="${*:$NEXT_ARG:1}"
            OPTIND=$((NEXT_ARG + 1))
        else
            BACKUP_FILE="$DEFAULT_BACKUP_FILE"
        fi
        CLEAN_HOSTS=true
        validate_token
        ;;
    --list-users) LIST_USERS=true; validate_token ;;
    --create-user)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            USERNAME="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
            # Get password
            next_arg="$((OPTIND))"
            if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
                PASSWORD="${*:$next_arg:1}"
                OPTIND=$((next_arg + 1))
                # Get email
                next_arg="$((OPTIND))"
                if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
                    EMAIL="${*:$next_arg:1}"
                    OPTIND=$((next_arg + 1))
                fi
            fi
        fi
        if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$EMAIL" ]; then
            echo -e "\n 👤 ${COLOR_RED}The --create-user option requires username, password, and email.${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --create-user username password email${CoR}"
            echo -e " Example:"
            echo -e "   ${COLOR_GREEN}$0 --create-user john secretpass john@domain.com${CoR}\n"
            exit 1
        fi
        CREATE_USER=true
        validate_token
        ;;
    --delete-user)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            USER_ID="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
        else
            echo -e "\n ⛔ ${COLOR_RED}Error: The --delete-user option requires a user ID.${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --delete-user <user_id>${CoR}"
            echo -e " To find user IDs, use: ${COLOR_ORANGE}$0 --list-users${CoR}\n"
            echo -e " Example:"
            echo -e "   ${COLOR_GREEN}$0 --delete-user 123${CoR}\n"
            exit 1
        fi
        DELETE_USER=true
        validate_token
        ;;
    --host-show)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            HOST_ID="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
        else
            echo -e "\n ⛔ ${COLOR_RED}The --host-show option requires a host ID.${CoR}"
            echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
            exit 1
        fi
        HOST_SHOW=true
        validate_token
        ;;
    --host-list) HOSTS_LIST=true; validate_token ;;
    --host-list-full) HOSTS_LIST_FULL=true; validate_token ;;
    --host-search)
        HOST_SEARCHNAME="${!OPTIND}"; OPTIND=$((OPTIND + 1))
        if [ -z "$HOST_SEARCHNAME" ]; then
            echo -e "\n ⛔ ${COLOR_RED}The --host-search option requires a host name.${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --host-search hostname${CoR}"
            exit 1
        fi
        HOST_SEARCH=true
        validate_token
        ;;
    --host-enable)
        HOST_ID="${!OPTIND}"; shift
        if [ -z "$HOST_ID" ]; then
            echo -e "\n ⛔ ${COLOR_RED}The --host-enable option requires a host ID.${CoR}"
            echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
            exit 1
        fi
        HOST_ENABLE=true
        validate_token
        ;;
    --host-disable)
        HOST_ID="${!OPTIND}"; shift
        if [ -z "$HOST_ID" ]; then
            echo -e "\n ⛔ ${COLOR_RED}The --host-disable option requires a host ID.${CoR}"
            echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
            exit 1
        fi
        HOST_DISABLE=true
        validate_token
        ;;
    --host-delete)
        next_arg=$((OPTIND))
        HOST_ID=${@:$next_arg:1}
        
        if [ -z "$HOST_ID" ]; then
            echo -e "\n 🗑️ ${COLOR_RED}The --host-delete option requires a host ID.${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --host-delete <host_id>${CoR}"
            echo -e " To find host IDs, use: ${COLOR_ORANGE}$0 --host-list${CoR}\n"
            exit 1
        fi
        
        if ! [[ "$HOST_ID" =~ ^[0-9]+$ ]]; then
            echo -e "\n ⛔ ${COLOR_RED}Invalid host ID. Must be a number.${CoR}"
            exit 1
        fi
        HOST_DELETE=true
        validate_token
        ;;
    --host-update)
        next_arg=$((OPTIND))
        HOST_ID=${@:$next_arg:1}
        FIELD_VALUE=${@:$next_arg+1:1}
        
        if [ -z "$HOST_ID" ] || [ -z "$FIELD_VALUE" ]; then
            echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing arguments${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --host-update <host_id> <field=value>${CoR}"
            echo -e " Example:"
            echo -e "   ${COLOR_GREEN}$0 --host-update 42 forward_port=8080${CoR}\n"
            echo -e " To find host IDs, use: ${COLOR_ORANGE}$0 --host-list${CoR}\n"
            exit 1
        fi
        
        if ! [[ "$HOST_ID" =~ ^[0-9]+$ ]]; then
            echo -e "\n ⛔ ${COLOR_RED}Invalid host ID. Must be a number.${CoR}"
            exit 1
        fi
        
        if ! [[ "$FIELD_VALUE" =~ ^[a-zA-Z_]+=[^[:space:]]+$ ]]; then
            echo -e "\n ⛔ ${COLOR_RED}Invalid field=value format${CoR}"
            echo -e " Format should be: field=value"
            echo -e " Example: forward_port=8080\n"
            exit 1
        fi
        
        FIELD="${FIELD_VALUE%%=*}"
        VALUE="${FIELD_VALUE#*=}"
        HOST_UPDATE=true
        validate_token
        ;;
    --host-acl-enable)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            ACL_ARG="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
            IFS=',' read -r HOST_ID ACCESS_LIST_ID <<< "$ACL_ARG"

            if [ -z "$HOST_ID" ] || [ -z "$ACCESS_LIST_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing or invalid arguments${CoR}"
                echo -e " Usage: ${COLOR_ORANGE}$0 --host-acl-enable host_id,access_list_id${CoR}"
                echo -e " Example:"
                echo -e "   ${COLOR_GREEN}$0 --host-acl-enable 42,2${CoR}"
                echo -e "\n To find IDs:"
                echo -e " • Host IDs:        ${COLOR_ORANGE}$0 --host-list${CoR}"
                echo -e " • Access List IDs: ${COLOR_ORANGE}$0 --access-list${CoR}\n"
                exit 1
            fi
        else
            echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing arguments${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --host-acl-enable host_id,access_list_id${CoR}"
            echo -e " Example:"
            echo -e "   ${COLOR_GREEN}$0 --host-acl-enable 42,2${CoR}"
            echo -e "\n To find IDs:"
            echo -e " • Host IDs:        ${COLOR_ORANGE}$0 --host-list${CoR}"
            echo -e " • Access List IDs: ${COLOR_ORANGE}$0 --access-list${CoR}\n"
            exit 1
        fi
        HOST_ACL_ENABLE=true
        validate_token
        ;;
    --host-acl-disable)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            HOST_ID="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
        else
            echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing argument${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --host-ssl-disable <host_id>${CoR}"
            echo -e " To find host IDs, use: ${COLOR_ORANGE}$0 --host-list${CoR}\n"
            exit 1
        fi
        DISABLE_SSL=true
        validate_token
        ;;
    --ssl-regenerate)  SSL_REGENERATE=true; validate_token ;;
    --ssl-restore)  SSL_RESTORE=true; validate_token ;;              
    --generate-cert)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            DOMAIN="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
            # Check for optional email parameter
            next_arg="$((OPTIND))"
            if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
                EMAIL="${*:$next_arg:1}"
                OPTIND=$((next_arg + 1))
                # Check for optional DNS parameters
                while [ -n "${*:$OPTIND:1}" ] && [[ "${*:$OPTIND:1}" != -* ]]; do
                    case "${*:$OPTIND:1}" in
                        "dns-provider")
                            OPTIND=$((OPTIND + 1))
                            if [ -n "${*:$OPTIND:1}" ] && [[ "${*:$OPTIND:1}" != -* ]]; then
                                DNS_PROVIDER="${*:$OPTIND:1}"
                                OPTIND=$((OPTIND + 1))
                            fi
                            ;;
                        "dns-api-key")
                            OPTIND=$((OPTIND + 1))
                            if [ -n "${*:$OPTIND:1}" ] && [[ "${*:$OPTIND:1}" != -* ]]; then
                                DNS_API_KEY="${*:$OPTIND:1}"
                                OPTIND=$((OPTIND + 1))
                            fi
                            ;;
                    esac
                done
            fi
        fi
        if [ -z "$DOMAIN" ]; then
            echo -e "\n 🛡️ The --generate-cert option requires a domain."
            echo -e " Usage: ${COLOR_ORANGE}$0 --generate-cert domain [email] [dns-provider provider dns-api-key key]${CoR}"
            echo -e " Note: If email is not provided, default email ${COLOR_YELLOW}$DEFAULT_EMAIL${CoR} will be used"
            echo -e " For wildcard certificates (*.domain.com), DNS challenge is required\n"
            echo -e " Examples:"
            echo -e "   ${COLOR_GREEN}$0 --generate-cert example.com admin@example.com${CoR}"
            echo -e "   ${COLOR_GREEN}$0 --generate-cert *.example.com admin@example.com dns-provider dynu dns-api-key YOUR_API_KEY${CoR}\n"
            exit 1
        fi
        GENERATE_CERT=true
        validate_token
        ;;
    --delete-cert)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            DOMAIN="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
        fi
        DELETE_CERT=true
        validate_token
        ;;
    --host-ssl-enable)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            HOST_ID="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
        fi
        if [ -z "$HOST_ID" ]; then
            echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing argument${CoR}"
            echo -e " Usage: ${COLOR_ORANGE}$0 --host-ssl-enable <host_id>${CoR}"
            echo -e " To find host IDs, use: ${COLOR_ORANGE}$0 --host-list${CoR}\n"
            exit 1
        fi
        ENABLE_SSL=true
        validate_token
        ;;
    --host-ssl-disable)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            HOST_ID="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
        fi
        DISABLE_SSL=true
        validate_token
        ;;
    --force-cert-creation)
        FORCE_CERT_CREATION=true
        validate_token
        ;;
    --list-ssl-cert)
        next_arg="$((OPTIND))"
        if [ -n "${*:$next_arg:1}" ] && [[ "${*:$next_arg:1}" != -* ]]; then
            DOMAIN="${*:$next_arg:1}"
            OPTIND=$((next_arg + 1))
        fi
        LIST_SSL_CERT=true
        validate_token
        ;;
    --access-list) ACCESS_LIST=true; validate_token ;;
    y|yes) AUTO_YES=true ;;
    *)
        echo -e "\n${COLOR_RED}⛔ Invalid command or option: $1${CoR}"
        echo -e "Use $0 --help to see all available commands\n"
        help
        exit 1
        ;;
esac


######################################
# DEBUG
debug_var(){
  # 🔍 Debugging Data
  echo -e "\n 🔍 Debugging variables before JSON update:"
  echo " DOMAIN_NAMES: $DOMAIN_NAMES"
  echo " FORWARD_HOST: $FORWARD_HOST"
  echo " FORWARD_PORT: $FORWARD_PORT"
  echo " FORWARD_SCHEME: $FORWARD_SCHEME"
  echo " CACHING_ENABLED: $CACHING_ENABLED_JSON"
  echo " BLOCK_EXPLOITS: $BLOCK_EXPLOITS_JSON"
  echo " ALLOW_WEBSOCKET_UPGRADE: $ALLOW_WEBSOCKET_UPGRADE_JSON"
  echo " HTTP2_SUPPORT: $HTTP2_SUPPORT_JSON"
  echo " CUSTOM_LOCATIONS: $CUSTOM_LOCATIONS_ESCAPED"
  echo " ADVANCED_CONFIG: $ADVANCED_CONFIG"

}
######################################

################################
# List all access lists
access_list() {
    echo -e "\n📋 Available Access Lists:"
    local response=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
        -H "Authorization: Bearer $(get_token)")

    # Check if response is valid JSON
    if ! echo "$response" | jq empty 2>/dev/null; then
        echo -e "⛔ ${COLOR_RED}Invalid response from API${CoR}"
        return 1
    fi
    # Check if response is empty
    if [ "$(echo "$response" | jq length)" -eq 0 ]; then
        echo -e "ℹ️ ${COLOR_YELLOW}No access lists found${CoR}"
        return 0
    fi
    # Format and display the access lists
    echo -e "\n${COLOR_YELLOW}ID    |  Name          |  Clients  | Pass Auth | Satisfy${CoR}"
    echo "------|----------------|-----------|------------|--------"
    echo "$response" | jq -r '.[] | [.id, .name, (.clients | length), .pass_auth, .satisfy]  |         "\(.[0]|tostring|.[0:4] + "      "  | .[0:6])| \(.[1]|tostring|.[0:14] + "              " | .[0:14])| \(.[2]) clients | \(.[3]|tostring|.[0:10] + "          " | .[0:10])| \(.[4])"'
    echo -e "\n"

    # Display the details of the clients for each list
    echo -e "${COLOR_YELLOW}Details of Access Lists:${CoR}"
    echo "$response" | jq -r '.[] | "🔒 List: \(.name) (ID: \(.id))
   • Pass Auth: \(.pass_auth)
   • Satisfy: \(.satisfy)
   • Clients (\(.clients | length)):\(.clients | if length > 0 then map("     - \(.address)") | join("\n") else " (No clients)" end)"'
    echo -e "\n"
}

##############################################################
# Function to confirm dangerous operations
##############################################################
confirm_dangerous_operation() {
    local operation=$1
    local id=$2
    
    echo -e "\n 📣${COLOR_RED}Warning: You are about to $operation ID: $id${CoR}"
    echo -n "   Are you sure you want to continue? (y/N) "
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    else
        echo -e " Operation cancelled."
        return 1
    fi
}
################################
# Function to check if the host ID exists
host-check-id() {
  local host_id=$1
  # shellcheck disable=SC2155
  local host_list=$($0 --host-list)

  if echo "$host_list" | grep -q "\"id\": $host_id"; then
    return 0
  else
    echo "Error: Host ID $host_id does not exist."
    exit 1
  fi
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
# Function to regenerate SSL certificates for all hosts
regenerate_all_ssl_certificates() {
  echo -e "\n🔄 Regenerating SSL certificates for all hosts..."

  # shellcheck disable=SC2155
  local hosts=$(curl -s -X GET -H "Authorization: Bearer $(get_token)" "$NGINX_API_URL/nginx/proxy-hosts")

  # shellcheck disable=SC2207
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

##############################################################
# Function to delete all existing proxy hosts  # DEBUG
##############################################################
# Delete all existing proxy hosts
delete_all_proxy_hosts() {
    echo -e "\n 🗑️ ${COLOR_ORANGE}Deleting all existing proxy hosts...${CoR}"

    # Get all host IDs
    local existing_hosts=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(get_token)" | jq -r '.[].id')

    local count=0
    for host_id in $existing_hosts; do
        echo -e " •  Deleting host ID ${COLOR_CYAN}$host_id${CoR}...${COLOR_GREEN}✓${CoR}"
        local response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/nginx/proxy-hosts/$host_id" \
            -H "Authorization: Bearer $(get_token)")

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
# List all proxy hosts with full details
host_list_full() {
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(get_token)")

  echo "$RESPONSE" | jq -c '.[]' | while read -r proxy; do
    echo "$proxy" | jq .
  done
  echo ""
  exit 0
}

##############################################################
# Function to cleanup duplicate SSL certificates  
##############################################################
cleanup_duplicate_certificates() {
    echo -e "🧹 ${COLOR_YELLOW}Check and clean up duplicate SSL certificates...${CoR}"
    
    local certs=""
    local total_groups=0
    local total_removed=0
    local domains=""  
    certs=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(get_token)") || certs="[]"
    
    # Check if the response is valid
    if ! echo "$certs" | jq empty 2>/dev/null; then
        echo -e " ❌ ${COLOR_RED}Invalid response from API${CoR}"
        return 1
    fi
    
    # Count occurrences of each domain
    local duplicates=$(echo "$certs" | jq -r '
        [.[].domain_names | sort | join(",")] | 
        group_by(.) | 
        map(select(length > 1)) | 
        length
    ')
    
    # Check if there are any duplicate certificates
    if [ "$duplicates" -eq 0 ]; then
        echo -e " ℹ️ ${COLOR_GREEN}Nothing to do - No duplicate certificates found${CoR}\n"
    else
        
    echo -e " • Found ${COLOR_YELLOW}$duplicates${CoR} sets of duplicate certificates\n"
    total_groups=$duplicates
 
    # Get the list of unique domains with duplicates
    domains=$(echo "$certs" | jq -r '
        [.[].domain_names | sort | join(",")] | 
        group_by(.) | 
        map(select(length > 1)) | 
        .[] | .[0]
    ')

    # Process each domain group
    while IFS= read -r domain_group; do
        [ -z "$domain_group" ] && continue
        
        local group_certs=$(echo "$certs" | jq --arg domains "$domain_group" \
            '[.[] | select(.domain_names | sort | join(",") == $domains)]')
        local count=$(echo "$group_certs" | jq length)
        
        if [ "$count" -gt 1 ]; then
            local domain_display=$(echo "$domain_group" | cut -d',' -f1)
            if [ "$domain_group" != "$domain_display" ]; then
                domain_display+=" (+$(( $(echo "$domain_group" | tr -cd ',' | wc -c) + 1 )) domains"
            fi
            
            echo -e " • ${domain_display}: found ${COLOR_YELLOW}$count${CoR} certificates..."
            
            # Find the most recent and valid certificate
            local valid_cert=$(echo "$group_certs" | jq 'max_by(.id)')
            local keep_id=$(echo "$valid_cert" | jq -r '.id')
            local removed=0
            
            # Display the found certificates with more details
            echo "$group_certs" | jq -r '.[] | "   - ID: \(.id), Created: \(.created_on // "N/A"), Provider: \(.provider // "N/A")"'
            echo -e "   ℹ️ Will keep certificate ID: ${COLOR_GREEN}$keep_id${CoR} (most recent)"
            
            # Delete other certificates with confirmation
            while IFS= read -r cert_id; do
                if [ "$cert_id" != "$keep_id" ]; then
                    if [ "$AUTO_YES" != "true" ]; then
                        echo -e -n "   🗑️ Delete certificate ID ${COLOR_CYAN}$cert_id${CoR}? (y/N): "
                        read -r answer < /dev/tty
                        
                        if [[ ! "$answer" =~ ^[Yy]$ ]]; then
                            echo -e "   ⏭️ Skipping deletion of certificate ID ${COLOR_CYAN}$cert_id${CoR}"
                            continue
                        fi
                    fi
                    
                    echo -e "   🗑️ Deleting certificate ID ${COLOR_CYAN}$cert_id${CoR}..."
                    local delete_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE \
                        "$BASE_URL/nginx/certificates/$cert_id" \
                        -H "Authorization: Bearer $(get_token)")
                    
                    local http_body=$(echo "$delete_response" | sed -e 's/HTTPSTATUS\:.*//g')
                    local http_status=$(echo "$delete_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
                    
                    if [ "$http_status" -eq 200 ]; then
                        ((removed++))
                        ((total_removed++))
                        echo -e "   ✅ ${COLOR_GREEN}Successfully removed certificate ID ${COLOR_CYAN}$cert_id${CoR}"
                    else
                        echo -e "   ❌ ${COLOR_RED}Failed to remove certificate ID ${COLOR_CYAN}$cert_id${CoR} (Status: $http_status)${CoR}"
                    fi
                fi
            done < <(echo "$group_certs" | jq -r '.[].id')
            
            if [ $removed -gt 0 ]; then
                echo -e "   📊 ${COLOR_GREEN}Removed ${COLOR_CYAN}$removed${CoR} certificate(s), keeping ID ${COLOR_CYAN}$keep_id${CoR}"
            else
                echo -e "   ℹ️ ${COLOR_YELLOW}No certificates were removed${CoR}"
            fi
            echo ""
        fi
    done <<< "$domains"


    fi

    echo -e "\n📊 ${COLOR_YELLOW}Cleanup Summary:${CoR}"
    echo -e " • Processed domain groups: ${COLOR_CYAN}$total_groups${CoR}"
    echo -e " • Total duplicates removed: ${COLOR_GREEN}$total_removed${CoR}"
    echo -e " • Note: NPM will handle certificate renewals automatically"
}

################################
# --clean_hosts from_backup_file
# Function to reimport hosts from backup file
# Create a safety backup before major operations
create_safety_backup() {
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    SAFETY_BACKUP="$BACKUP_DIR/pre_reimport_SAFETY_BACKUP_${TIMESTAMP}.json" 
    echo -e "📦 Creating safety backup..."   
    # Get the list of IDs
    local host_ids=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(get_token)" | jq -r '.[].id')
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
            -H "Authorization: Bearer $(get_token)" >> "$SAFETY_BACKUP"
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
# Clean and reset all IDs for hosts and certificates
clean-hosts() {
    echo -e "\n🧹 ${COLOR_YELLOW}Starting complete cleanup and ID reset process...${CoR}"
    echo -e " • 💡 ${COLOR_YELLOW}Tip${CoR}: Use -y flag to skip confirmation\n"
    # 1. Initial checks
    echo -e "\n🔍 ${COLOR_YELLOW}Performing pre-checks...📋${CoR}"
    #  Display summary of hosts to process
    #echo -e "\n📋 ${COLOR_YELLOW}Domains to be processed:${CoR}"
    echo -e "┌─────┬─────────────────────┬────────────────┬───────┬──────────┬───────┬────────┬───────────────┐"
    echo -e "│ ID  │ Domain              │ Forward Host   │ Port  │ Scheme   │ SSL   │ CertID │ Block Exploits│"
    echo -e "├─────┼─────────────────────┼────────────────┼───────┼──────────┼───────┼────────┼───────────────┤"
    
    # Get the list of hosts from the API
    HOSTS_LIST=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(get_token)")
    
    # Use printf for the display with colors
    echo "$HOSTS_LIST" | jq -r '.[] | [
        .id,
        .domain_names[0],
        .forward_host,
        .forward_port,
        .forward_scheme,
        .ssl_forced,
        .certificate_id,
        .block_exploits
    ] | @tsv' | \
    while IFS=$'\t' read -r id domain host port scheme ssl cert_id block; do
        # Validation of the ports and schemes
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "\n❌ ${COLOR_RED}Invalid port number for $domain: $port${CoR}"
            exit 1
        fi
        if ! [[ "$scheme" =~ ^(http|https)$ ]]; then
            echo -e "\n❌ ${COLOR_RED}Invalid scheme for $domain: $scheme${CoR}"
            exit 1
        fi
        
        # Format of the display of the IDs with fixed padding
        if [ "$ssl" = "true" ] && [ -n "$cert_id" ] && [ "$cert_id" != "null" ]; then
            cert_display=$(printf "${COLOR_CYAN}%-6s${CoR}" "$cert_id")
        else
            cert_display=$(printf "%-7s" " ❌")
        fi
        
        # Format of the display of the proxy ID
        id_display=$(printf "${COLOR_YELLOW}%-3s${CoR}" "$id")
        
        printf "│ %-5b │ %-19s │ %-14s │ %-5s │ %-8s │ %-5s │ %-6b │ %-13s │\n" \
            "$id_display" \
            "${domain:0:19}" \
            "${host:0:14}" \
            "${port:0:5}" \
            "${scheme:0:8}" \
            "${ssl:0:5}" \
            "${cert_display}" \
            "${block:0:13}"
    done
    echo -e "└─────┴─────────────────────┴────────────────┴───────┴──────────┴───────┴────────┴───────────────┘"
    # check if NPM is accessible
    if ! curl --output /dev/null --silent --head --fail --connect-timeout 5 "$BASE_URL"; then
        echo -e "\n❌ ${COLOR_RED}ERROR: Cannot connect to NPM${CoR}"
        echo -e "🔍 Please check if NPM is running and accessible at ${COLOR_YELLOW}$BASE_URL${CoR}\n"
        return 1
    fi

    # check if the container is running
    if ! docker ps | grep -q "nginx-proxy-manager"; then
        echo -e "\n❌ ${COLOR_RED}ERROR: NPM container is not running${CoR}"
        return 1
    fi

    # 2. Ask for confirmation
    echo -e "\n⚠️  ${COLOR_YELLOW}This operation will:${CoR}"
    echo -e " • Create a safety backup"
    echo -e " • Clean up duplicate certificates"
    echo -e " • Reset all certificate and proxy IDs to start from 1"
    echo -e " • Reorganize configuration files"
    echo -e "\n⚠️  ${COLOR_RED}This operation cannot be undone!${CoR}"
    
    if [ "$AUTO_YES" != "true" ]; then
        read -r -p "👉 Continue? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "\n❌ Operation cancelled"
            return 1
        fi
    fi

    # 3. Create a safety backup
    echo -e "\n📦 ${COLOR_YELLOW}Creating safety backup...${CoR}"
    if ! create_safety_backup; then
        echo -e "\n❌ ${COLOR_RED}Failed to create safety backup. Aborting.${CoR}"
        return 1
    fi

    # 4. Clean up duplicate certificates
    cleanup_duplicate_certificates

    # 5. Find the paths of the configuration files
    echo -e "\n🔍 ${COLOR_YELLOW}Locating configuration directories...${CoR}"

    CONTAINER_PATH="/data"   
    CONTAINER_PROXY_PATH="/data/nginx/proxy_host"
    CONTAINER_CERT_PATH="/data/letsencrypt/live"

    NGINX_PATH="$NGINX_PATH_DOCKER"
    # Get the real paths of the mounts
    MOUNT_INFO=$(docker inspect nginx-proxy-manager)
    DATA_PATH=$(echo "$MOUNT_INFO" | jq -r '.[].Mounts[] | select(.Destination == "/data") | .Source')

    #LETSENCRYPT_PATH=$(echo "$MOUNT_INFO" | jq -r '.[].Mounts[] | select(.Destination == "/etc/letsencrypt") | .Source')
    #echo -e "\n🔍 ${COLOR_YELLOW}Debug - Detection Mounts:${CoR}"
    echo "$MOUNT_INFO" | jq -r '.[].Mounts[] | "Destination: \(.Destination), Source: \(.Source)"'
    # Check the essential paths
    if [ -z "$CONTAINER_PATH" ]; then
        echo -e "\n❌ ${COLOR_RED}Failed to locate data path${CoR}"
        return 1
    fi
    if [ -z "$CONTAINER_CERT_PATH" ]; then
        echo -e "\n❌ ${COLOR_RED}Failed to locate letsencrypt path${CoR}"
        return 1
    fi

    echo -e "\n📂 ${COLOR_YELLOW}Paths detected:${CoR}"
    #echo -e " • Database: ${COLOR_CYAN}$DB_PATH${CoR}"
    echo -e " • Data path: ${COLOR_CYAN}$DATA_PATH${CoR}"
    echo -e " • Nginx path: ${COLOR_CYAN}$NGINX_PATH${CoR}"
    #echo -e " • Letsencrypt path: ${COLOR_CYAN}$LETSENCRYPT_PATH${CoR}"
    echo -e " • Container data path: ${COLOR_CYAN}$CONTAINER_PATH${CoR}"
    echo -e " • Container proxy path: ${COLOR_CYAN}$CONTAINER_PROXY_PATH${CoR}"
    echo -e " • Container cert path: ${COLOR_CYAN}$CONTAINER_CERT_PATH${CoR}"

    #exit 1
    # 7. Reset the IDs in the database
    echo -e "\n🔄 ${COLOR_YELLOW}Resetting database IDs...${CoR}"
    docker run --rm \
        -v "${DATA_PATH}:${CONTAINER_PATH}" \
        alpine:latest sh -c "
            set -e
            apk add --no-cache sqlite
            cd ${CONTAINER_PATH}
            sqlite3 database.sqlite << 'EOF'
            BEGIN TRANSACTION;

            -- Sauvegarder les associations certificate_id pour chaque proxy_host
            CREATE TEMP TABLE proxy_cert_mapping AS
            SELECT id as proxy_id, certificate_id
            FROM proxy_host;

            -- Reset les IDs des certificats d'abord
            UPDATE certificate SET id = id - (SELECT MAX(id) FROM certificate) + 1;

            -- Mettre à jour les certificate_id dans proxy_host avec les nouveaux IDs
            UPDATE proxy_host
            SET certificate_id = CASE
                WHEN certificate_id > 0 THEN (
                    certificate_id - (SELECT MAX(certificate_id) FROM proxy_cert_mapping) + 1
                )
                ELSE 0  -- Garder 0 pour les entrées sans certificat
            END;

            -- Reset les IDs des proxy_host ensuite
            UPDATE proxy_host SET id = id - (SELECT MAX(id) FROM proxy_host) + 1;

            DROP TABLE proxy_cert_mapping;

            -- Reset les séquences
            DELETE FROM sqlite_sequence WHERE name IN ('proxy_host', 'certificate');
            INSERT INTO sqlite_sequence (name, seq)
            SELECT 'proxy_host', MAX(id) FROM proxy_host
            UNION ALL
            SELECT 'certificate', MAX(id) FROM certificate;

            COMMIT;
            VACUUM;
            PRAGMA wal_checkpoint(FULL);

            -- Afficher le statut
            SELECT '📊 Current Status:';
            SELECT 'Proxy Hosts: ' || COUNT(*) FROM proxy_host;
            SELECT 'Certificates: ' || COUNT(*) FROM certificate;
            SELECT '📊 Updated sequences:';
            SELECT name, seq FROM sqlite_sequence;

            -- Exporter les mappings pour le renommage des fichiers
            .mode csv
            .output '/tmp/cert_mapping.csv'
            SELECT old.id, new.id
            FROM certificate old
            JOIN certificate new ON new.id = old.id - (SELECT MAX(id) FROM certificate) + 1;

            .output '/tmp/proxy_mapping.csv'
            SELECT old.id, new.id
            FROM proxy_host old
            JOIN proxy_host new ON new.id = old.id - (SELECT MAX(id) FROM proxy_host) + 1;
EOF
"

    # 8. Rename the configuration files
    echo -e "\n📁 ${COLOR_YELLOW}Updating configuration files...${CoR}"

    # For the certificates
    echo -e " • ${COLOR_CYAN}Processing certificates...${CoR}"
    docker exec nginx-proxy-manager sh -c "
        while IFS=, read -r old_id new_id; do
            if [ -f '$CONTAINER_CERT_PATH/$old_id.crt' ]; then
                mv '$CONTAINER_CERT_PATH/$old_id.crt' '$CONTAINER_CERT_PATH/$new_id.crt' 2>/dev/null
                mv '$CONTAINER_CERT_PATH/$old_id.key' '$CONTAINER_CERT_PATH/$new_id.key' 2>/dev/null
                echo -e '   ✓ Renamed certificate $old_id → $new_id'
            fi
        done < /tmp/cert_mapping.csv"

    # For the proxy configurations
    echo -e " • ${COLOR_CYAN}Processing proxy configurations...${CoR}"
    docker exec nginx-proxy-manager sh -c "
        while IFS=, read -r old_id new_id; do
            if [ -f '$CONTAINER_PROXY_PATH/$old_id.conf' ]; then
                mv '$CONTAINER_PROXY_PATH/$old_id.conf' '$CONTAINER_PROXY_PATH/$new_id.conf' 2>/dev/null
                echo -e '   ✓ Renamed proxy config $old_id → $new_id'
            fi
        done < /tmp/proxy_mapping.csv"

    # Clean up the temporary files
    docker exec nginx-proxy-manager rm -f /tmp/cert_mapping.csv /tmp/proxy_mapping.csv

    # 9. Restart NPM
    echo -e "\n🔄 ${COLOR_YELLOW}Restarting NPM...${CoR}"
    if docker restart nginx-proxy-manager; then
        echo -e " ✅ ${COLOR_GREEN}NPM restarted successfully${CoR}"
        echo -e " ⏳ Waiting for NPM to be ready..."
        sleep 5

        # Vérification de la configuration nginx
        if docker exec nginx-proxy-manager nginx -t &>/dev/null; then
            echo -e " ✅ ${COLOR_GREEN}Nginx configuration is valid${CoR}"
        else
            echo -e " ⚠️ ${COLOR_YELLOW}Nginx configuration test failed${CoR}"
        fi
    else
        echo -e " ❌ ${COLOR_RED}Failed to restart NPM${CoR}"
        return 1
    fi

    echo -e "\n✨ ${COLOR_GREEN}Cleanup and ID reset completed successfully!${CoR}"
    echo -e "💡 ${COLOR_YELLOW}Note: If you experience any issues, you can restore from the safety backup${CoR}\n"

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


reimport_hosts() {
    local BACKUP_FILE="$1"
    local host_count=$(jq '. | length' "$BACKUP_FILE")


    #  Display summary of hosts to process
    echo -e "\n📋 ${COLOR_YELLOW}Domains to be processed:${CoR}"
    echo -e "┌─────────────────────┬────────────────┬───────┬──────────┬───────┬───────────────┐"
    echo -e "│ Domain              │ Forward Host   │ Port  │ Scheme   │ SSL   │ Block Exploits│"
    echo -e "├─────────────────────┼────────────────┼───────┼──────────┼───────┼───────────────┤"
    
    jq -r '.[] | [.domain_names[0], .forward_host, .forward_port, .forward_scheme, 
           (.certificate.provider == "letsencrypt"), .block_exploits] | @tsv' "$BACKUP_FILE" | \
    while IFS=$'\t' read -r domain host port scheme ssl block; do
        # Validate port and scheme while displaying
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "\n❌ ${COLOR_RED}Invalid port number for $domain: $port${CoR}"
            exit 1
        fi
        if ! [[ "$scheme" =~ ^(http|https)$ ]]; then
            echo -e "\n❌ ${COLOR_RED}Invalid scheme for $domain: $scheme${CoR}"
            exit 1
        fi
        printf "│ %-19s │ %-14s │ %-5s │ %-8s │ %-5s │ %-13s │\n" \
            "${domain:0:19}" "${host:0:14}" "${port:0:5}" "${scheme:0:8}" "${ssl:0:5}" "${block:0:13}"
    done
    echo -e "└─────────────────────┴────────────────┴───────┴──────────┴───────┴───────────────┘"

    #  User confirmation
    if [ "$AUTO_YES" != "true" ]; then
        echo -e "\n⚠️  ${COLOR_YELLOW}Operation can't be undone, but you can restore from safety backup created automatically.${CoR}"
        echo -e " • Delete ALL existing proxy hosts"
        echo -e " • Reimport $host_count hosts from backup"
        echo -e " • Reset all proxy host IDs to start from 1"
        echo -e " • ${COLOR_GREEN}All other settings (access lists, users, etc.) will be preserved.${CoR}\n"
        echo -e "📂 Using backup file: ${COLOR_GREEN}$BACKUP_FILE${CoR}\n"        
        echo -e "Drink 🍵 or coffee and relax, this may take a while..."
        read -r -p "👉 Continue? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "\n ❌ Operation cancelled"
            exit 1
        fi
    fi

    echo -e "\n🔄 ${COLOR_YELLOW}Starting ID sequence reset process...${CoR}"

    # 1. Create safety backup
    create_safety_backup
    # add velidation from user to continue
    echo -e "\n🔄 ${COLOR_YELLOW}backup created, continue? (y/N): " -r
    read -r -p "👉 Continue? (y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "\n ❌ Operation cancelled"
        exit 1
    fi

    # 2. Reset IDs while preserving relationships
    #reimport_hosts_reset_id_sequences

    # 3. Restart NPM to apply changes
    echo -e -n "🔄 Restarting Nginx Proxy Manager..."
    if docker restart nginx-proxy-manager; then
        echo -e " ✅ ${COLOR_GREEN}NPM container restarted${CoR}"
        echo -e " ⏳ Waiting for NPM to be ready..."
        sleep 5
        
        # 4. Validate nginx configuration
        echo -e "\n🔍 Validating nginx configuration..."
        if docker exec nginx-proxy-manager nginx -t &>/dev/null; then
            echo -e " ✅ ${COLOR_GREEN}Nginx configuration is valid${CoR}"
        else
            echo -e " ⚠️ ${COLOR_YELLOW}Nginx configuration test failed${CoR}"
        fi
    else
        echo -e " ❌ ${COLOR_RED}Failed to restart NPM container${CoR}"
        return 1
    fi

    echo -e "\n✨ ${COLOR_GREEN}ID sequence reset completed successfully${CoR}"
    return 0
}

################################
# Delete a proxy host by ID
# Function to delete a proxy host
host_delete() {

    echo "DEBUG: AUTO_YES=$AUTO_YES"
    if [ "$AUTO_YES" = true ]; then
        echo -e "\n 🔔 Auto-confirming deletion due to -y option..."
    else
        if ! confirm_dangerous_operation "delete proxy host" "$HOST_ID"; then
            return 1
        fi
    fi

    echo -e "\n 🗑️ Deleting proxy host ID: $HOST_ID..."
    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE \
        "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
        -H "Authorization: Bearer $(get_token)")

    HTTP_BODY=${RESPONSE//HTTPSTATUS:*/}
    HTTP_STATUS=${RESPONSE##*HTTPSTATUS:}

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e " ✅ ${COLOR_GREEN}Proxy host $HOST_ID deleted successfully!${CoR}\n"
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete proxy host. Status: $HTTP_STATUS. Error: $HTTP_BODY${CoR}\n"
        return 1
    fi
}


################################
# Update an existing proxy host
update_proxy_host() {
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
  -H "Authorization: Bearer $(get_token)" \
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
host-update() {
  HOST_ID="$1"
  FIELD="$2"
  NEW_VALUE="$3"

  # ✅ 1) Check if the three arguments are passed
  if [ -z "$HOST_ID" ] || [ -z "$FIELD" ] || [ -z "$NEW_VALUE" ]; then
      echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing required parameters${CoR}"
      echo -e " Usage: ${COLOR_ORANGE}$0 --host-update <host_id> <field=value>${CoR}"
    exit 1
  fi

  # ✅ 2) Get the complete proxy config from the API
  CURRENT_DATA=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(get_token)")

  # Check if it is valid
  if ! echo "$CURRENT_DATA" | jq empty > /dev/null 2>&1; then
    echo -e "  ⛔ ${COLOR_RED}ERROR:${CoR} Failed to fetch current proxy configuration."
    exit 1
  fi

  # ✅ 3) Filter allowed fields by API (whitelist)
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

  # ✅ 4)  Modify ONE field in the filtered object
  #     Some fields (like forward_port) must be converted to a number
  if [ "$FIELD" = "forward_port" ]; then
    # If it's forward_port, force it to a number
    UPDATED_DATA=$(echo "$FILTERED_DATA" \
      | jq --argjson newVal "$(echo "$NEW_VALUE" | jq -R 'tonumber? // 0')" \
           '.forward_port = $newVal')
  else
    # Otherwise, treat the new value as a string
    UPDATED_DATA=$(echo "$FILTERED_DATA" \
      | jq --arg newVal "$NEW_VALUE" \
           ".$FIELD = \$newVal")
  fi

  # Check if the final JSON is valid
  if ! echo "$UPDATED_DATA" | jq empty > /dev/null 2>&1; then
    echo -e "  ⛔ ${COLOR_RED}ERROR: Invalid JSON generated:${CoR}\n$UPDATED_DATA"
    exit 1
  fi

  # ✅ 5) Send the update via API (PUT)
  echo -e "\n 🔄 Updating proxy host ${COLOR_ORANGE}🆔${CoR} ${COLOR_YELLOW}$HOST_ID${CoR} with ${COLOR_ORANGE}$FIELD${CoR} ${COLOR_YELLOW}$NEW_VALUE${CoR}"
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(get_token)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$UPDATED_DATA")

  # ✅ 6) Check API response
  ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // empty')
  if [ -z "$ERROR_MSG" ]; then
    echo -e "\n ✅ ${COLOR_GREEN}SUCCESS:${CoR} Proxy host 🆔 $HOST_ID  updated successfully! 🎉"
  else
    echo -e "\n ⛔ ${COLOR_RED}Failed to update proxy host. Error:${CoR} $ERROR_MSG"
    exit 1
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

# List all proxy hosts with basic details, including SSL certificate status and associated domain
host_list() {
  echo -e "\n${COLOR_ORANGE} 👉 List of proxy hosts (simple)${CoR}"
  printf "  %-6s %-36s %-9s %-4s %-36s\n" "ID" "Domain" "Status" "SSL" "Certificate Domain"

  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(get_token)")

  # Clean the response to remove control characters
  CLEANED_RESPONSE=$(echo "$RESPONSE" | tr -d '\000-\031')

  echo "$CLEANED_RESPONSE" | jq -r '.[] | "\(.id) \(.domain_names | join(", ")) \(.enabled) \(.certificate_id)"' | while read -r id domain enabled certificate_id; do
		if [ "$enabled" = "true" ]; then
  		status="$(echo -e "${WHITE_ON_GREEN} enabled ${CoR}")"
		else
  		status="$(echo -e "${COLOR_RED} disable ${CoR}")"
		fi

#    if [ "$enabled" -eq 1 ]; then
#      status="$(echo -e "${WHITE_ON_GREEN} enabled ${CoR}")"
#    else
#      status="$(echo -e "${COLOR_RED} disable ${CoR}")"
#    fi

    # Default SSL status
    ssl_status="✘"
    cert_domain=""

    # Check if a valid certificate ID is present and not null
    if [ "$certificate_id" != "null" ] && [ -n "$certificate_id" ]; then
      # Fetch the certificate details using the certificate_id
      CERT_DETAILS=$(curl -s -X GET "$BASE_URL/nginx/certificates/$certificate_id" \
      -H "Authorization: Bearer $(get_token)")

      # Check if the certificate details are valid and domain_names is not null
      if [ "$(echo "$CERT_DETAILS" | jq -r '.domain_names')" != "null" ]; then
        cert_domain=$(echo "$CERT_DETAILS" | jq -r '.domain_names | join(", ")')
        ssl_status="✅"
      else
        ssl_status="✘"  # If no valid certificate domain is found
        cert_domain=""
      fi
    fi

    # Print the row with colors and certificate domain (if available)
    printf "  ${COLOR_YELLOW}%6s${CoR} ${COLOR_GREEN}%-36s${CoR} %-8s %-4s %-36s\n" \
      "$(pad "$id" 6)" "$(pad "$domain" 36)" "$status" "$ssl_status" "$cert_domain"
  done
  echo ""
  exit 0
}

################################
# Search for a proxy host by domain name
host_search() {
  if [ -z "$HOST_SEARCHNAME" ]; then
    echo " 🔍 The --host-search option requires a domain name."
    help
  fi
  echo -e "\n 🔍 Searching for proxy host for $HOST_SEARCHNAME..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(get_token)")

  echo "$RESPONSE" | jq -c --arg search "$HOST_SEARCHNAME" '.[] | select(.domain_names[] | contains($search))' | while IFS= read -r line; do
    id=$(echo "$line" | jq -r '.id')
    domain_names=$(echo "$line" | jq -r '.domain_names[]')

    echo -e " 🔎 id: ${COLOR_YELLOW}$id${CoR} ${COLOR_GREEN}$domain_names${CoR}"
  done
	echo ""
}

################################
# Function to list all SSL certificates or filter by domain
list_ssl_cert() {
  # Regex to validate domain or subdomain
  DOMAIN_REGEX="^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
  if [ -n "$DOMAIN" ]; then
    # Validate domain format
    if [[ ! "$DOMAIN" =~ $DOMAIN_REGEX ]]; then
      echo " ⛔ Invalid domain format: $DOMAIN"
      exit 1
    fi
    echo " 👉 Listing SSL certificates for domain: $DOMAIN..."
    # Fetch all certificates
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(get_token)")
    # Filter certificates by nice_name
    CERTS_FOR_DOMAIN=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN" \
      '.[] | select(.nice_name == $DOMAIN) | {id: .id, provider: .provider, nice_name: .nice_name, domain_names: .domain_names, valid_from: .valid_from, valid_to: .valid_to}')

    if [ -z "$CERTS_FOR_DOMAIN" ]; then
      echo " ⛔ No SSL certificates found for domain: $DOMAIN"
    else
      echo " ✅ SSL certificates found for domain: $DOMAIN"
      echo "$CERTS_FOR_DOMAIN" | jq  # Display the filtered certificates
    fi
  else
    echo " 👉 Listing all SSL certificates..."

    # Fetch all certificates
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(get_token)")
    # List all certificates
    echo "$RESPONSE" | jq
  fi
}

################################
# List all users
list_users() {
  echo -e "\n 👉 List of users..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(get_token)")
  echo -e "\n $RESPONSE" | jq
  exit 0
}

################################
# Create a new user
create_user() {
  if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$EMAIL" ]; then
    echo -e "\n 👤 ${COLOR_RED}The --create-user option requires username, password, and email.${CoR}"
    echo -e " Usage: ${COLOR_ORANGE}$0 --create-user username password email${CoR}"
    echo -e " Example:"
    echo -e "   ${COLOR_GREEN}$0 --create-user john secretpass john@domain.com${CoR}\n"
    return 1
  fi
  # check if user already exists
  EXISTING_USERS=$(curl -s -X GET "$BASE_URL/users" \
      -H "Authorization: Bearer $(get_token)") 
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
        -H "Authorization: Bearer $(get_token)" \
        -H "Content-Type: application/json; charset=UTF-8" \
        --data-raw "$DATA")

    HTTP_BODY=${RESPONSE//HTTPSTATUS:*/}
    HTTP_STATUS=${RESPONSE##*HTTPSTATUS:}

    if [ "$HTTP_STATUS" -eq 201 ]; then
        # debug
        echo "Debug response: $HTTP_BODY" >> /tmp/npm_debug.log

        # get user id
        USERS_RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
            -H "Authorization: Bearer $(get_token)")
        
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
# Update delete_user function to use ID instead of username
delete_user() {
    local user_id="$1"
    if [ -z "$user_id" ]; then
        echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing argument${CoR}"
        echo -e " Usage: ${COLOR_ORANGE}$0 --delete-user <user_id>${CoR}"
        echo -e " To find user IDs, use: ${COLOR_ORANGE}$0 --list-users${CoR}\n"
        exit 1
    fi

    if [ "$AUTO_YES" = true ]; then
        echo -e "\n 🔔 Auto-confirming user deletion due to -y option..."
    else
        if ! confirm_dangerous_operation "delete user" "$user_id"; then
            return 1
        fi
    fi

    echo -e "\n🗑️ Deleting user ID: $user_id..."
    local response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE \
        "$BASE_URL/users/$user_id" \
        -H "Authorization: Bearer $(get_token)")

    local http_body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
    local http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    if [ "$http_status" -eq 200 ]; then
        echo -e " ✅ ${COLOR_GREEN}User deleted successfully!${CoR}\n"
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete user. Status: $http_status${CoR}"
        if [ -n "$http_body" ]; then
            echo -e " Response: $http_body"
        fi
        exit 1
    fi
}

################################
# Enable a proxy host by ID
host_enable() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 💣 The --host-enable option requires a host ID."
    help
  fi
  # Validate that HOST_ID is a number
  if ! [[ "$HOST_ID" =~ ^[0-9]+$ ]]; then
    echo -e " ⛔ ${COLOR_RED}Invalid host ID: $HOST_ID. It must be a numeric value.${CoR}\n"
    exit 1
  fi
  echo -e "\n ✅ Enabling 🌐 proxy host ID: $HOST_ID..."

  # Check if the proxy host exists before enabling
  CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(get_token)")

  if echo "$CHECK_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    # Proxy host exists, proceed to enable
    DATA=$(echo "$CHECK_RESPONSE" | jq '{enabled: 1}')

    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(get_token)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

    # Extract the body and the status
    HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
    HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

    if [ "$HTTP_STATUS" -eq 200 ]; then
      echo -e " ✅ ${COLOR_GREEN}Proxy host enabled successfully!${CoR}\n"
    else
      echo -e " ⛔ ${COLOR_RED}Failed to enable proxy host. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
    fi
  else
    echo -e " ⛔ ${COLOR_RED}Proxy host with ID $HOST_ID does not exist.${CoR}\n"
  fi
}

################################
# Disable a proxy host by ID
host_disable() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n ❌ The --host-disable option requires a host ID."
    help
  fi
  echo -e "\n ❌ Disabling 🌐 proxy host ID: $HOST_ID..."

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/proxy-hosts/$HOST_ID/disable" \
  -H "Authorization: Bearer $(get_token)" \
  -H "Content-Type: application/json")

  # Extract the body and the status
  HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
  HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e " ✅ ${COLOR_GREEN}Proxy host disabled successfully!${CoR}\n"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to disable proxy host. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
  fi
}

################################
# Delete a certificate in NPM
delete_certificate() {
    if [ -z "$DOMAIN" ]; then
        echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing argument${CoR}"
        echo -e " Usage: ${COLOR_ORANGE}$0 --delete-cert <domain>${CoR}"
        echo -e " To list certificates, use: ${COLOR_ORANGE}$0 --list-certificates <domain>${CoR}\n"
        exit 1
    fi

    echo -e "\n 👀 Checking if certificate for domain: $DOMAIN exists..."

    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(get_token)")

    EXISTING_CERT=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN" '.[] | select(.domain_names[] == $DOMAIN)')

    if [ -z "$EXISTING_CERT" ]; then
        echo -e " ⛔ No certificate found for domain: $DOMAIN. \n"
        exit 0
    fi

  if [ "$AUTO_YES" = true ]; then
    echo -e "🔔 The -y option was provided. Skipping confirmation prompt and proceeding with certificate creation..."
    CONFIRM="y"
  else
    read -p "⚠️ Are you sure you want to delete the certificate for $DOMAIN? (y/n): " CONFIRM
  fi

    CERTIFICATE_ID=$(echo "$EXISTING_CERT" | jq -r '.id')
    EXPIRES_ON=$(echo "$EXISTING_CERT" | jq -r '.expires_on')
    PROVIDER=$(echo "$EXISTING_CERT" | jq -r '.provider')

    echo -e " ✅ Certificate found for $DOMAIN (Provider: $PROVIDER, Expires on: $EXPIRES_ON)."
    echo -e " 🗑️ Deleting certificate for domain: $DOMAIN..."

    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE \
        "$BASE_URL/nginx/certificates/$CERTIFICATE_ID" \
        -H "Authorization: Bearer $(get_token)")

    HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
    HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

    if [ "$HTTP_STATUS" -eq 204 ] || { [ "$HTTP_STATUS" -eq 200 ] && [ "$HTTP_BODY" == "true" ]; }; then
        echo -e " ✅ ${COLOR_GREEN}Certificate deleted successfully!${CoR}\n"
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete certificate. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
        return 1
    fi
}

################################
# Generate Let's Encrypt certificate if not exists
generate_certificate() {
  if [ -z "$DOMAIN" ]; then
    echo -e "\n 🛡️ The --generate-cert option requires a domain."
    echo -e " Usage: ${COLOR_ORANGE}$0 --generate-cert domain [email] [dns-provider provider dns-api-key key]${CoR}"
    echo -e " Note: If email is not provided, default email ${COLOR_YELLOW}$DEFAULT_EMAIL${CoR} will be used"
    echo -e " For wildcard certificates (*.domain.com), DNS challenge is required\n"
    echo -e " Examples:"
    echo -e "   ${COLOR_GREEN}$0 --generate-cert example.com admin@example.com${CoR}"
    echo -e "   ${COLOR_GREEN}$0 --generate-cert *.example.com admin@example.com dns-provider dynu dns-api-key YOUR_API_KEY${CoR}\n"
    exit 1
  fi

  # Use default email if none provided
  if [ -z "$EMAIL" ]; then
    EMAIL="$DEFAULT_EMAIL"
    echo -e "\n 📧 Using default email: ${COLOR_YELLOW}$EMAIL${CoR}"
  fi

  # Check if this is a wildcard certificate and validate DNS requirements
  if [[ "$DOMAIN" == \** ]]; then
    if [ -z "$DNS_PROVIDER" ] || [ -z "$DNS_API_KEY" ]; then
      echo -e "\n ⛔ ${COLOR_RED}Wildcard certificates require DNS challenge. Please provide dns-provider and dns-api-key.${CoR}"
      echo -e " Example: ${COLOR_GREEN}$0 --generate-cert *.example.com admin@example.com dns-provider dynu dns-api-key YOUR_API_KEY${CoR}\n"
      echo -e " Supported DNS providers: dynu, cloudflare, digitalocean, godaddy, namecheap, route53\n"
      exit 1
    fi
  fi

  echo -e "\n 👀 Checking existing certificates for domain: $DOMAIN..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(get_token)")
  
  # Check for exact match and wildcard matches
  EXISTING_CERT=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN" \
    '.[] | select(
      (.domain_names[] == $DOMAIN) or
      (.domain_names[] | startswith("*.") and ($DOMAIN | endswith(.[2:]))) or
      ($DOMAIN | startswith("*.") and (.domain_names[] | endswith(.[2:])))
    )')

  if [ -n "$EXISTING_CERT" ] && ! $FORCE_CERT_CREATION; then
    EXPIRES_ON=$(echo "$EXISTING_CERT" | jq -r '.expires_on')
    # Check if certificate is expired or expires soon (30 days)
    EXPIRY_DATE=$(date -d "$EXPIRES_ON" +%s)
    CURRENT_DATE=$(date +%s)
    DAYS_UNTIL_EXPIRY=$(( ($EXPIRY_DATE - $CURRENT_DATE) / 86400 ))
    
    if [ $DAYS_UNTIL_EXPIRY -gt 30 ]; then
      echo -e " 🔔 Valid certificate found for $DOMAIN (expires in $DAYS_UNTIL_EXPIRY days: $EXPIRES_ON).\n"
      exit 0
    else
      echo -e " ⚠️ Certificate expires soon or is expired (in $DAYS_UNTIL_EXPIRY days: $EXPIRES_ON)."
    fi
  fi

  # Ask for confirmation before creating a new certificate
  if [ "$AUTO_YES" = true ]; then
    echo -e "🔔 The -y option was provided. Skipping confirmation prompt and proceeding with certificate creation..."
    CONFIRM="y"
  else
    if [ -n "$EXISTING_CERT" ]; then
      read -r -p "⚠️ Do you want to renew the existing certificate for $DOMAIN? (y/n): " CONFIRM
    else
      read -r -p "⚠️ No existing certificate found for $DOMAIN. Create new Let's Encrypt certificate? (y/n): " CONFIRM
    fi
  fi

  if [[ "$CONFIRM" != "y" ]]; then
    echo -e " ❌ Certificate creation aborted."
    exit 0
  fi

  echo -e " ⚙️ Generating Let's Encrypt certificate for domain: $DOMAIN..."

  # Prepare the meta object based on whether DNS challenge is requested
  local meta_json="{}"
  if [ -n "$DNS_PROVIDER" ] && [ -n "$DNS_API_KEY" ]; then
    echo -e " 🔑 Using DNS challenge with provider: ${COLOR_YELLOW}$DNS_PROVIDER${CoR}"
    meta_json=$(jq -n \
      --arg provider "$DNS_PROVIDER" \
      --arg key "$DNS_API_KEY" \
      --arg email "$EMAIL" \
      --argjson agree true \
      '{
        dns_challenge: true,
        dns_provider: $provider,
        dns_provider_credentials: {
          api_key: $key
        },
        letsencrypt_agree: $agree,
        letsencrypt_email: $email,
        propagation_seconds: 60,
        dns_challenge_timeout: 120
      }')
  else
    meta_json=$(jq -n \
      --arg email "$EMAIL" \
      --argjson agree true \
      '{
        letsencrypt_agree: $agree,
        letsencrypt_email: $email
      }')
  fi

  # Create the full request data
  DATA=$(jq -n \
    --arg domain "$DOMAIN" \
    --argjson meta "$meta_json" \
    '{
      provider: "letsencrypt",
      domain_names: [$domain],
      meta: $meta
    }')

  echo -e "\n 🔔 ${COLOR_YELLOW}Initiating certificate generation...${CoR}"
  echo -e " This may take a few minutes, especially for DNS challenges."
  echo -e " Data being sent: $DATA"

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(get_token)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

  HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
  HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}
  if [ "$HTTP_STATUS" -eq 201 ]; then
    echo -e " ✅ ${COLOR_GREEN}Certificate generated successfully!${CoR}"
    # Get the certificate ID from the response
    CERT_ID=$(echo "$HTTP_BODY" | jq -r '.id')
    echo -e " 📝 Certificate ID: ${COLOR_YELLOW}$CERT_ID${CoR}"
    echo -e " 📅 Expires on: ${COLOR_YELLOW}$(echo "$HTTP_BODY" | jq -r '.expires_on')${CoR}\n"
  else
    echo -e "\n ⛔ ${COLOR_RED}Failed to generate certificate. HTTP status: $HTTP_STATUS${CoR}"
    ERROR_MSG=$(echo "$HTTP_BODY" | jq -r '.error.message // "Unknown error"')
    echo -e " Error: ${COLOR_RED}$ERROR_MSG${CoR}"
    
    if [ -n "$DNS_PROVIDER" ]; then
      echo -e "\n 🔍 Troubleshooting DNS challenge:"
      echo -e " • Verify DNS provider credentials"
      echo -e " • Check if DNS provider ($DNS_PROVIDER) is supported"
      echo -e " • Allow time for DNS propagation (up to 24 hours)"
      echo -e " • Verify DNS records for $DOMAIN"
      echo -e " • Check if domain is properly configured\n"
    else
      echo -e "\n 🔍 Troubleshooting HTTP challenge:"
      echo -e " • Verify domain points to correct IP"
      echo -e " • Check if port 80 is accessible"
      echo -e " • Verify domain configuration"
      echo -e " • Check for firewall rules\n"
    fi
  fi
}

################################
# Enable SSL for a proxy host
enable_ssl() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 🛡️ The --host-ssl-enable option requires a host ID."
    echo -e " Usage: ${COLOR_ORANGE}$0 --host-ssl-enable <host_id> [cert_id]${CoR}"
    echo -e " Note: If cert_id is not provided, will try to find or create a matching certificate"
    echo -e " To list available certificates, use: ${COLOR_ORANGE}$0 --list-ssl-cert${CoR}\n"
    exit 1
  fi

  # Validate that HOST_ID is a number
  if ! [[ "$HOST_ID" =~ ^[0-9]+$ ]]; then
    echo -e " ⛔ ${COLOR_RED}Invalid host ID: $HOST_ID. It must be a numeric value.${CoR}\n"
    exit 1
  fi

  echo -e "\n ✅ Enabling 🔒 SSL, HTTP/2, and HSTS for proxy host ID: $HOST_ID..."

  # Check host details
  CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(get_token)")
  
  if ! echo "$CHECK_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    echo -e " ⛔ ${COLOR_RED}Host ID $HOST_ID not found.${CoR}\n"
    exit 1
  fi

  DOMAIN_NAMES=$(echo "$CHECK_RESPONSE" | jq -r '.domain_names[]')

  # If a specific certificate ID was provided, use it
  if [ -n "$CERTIFICATE_ID" ]; then
    echo -e " 🔍 Using specified certificate ID: ${COLOR_YELLOW}$CERTIFICATE_ID${CoR}"
    
    # Verify the certificate exists
    CERT_CHECK=$(curl -s -X GET "$BASE_URL/nginx/certificates/$CERTIFICATE_ID" \
    -H "Authorization: Bearer $(get_token)")
    
    if ! echo "$CERT_CHECK" | jq -e '.id' > /dev/null 2>&1; then
      echo -e " ⛔ ${COLOR_RED}Certificate ID $CERTIFICATE_ID not found.${CoR}"
      echo -e " Use ${COLOR_ORANGE}$0 --list-ssl-cert${CoR} to list available certificates.\n"
      exit 1
    fi
  else
    # Fetch all certificates
    CERTIFICATES=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(get_token)")
    
    # Find matching certificates (including wildcards)
    DOMAIN_CERTS=$(echo "$CERTIFICATES" | jq -c --arg domain "$DOMAIN_NAMES" \
      '[.[] | select(
        (.domain_names[] == $domain) or
        (.domain_names[] | startswith("*.") and ($domain | endswith(.[2:])))
      )]')
    
    CERT_COUNT=$(echo "$DOMAIN_CERTS" | jq 'length')
    CERT_COUNT=${CERT_COUNT:-0}

    if [ "$CERT_COUNT" -eq 0 ]; then
      echo -e " ⛔ No matching certificates found for $DOMAIN_NAMES"
      if [ "$AUTO_YES" = true ]; then
        echo -e "🔔 The -y option was provided. Proceeding with certificate creation..."
        CONFIRM_CREATE="y"
      else
        read -r -p "⚠️ Do you want to create a new Let's Encrypt certificate? (y/n): " CONFIRM_CREATE
      fi
      if [[ "$CONFIRM_CREATE" == "y" ]]; then
        if [[ "$DOMAIN_NAMES" == \** ]]; then
          echo -e " ⛔ ${COLOR_RED}Wildcard certificates require manual DNS challenge setup.${CoR}"
          echo -e " Please create the certificate first using:"
          echo -e " ${COLOR_GREEN}$0 --generate-cert $DOMAIN_NAMES your@email.com dns-provider YOUR_PROVIDER dns-api-key YOUR_KEY${CoR}\n"
          exit 1
        fi
        DOMAIN="$DOMAIN_NAMES"
        generate_certificate
        if [ -n "$CERT_ID" ]; then
          CERTIFICATE_ID="$CERT_ID"
        else
          return
        fi
      else
        echo -e " ❌ Certificate creation aborted. Exiting."
        exit 1
      fi
    elif [ "$CERT_COUNT" -gt 1 ]; then
      echo -e " ℹ️ Multiple certificates found that could match $DOMAIN_NAMES:"
      echo "$DOMAIN_CERTS" | jq -r '.[] | "  ID: \(.id), Domains: \(.domain_names | join(", ")), Provider: \(.provider), Expires: \(.expires_on)"'
      read -r -p "Enter the ID of the certificate you want to use: " CERTIFICATE_ID
    else
      CERTIFICATE_ID=$(echo "$DOMAIN_CERTS" | jq -r '.[0].id')
      CERT_INFO=$(echo "$DOMAIN_CERTS" | jq -r '.[0] | "ID: \(.id), Domains: \(.domain_names | join(", ")), Provider: \(.provider), Expires: \(.expires_on)"')
      echo -e " ✅ Using certificate: ${COLOR_GREEN}$CERT_INFO${CoR}"
    fi
  fi

  # Update the host with SSL enabled
  DATA=$(jq -n --arg cert_id "$CERTIFICATE_ID" '{
    certificate_id: $cert_id,
    ssl_forced: true,
    http2_support: true,
    hsts_enabled: true,
    hsts_subdomains: false
  }')

  echo -e "\n Data being sent for SSL enablement: $DATA"
  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(get_token)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
  HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}
  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e "\n ✅ ${COLOR_GREEN}SSL enabled successfully!${CoR}"
    echo -e " • Certificate ID: ${COLOR_YELLOW}$CERTIFICATE_ID${CoR}"
    echo -e " • HTTP/2: ${COLOR_GREEN}enabled${CoR}"
    echo -e " • HSTS: ${COLOR_GREEN}enabled${CoR}\n"
  else
    echo -e "\n ⛔ ${COLOR_RED}Failed to enable SSL. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
  fi
}

################################
# list_certificates function
list_certificates() {
  if [ -z "$DOMAIN" ]; then
    echo -e "\n 🌐 The --list-certificates option requires a domain name."
    help
  fi
  echo -e "\n 📜 Listing all certificates for domain: $DOMAIN..."

  # Fetch all certificates (custom and Let's Encrypt)
  CERTIFICATES=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(get_token)")
  # Find all certificates for the given domain
  DOMAIN_CERTS=$(echo "$CERTIFICATES" | jq -r --arg domain "$DOMAIN" \
    '.[] | select(.domain_names[] == $domain) | {id: .id, provider: .provider, valid_from: .valid_from, valid_to: .valid_to}')
  CERT_COUNT=$(echo "$DOMAIN_CERTS" | jq length)
  if [ "$CERT_COUNT" -eq 0 ]; then
    echo " ⛔ No certificates found for domain: $DOMAIN."
  else
    echo " ✅ Certificates found for domain $DOMAIN:"
    # Display the certificates with provider and validity dates
    echo "$DOMAIN_CERTS" | jq -r '. | "ID: \(.id), Provider: \(.provider), Valid From: \(.valid_from), Valid To: \(.valid_to)"'
  fi
}

################################  
# disable_ssl
# Function to disable SSL for a proxy host
disable_ssl() {
    if [ -z "$HOST_ID" ]; then
        echo -e "\n ⛔ ${COLOR_RED}INVALID command: Missing argument${CoR}"
        echo -e " Usage: ${COLOR_ORANGE}$0 --host-ssl-disable <host_id>${CoR}"
        echo -e " To find host IDs, use: ${COLOR_ORANGE}$0 --host-list${CoR}\n"
        exit 1
    fi

    echo -e "\n 🚫 Disabling 🔓 SSL for proxy host ID: $HOST_ID..."

    CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(get_token)")

    if echo "$CHECK_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
        DATA=$(jq -n --argjson cert_id null '{
            certificate_id: $cert_id,
            ssl_forced: false,
            http2_support: false,
            hsts_enabled: false,
            hsts_subdomains: false
        }')

        HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
        -H "Authorization: Bearer $(get_token)" \
        -H "Content-Type: application/json; charset=UTF-8" \
        --data-raw "$DATA")

        HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
        HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

        if [ "$HTTP_STATUS" -eq 200 ]; then
            echo -e " ✅ ${COLOR_GREEN}SSL disabled successfully!${CoR}\n"
        else
            echo " Data sent: $DATA"  # Log the data sent
            echo -e " ⛔ ${COLOR_RED}Failed to disable SSL. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
        fi
    else
        echo -e " ⛔ ${COLOR_RED}Proxy host with ID $HOST_ID does not exist.${CoR}\n"
    fi
}

################################
# ACL  proxy host 
host_acl_enable() {
  if [ -z "$HOST_ID" ] || [ -z "$ACCESS_LIST_ID" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Error: HOST_ID and ACCESS_LIST_ID are required to enable the ACL.${CoR}"
    help
  fi
  echo -e " 🔓 Enabling ACL for host ID: $HOST_ID with access list ID: $ACCESS_LIST_ID..."

  DATA=$(jq -n \
    --argjson access_list_id "$ACCESS_LIST_ID" \
    --argjson enabled true \
    '{
      access_list_id: $access_list_id,
      enabled: $enabled
    }')

  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(get_token)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

  if [ "$(echo "$RESPONSE" | jq -r '.error | length')" -eq 0 ]; then
    echo -e " ✅ ${COLOR_GREEN}ACL successfully enabled for host ID $HOST_ID!${CoR}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to enable ACL. Error: $(echo "$RESPONSE" | jq -r '.message')${CoR}\n"
  fi
}

################################
# Disable ACL for a given proxy host
host_acl_disable() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Error: HOST_ID is required to disable the ACL.${CoR}"
    help
  fi
  echo -e " 🔒 Disabling ACL for host ID: $HOST_ID..."
  DATA=$(jq -n \
    --argjson access_list_id null \
    --argjson enabled false \
    '{
      access_list_id: $access_list_id,
      enabled: $enabled
    }')
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(get_token)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")
  if [ "$(echo "$RESPONSE" | jq -r '.error | length')" -eq 0 ]; then
    echo -e " ✅ ${COLOR_GREEN}ACL successfully disabled for host ID $HOST_ID!${CoR}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to disable ACL. Error: $(echo "$RESPONSE" | jq -r '.message')${CoR}\n"
  fi
}

################################
# Show details of a specific proxy host
host_show() {
    local host_id="$1"

    if [ -z "$host_id" ]; then
        echo -e "\n ⛔ ${COLOR_RED}The --host-show option requires a host ID.${CoR}"
        echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
        return 1
    fi

    echo -e "\n 🔍 Fetching details for proxy host ID: ${COLOR_YELLOW}$host_id${CoR}..."
    # get host details
    local response=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id" \
        -H "Authorization: Bearer $(get_token)")
    # Check if the response contains an error
    if echo "$response" | jq -e '.error' >/dev/null; then
        echo -e " ⛔ ${COLOR_RED}Error: $(echo "$response" | jq -r '.error.message')${CoR}\n"
        return 1
    fi
    # Formater et afficher les détails
    echo -e "\n📋 ${COLOR_YELLOW}Host Details:${CoR}"
    echo -e "┌───────────────────────────────────"
    # ID and Domains
    echo -e "│ 🆔 ID: ${COLOR_YELLOW}$(echo "$response" | jq -r '.id')${CoR}"
    echo -e "│ 🌐 Domains: ${COLOR_GREEN}$(echo "$response" | jq -r '.domain_names[]')${CoR}"
    # Forward Configuration
    echo -e "│ 🔄 Forward Configuration:"
    echo -e "│   • Host: ${COLOR_YELLOW}$(echo "$response" | jq -r '.forward_host')${CoR}"
    echo -e "│   • Port: ${COLOR_YELLOW}$(echo "$response" | jq -r '.forward_port')${CoR}"
    echo -e "│   • Scheme: ${COLOR_YELLOW}$(echo "$response" | jq -r '.forward_scheme')${CoR}"

    # Status
    local enabled=$(echo "$response" | jq -r '.enabled')
    if [ "$enabled" = "true" ]; then
        echo -e "│ ✅ Status: ${COLOR_GREEN}Enabled${CoR}"
    else
        echo -e "│ ❌ Status: ${COLOR_RED}Disabled${CoR}"
    fi
    # SSL Configuration
    local cert_id=$(echo "$response" | jq -r '.certificate_id')
    if [ "$cert_id" != "null" ]; then
        echo -e "│ 🔒 SSL Configuration:"
        echo -e "│    • Certificate ID: ${COLOR_YELLOW}$cert_id${CoR}"
        echo -e "│    • SSL Forced: ${COLOR_YELLOW}$(echo "$response" | jq -r '.ssl_forced')${CoR}"
        echo -e "│    • HTTP/2: ${COLOR_YELLOW}$(echo "$response" | jq -r '.http2_support')${CoR}"
        echo -e "│    • HSTS: ${COLOR_YELLOW}$(echo "$response" | jq -r '.hsts_enabled')${CoR}"
    else
        echo -e "│ 🔓 SSL: ${COLOR_RED}Not configured${CoR}"
    fi
    # Features
    echo -e "│ 🛠️ Features:"
    echo -e "│    • Block Exploits: ${COLOR_YELLOW}$(echo "$response" | jq -r '.block_exploits')${CoR}"
    echo -e "│    • Caching: ${COLOR_YELLOW}$(echo "$response" | jq -r '.caching_enabled')${CoR}"
    echo -e "│    • Websocket Upgrade: ${COLOR_YELLOW}$(echo "$response" | jq -r '.allow_websocket_upgrade')${CoR}"
    # Access List
    local access_list_id=$(echo "$response" | jq -r '.access_list_id')
    if [ "$access_list_id" != "null" ]; then
        echo -e "│ 🔑 Access List ID: ${COLOR_YELLOW}$access_list_id${CoR}"
    fi
    # Custom Locations
    local locations=$(echo "$response" | jq -r '.locations')
    if [ "$locations" != "[]" ]; then
        echo -e "│ 📍 Custom Locations:"
        echo "$response" | jq -r '.locations[] | "│   • Path: \(.path)\n│     Handler: \(.handler)"'
    fi
    # Advanced Config
    local advanced_config=$(echo "$response" | jq -r '.advanced_config')
    if [ -n "$advanced_config" ] && [ "$advanced_config" != "null" ]; then
        echo -e "│ ⚙️ Advanced Config: ${COLOR_YELLOW}Yes${CoR}"
    fi
    echo -e "└────────────────────────────────────\n"
    return 0
}

# Function to show full details for a specific host by ID
 host_show_() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n ⛔ The --host-show option requires a host ID."
    help
  fi
  echo -e "\n${COLOR_ORANGE} 👉 Full details for proxy host ID: $HOST_ID...${CoR}\n"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(get_token)")

  echo "$RESPONSE" | jq .
  echo ""
}

show_host() {
    local host_id=$1

    if [ -z "$host_id" ]; then
        echo -e "\n⛔ ${COLOR_RED}Host ID is required${CoR}"
        echo -e "Usage: $0 --host-show <id>"
        return 1
    fi

    echo -e "\n🔍 Showing details for host ID: ${COLOR_YELLOW}$host_id${CoR}"

    local response
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -X GET "$BASE_URL/nginx/proxy-hosts/$host_id" \
        -H "Authorization: Bearer $(get_token)")

    local http_body=${response//HTTPSTATUS:*/}
    local http_status=${response##*HTTPSTATUS:}

    if [ "$http_status" -eq 200 ]; then
        # Format the output nicely
        echo -e "\n${COLOR_GREEN}Host Details:${CoR}"
        echo "$http_body" | jq -r '
            "🌐 Domain Names: \(.domain_names | join(", "))
            📡 Forward Host: \(.forward_host)
            🔌 Forward Port: \(.forward_port)
            🔒 SSL Enabled: \(.ssl_forced)
            ✨ Status: \(.enabled)
            🔄 Forward Scheme: \(.forward_scheme)
            📦 Caching Enabled: \(.caching_enabled)
            🛡️ Block Exploits: \(.block_exploits)
            🔌 WebSocket Upgrade: \(.allow_websocket_upgrade)
            🚀 HTTP/2 Support: \(.http2_support)
            
            📝 Advanced Config:
            \(.advanced_config // "None")
            
            📍 Custom Locations:
            \(.locations | if length > 0 then .[] | "  - Path: \(.path)\n    Forward: \(.forward_scheme)://\(.forward_host):\(.forward_port)" else "None" end)"
        '
    else
        echo -e "⛔ ${COLOR_RED}Failed to get host details. Status: $http_status${CoR}"
        echo -e "Error: ${COLOR_RED}$(echo "$http_body" | jq -r '.error.message // "Unknown error"')${CoR}"
        return 1
    fi
}

# Access List Management
create_access_list() {
    # Implement access list creation
    echo -e "\n🔑 ${COLOR_CYAN}Creating access list...${CoR}"
    echo -e "Enter the name for the new access list:"
    read -r access_list_name

    # Create the access list
    local response=$(curl -s -X POST "$BASE_URL/nginx/access-lists" \
        -H "Authorization: Bearer $(get_token)" \
        -H "Content-Type: application/json; charset=UTF-8" \
        -d "{\"name\": \"$access_list_name\"}")

    if [ "$(echo "$response" | jq -r '.error | length')" -eq 0 ]; then
        echo -e " ✅ ${COLOR_GREEN}Access list created successfully!${CoR}"
    else
        echo -e " ⛔ ${COLOR_RED}Failed to create access list. Error: $(echo "$response" | jq -r '.error')${CoR}"
    fi
}

update_access_list() {
    # Implement access list update
    echo -e "\n🔑 ${COLOR_CYAN}Updating access list...${CoR}"
    echo -e "Enter the ID of the access list to update:"
    read -r access_list_id

    # Get the current access list details
    local response=$(curl -s -X GET "$BASE_URL/nginx/access-lists/$access_list_id" \
        -H "Authorization: Bearer $(get_token)")

    if [ "$(echo "$response" | jq -r '.error | length')" -eq 0 ]; then
        echo -e " ✅ ${COLOR_GREEN}Access list details fetched successfully!${CoR}"
    else
        echo -e " ⛔ ${COLOR_RED}Failed to fetch access list details. Error: $(echo "$response" | jq -r '.error')${CoR}"
    fi
}

delete_access_list() {
    # Implement access list deletion
    echo -e "\n🔑 ${COLOR_CYAN}Deleting access list...${CoR}"
    echo -e "Enter the ID of the access list to delete:"
    read -r access_list_id

    # Delete the access list
    local response=$(curl -s -X DELETE "$BASE_URL/nginx/access-lists/$access_list_id" \
        -H "Authorization: Bearer $(get_token)")

    if [ "$(echo "$response" | jq -r '.error | length')" -eq 0 ]; then
        echo -e " ✅ ${COLOR_GREEN}Access list deleted successfully!${CoR}"
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete access list. Error: $(echo "$response" | jq -r '.error')${CoR}"
    fi

} 





################################
# show_default
# Display default settings for creating hosts
show_default_test() {
  echo -e "\n ⭐ ${COLOR_YELLOW}Default settings Token:${CoR}"
  echo -e "  - TOKEN_EXPIRY    : ${COLOR_ORANGE}${TOKEN_EXPIRY}${CoR}"
  echo -e "\n ⭐ ${COLOR_YELLOW}Default settings for creating hosts (change according to your needs):${CoR}"
  echo -e "  - FORWARD_SCHEME  : ${COLOR_ORANGE}${FORWARD_SCHEME}${CoR}"
  echo -e "  - SSL_FORCED      : ${COLOR_ORANGE}${SSL_FORCED}${CoR}"
  echo -e "  - CACHING_ENABLED : ${COLOR_ORANGE}${CACHING_ENABLED}${CoR}"
  echo -e "  - BLOCK_EXPLOITS  : ${COLOR_ORANGE}${BLOCK_EXPLOITS}${CoR}"
  echo -e "  - ALLOW_WEBSOCKET : ${COLOR_ORANGE}${ALLOW_WEBSOCKET_UPGRADE}${CoR}"
  echo -e "  - HTTP2_SUPPORT   : ${COLOR_ORANGE}${HTTP2_SUPPORT}${CoR}"
  echo -e "  - HSTS_ENABLED    : ${COLOR_ORANGE}${HSTS_ENABLED}${CoR}"
  echo -e "  - HSTS_SUBDOMAINS : ${COLOR_ORANGE}${HSTS_SUBDOMAINS}${CoR}"
  echo
  exit 0
}
show_default() {
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
  echo -e "  Base Directory:           $BASE_DIR"
  echo -e "  Token Directory:          $TOKEN_DIR"
  echo -e "  Backup Directory:         $BACKUP_DIR"
  echo -e "  Token Expiry:             $TOKEN_EXPIRY\n"
  
  exit 0
}

# Function to sanitize names for directory
sanitize_name() {
  local name=$1
  echo "${name//[^a-zA-Z0-9]/_}"
}
################################
## backup
# Function to make a full backup
full_backup() {
    check_dependencies
    check_nginx_access
    validate_token

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
    if [[ "$BACKUP_DIR" != *"${NGINX_IP}_${NGINX_PORT}" ]]; then
        BACKUP_PATH="$BACKUP_DIR/${NGINX_IP}_${NGINX_PORT}"
    fi

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
    echo -e "\n👥 ${COLOR_CYAN}Backing up users...${CoR}"
    USERS_RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
    -H "Authorization: Bearer $(get_token)")
    
    if [ -n "$USERS_RESPONSE" ] && echo "$USERS_RESPONSE" | jq empty 2>/dev/null; then
        users_count=$(echo "$USERS_RESPONSE" | jq '. | length')
        # Save users to dedicated file
        echo "$USERS_RESPONSE" | jq '.' > "$BACKUP_PATH/.user/users_${NGINX_IP//./_}$DATE.json"
        # Add users to full configuration
        jq --argjson users "$USERS_RESPONSE" '. + {users: $users}' \
            "$BACKUP_PATH/full_config${DATE}.json" > "$BACKUP_PATH/full_config${DATE}.json.tmp"
        mv "$BACKUP_PATH/full_config${DATE}.json.tmp" "$BACKUP_PATH/full_config${DATE}.json"
        echo -e " ✅ ${COLOR_GREEN}Backed up $users_count users${CoR}"
    else
        echo -e " ⚠️ ${COLOR_YELLOW}No users found or invalid response${CoR}"
        ((error_count++))
    fi

    # 2. Backup settings
    echo -e "\n⚙️  ${COLOR_CYAN}Backing up settings...${CoR}"
    SETTINGS_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/settings" \
    -H "Authorization: Bearer $(get_token)")
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
    -H "Authorization: Bearer $(get_token)")
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
    -H "Authorization: Bearer $(get_token)")

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
            -H "Authorization: Bearer $(get_token)")
            if [ -n "$NGINX_CONFIG" ]; then
                echo "$NGINX_CONFIG" > "$PROXY_DIR/nginx.conf"
            fi

            # Get and save logs if they exist
            curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id/access.log" \
            -H "Authorization: Bearer $(get_token)" > "$PROXY_DIR/logs/access.log"
            curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$host_id/error.log" \
            -H "Authorization: Bearer $(get_token)" > "$PROXY_DIR/logs/error.log"

            # Process SSL certificate if exists
            if [ -n "$cert_id" ] && [ "$cert_id" != "null" ] && [ "$cert_id" != "0" ]; then
                echo -e "   🔒 Downloading SSL certificate (ID: $cert_id)"
                
                # Get certificate metadata first
                local CERT_META
                CERT_META=$(curl -s -X GET "$BASE_URL/nginx/certificates/$cert_id" \
                -H "Authorization: Bearer $(get_token)")
                
                if [ -n "$CERT_META" ] && echo "$CERT_META" | jq empty 2>/dev/null; then
                    echo "$CERT_META" | jq '.' > "$PROXY_DIR/ssl/certificate_meta.json"
                    
                    # Get certificate content
                    local CERT_CONTENT
                    CERT_CONTENT=$(curl -s -X GET "$BASE_URL/nginx/certificates/$cert_id/certificates" \
                    -H "Authorization: Bearer $(get_token)" \
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
                        if echo "$CERT_META" | jq -e '.provider | contains("letsencrypt")' >/dev/null; then
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

# maybe redudant
################################
# backup-host
# Function to backup a single host configuration and its certificate (if exists)
################################
# Function to backup hosts (single or all)
backup_host() {
    mkdir -p "$BACKUP_DIR"
    DATE=$(date +"_%Y_%m_%d__%H_%M_%S")

    # If an ID is specified, backup only this host
    if [ -n "$HOST_ID" ]; then
        echo -e "\n 📦 Backing up host ID: $HOST_ID"
        
        # Get host details
        local host_response
        host_response=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
            -H "Authorization: Bearer $(get_token)")

        if [ -n "$host_response" ] && [ "$(echo "$host_response" | jq -r '.id')" = "$HOST_ID" ]; then
            local domain_names=$(echo "$host_response" | jq -r '.domain_names[0]')
            local cert_id=$(echo "$host_response" | jq -r '.certificate_id')
            
            echo -e " 📝 Processing host: $domain_names (ID: $HOST_ID)"
            
            if [ "$cert_id" != "null" ] && [ "$cert_id" != "0" ]; then
                echo -e " 🔒 Getting certificate for host (cert ID: $cert_id)..."
                local cert_response
                cert_response=$(curl -s -X GET "$BASE_URL/nginx/certificates/$cert_id" \
                    -H "Authorization: Bearer $(get_token)")
                
                # Combine host and certificate data
                local backup_data
                backup_data=$(echo '{}' | jq \
                    --argjson host "$host_response" \
                    --argjson cert "$cert_response" \
                    '{host: $host, certificate: $cert}')
            else
                local backup_data
                backup_data=$(echo '{}' | jq \
                    --argjson host "$host_response" \
                    '{host: $host, certificate: null}')
            fi

            echo "$backup_data" | jq '.' > "$BACKUP_DIR/backup_host_${HOST_ID}${DATE}.json"
            echo -e " ✅ ${COLOR_GREEN}Backup completed: backup_host_${HOST_ID}${DATE}.json${CoR}"
        else
            echo -e " ⛔ ${COLOR_RED}Failed to backup host ID $HOST_ID${CoR}"
            return 1
        fi
    else
        echo -e "\n 📦 ${COLOR_YELLOW}Backing up all hosts and certificates...${CoR}"
        BACKUP_FILE="$BACKUP_DIR/backup_hosts${DATE}.json"
        
        local hosts_response
        hosts_response=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
            -H "Authorization: Bearer $(get_token)")

        if [ -z "$hosts_response" ]; then
            echo -e " ⛔ ${COLOR_RED}Failed to get hosts list${CoR}"
            return 1
        fi
        
        declare -a all_hosts
        local total_hosts=0
        local ssl_count=0
        
        # Définir les largeurs de colonnes
        local domain_width=30
        local id_width=3
        local cert_width=3
        
        while read -r host; do
            local domain
            domain=$(echo "$host" | jq -r '.domain_names[0]')
            local cert_id
            cert_id=$(echo "$host" | jq -r '.certificate_id')
            
            if [ "$cert_id" != "null" ] && [ "$cert_id" != "0" ]; then
                # Formater le domaine avec une largeur fixe
                printf -v domain_pad "%-${domain_width}s" "$domain"
                # Formater les IDs avec une largeur fixe
                printf -v id_pad "%${id_width}s" "$h_id"
                printf -v cert_pad "%${cert_width}s" "$cert_id"
                
                echo -e " 🔒 ${COLOR_CYAN}Getting certificate for host ${COLOR_GREEN}${domain_pad}${CoR}(ID: ${COLOR_YELLOW}${id_pad}${CoR}, cert ID: ${COLOR_CYAN}${cert_pad}${CoR}) ${COLOR_GREEN}🆗${CoR}"
                
                local cert_response
                cert_response=$(curl -s -X GET "$BASE_URL/nginx/certificates/$cert_id" \
                    -H "Authorization: Bearer $(get_token)")
                
                local host_data
                host_data=$(echo '{}' | jq \
                    --argjson host "$host" \
                    --argjson cert "$cert_response" \
                    '{host: $host, certificate: $cert}')
                ((ssl_count++))
            else
                local host_data
                host_data=$(echo '{}' | jq \
                    --argjson host "$host" \
                    '{host: $host, certificate: null}')
            fi
            
            all_hosts+=("$host_data")
            ((total_hosts++))
        done < <(echo "$hosts_response" | jq -c '.[]')

        # Sauvegarder tous les hosts dans un fichier
        printf '%s\n' "${all_hosts[@]}" | jq -s '.' > "$BACKUP_FILE"
        
        echo -e "\n ✅ ${COLOR_GREEN}Backup Summary:${CoR}"
        echo -e " • Total hosts backed up: ${COLOR_CYAN}$total_hosts${CoR}"
        echo -e " • Hosts with SSL: ${COLOR_CYAN}$ssl_count${CoR}"
        echo -e " • Backup file: ${COLOR_YELLOW}$BACKUP_FILE${CoR}"
        
        # Créer un lien symbolique vers le dernier backup
        ln -sf "$BACKUP_FILE" "$BACKUP_DIR/backup_hosts_latest.json"
        echo -e " • ${COLOR_GREEN}Symlink created: ${COLOR_YELLOW}backup_hosts_latest.json${CoR}\n"
    fi

    exit 0    
}

 
################################
# Function to list global backup files
list_global_backup_files() {
  ls -t "$BACKUP_DIR"/*_*.json
}

# Function to list SSL backup files
list_ssl_backup_files() {
  ls -t "$BACKUP_DIR"/ssl_certif_*.json
}


######################################################
# restore  ALL CONFIGURATIONS or specific domain or certificates only 
######################################################  
restore_backup() {
    echo -e "\n 🔄 ${COLOR_YELLOW}Restore Configuration Menu${CoR}"
    
    # 1. Sélection du type de restauration
    echo -e "\n🩹 Select restore type:"
    echo -e " 1) Full restore (all configurations)"
    echo -e " 2) Specific domain restore"
    echo -e " 3) Certificates only"
    echo -e " 4) Settings only"
    echo -e " 5) Access lists only"
    echo -e " 6) Users only"
    read -r -p "Enter your choice (1-6): " restore_choice

    case $restore_choice in
        1)  # Full restore
            echo -e "\n📦 ${COLOR_YELLOW}Available full configuration backups:${CoR}"
            select backup_file in "$BACKUP_DIR"/full_config_*.json; do
                if [ -n "$backup_file" ]; then
                    if [ "$AUTO_YES" != true ]; then
                        echo -e "\n⚠️  ${COLOR_RED}Warning: This will overwrite all current configurations!${CoR}"
                        read -r -p "Are you sure you want to proceed? (y/n): " confirm
                        [[ "$confirm" != "y" ]] && return 1
                    fi

                    echo -e "\n🔄 Restoring from: ${COLOR_CYAN}$backup_file${CoR}"
                    
                    # Restaure  utilisateurs
                    echo -e "\n👥 Restoring users..."
                    local users_data=$(jq '.users' "$backup_file")
                    if [ "$users_data" != "null" ]; then
                        local response=$(curl -s -X POST "$BASE_URL/users/bulk" \
                            -H "Authorization: Bearer $(get_token)" \
                            -H "Content-Type: application/json" \
                            --data-raw "$users_data")
                        echo -e " ✅ ${COLOR_GREEN}Users restored${CoR}"
                    fi

                    # Restaure  parametres
                    echo -e "\n⚙️  Restoring settings..."
                    local settings_data=$(jq '.settings' "$backup_file")
                    if [ "$settings_data" != "null" ]; then
                        local response=$(curl -s -X PUT "$BASE_URL/nginx/settings" \
                            -H "Authorization: Bearer $(get_token)" \
                            -H "Content-Type: application/json" \
                            --data-raw "$settings_data")
                        echo -e " ✅ ${COLOR_GREEN}Settings restored${CoR}"
                    fi

                    # Restaure  certificats
                    echo -e "\n🔒 Restoring certificates..."
                    local certs_data
                    certs_data=$(jq '.certificates[]' "$backup_file")
                    if [ -n "$certs_data" ]; then
                        echo "$certs_data" | while read -r cert; do
                            local clean_cert=$(echo "$cert" | jq 'del(.id, .created_on, .modified_on)')
                            local response=$(curl -s -X POST "$BASE_URL/nginx/certificates" \
                                -H "Authorization: Bearer $(get_token)" \
                                -H "Content-Type: application/json" \
                                --data-raw "$clean_cert")
                        done
                        echo -e " ✅ ${COLOR_GREEN}Certificates restored${CoR}"
                    fi

                    # Restaure  access lists
                    echo -e "\n🔑 Restoring access lists..."
                    local lists_data=$(jq '.access_lists' "$backup_file")
                    if [ "$lists_data" != "null" ]; then
                        local response=$(curl -s -X POST "$BASE_URL/nginx/access-lists/bulk" \
                            -H "Authorization: Bearer $(get_token)" \
                            -H "Content-Type: application/json" \
                            --data-raw "$lists_data")
                        echo -e " ✅ ${COLOR_GREEN}Access lists restored${CoR}"
                    fi

                    # Restaure  proxy hosts
                    echo -e "\n🌐 Restoring proxy hosts..."
                    local hosts_data=$(jq '.proxy_hosts[]' "$backup_file")
                    if [ -n "$hosts_data" ]; then
                        echo "$hosts_data" | while read -r host; do
                            local clean_host=$(echo "$host" | jq 'del(.id, .created_on, .modified_on, .owner_user_id)')
                            local response=$(curl -s -X POST "$BASE_URL/nginx/proxy-hosts" \
                                -H "Authorization: Bearer $(get_token)" \
                                -H "Content-Type: application/json" \
                                --data-raw "$clean_host")
                        done
                        echo -e " ✅ ${COLOR_GREEN}Proxy hosts restored${CoR}"
                    fi

                    echo -e "\n✅ ${COLOR_GREEN}Full restore completed successfully!${CoR}\n"
                    break
                fi
            done
            ;;

        2)  # Specific domain restore
            echo -e "\n🌐 ${COLOR_YELLOW}Available domains:${CoR}"
            select domain_dir in "$BACKUP_DIR/.Proxy_Hosts"/*/; do
                if [ -n "$domain_dir" ] && [ -d "$domain_dir" ]; then
                    domain_name=$(basename "$domain_dir")
                    echo -e "\n🔄 Restoring configuration for domain: ${COLOR_CYAN}$domain_name${CoR}"
     
                    # Restaurer la configuration du proxy
                    local proxy_file=$(ls -t "$domain_dir"/proxy_host_*.json | head -1)
                    if [ -f "$proxy_file" ]; then
                        local clean_proxy=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$proxy_file")
                        curl -s -X POST "$BASE_URL/nginx/proxy-hosts" \
                            -H "Authorization: Bearer $(get_token)" \
                            -H "Content-Type: application/json" \
                            --data-raw "$clean_proxy"
                    fi

                    # Restaurer le certificat SSL si présent
                    local ssl_file=$(ls -t "$domain_dir"/ssl_certif_*.json | head -1)
                    if [ -f "$ssl_file" ]; then
                        local clean_cert=$(jq 'del(.id)' "$ssl_file")
                        curl -s -X POST "$BASE_URL/nginx/certificates" \
                            -H "Authorization: Bearer $(get_token)" \
                            -H "Content-Type: application/json" \
                            --data-raw "$clean_cert"
                    fi

                    echo -e "\n✅ ${COLOR_GREEN}Domain restore completed!${CoR}\n"
                    break
                fi
            done
            ;;
            
        3)  # Certificates only
            echo -e "\n🔒 ${COLOR_YELLOW}Available certificate backups:${CoR}"
            select cert_file in "$BACKUP_DIR/.ssl"/all_certificates_*.json; do
                if [ -f "$cert_file" ]; then
                    echo -e "\n🔄 Restoring certificates from: ${COLOR_CYAN}$cert_file${CoR}"
                    jq -c '.[]' "$cert_file" | while read -r cert; do
                        local clean_cert=$(echo "$cert" | jq 'del(.id)')
                        curl -s -X POST "$BASE_URL/nginx/certificates" \
                            -H "Authorization: Bearer $(get_token)" \
                            -H "Content-Type: application/json" \
                            --data-raw "$clean_cert"
                    done
                    echo -e "\n✅ ${COLOR_GREEN}Certificates restore completed!${CoR}\n"
                    break
                fi
            done
            ;;
            
        4)  # Settings only
            # ... code pour restaurer uniquement les paramètres
            ;;
            
        5)  # Access lists only
            # ... code pour restaurer uniquement les access lists
            ;;
            
        6)  # Users only
            # ... code pour restaurer uniquement les utilisateurs
            ;;
            
        *)
            echo -e "\n⛔ ${COLOR_RED}Invalid choice${CoR}"
            ;;
    esac
}

######################################################
### Function to restore from backup file
restore_backup__old() {
  echo -e "\n 🩹 ${COLOR_ORANGE}Restoring all configurations from backup...${CoR}"

  # Function to sanitize names for directory
  sanitize_name() {
    echo "$1" | sed 's/[^a-zA-Z0-9]/_/g'
  }

  GLOBAL_BACKUP_FILES=$(ls -t "$BACKUP_DIR"/*_*.json)
  if [ -z "$GLOBAL_BACKUP_FILES" ]; then
    echo -e " ⛔ ${COLOR_RED}No backup files found.${CoR}"
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
          -H "Authorization: Bearer $(get_token)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE"
          echo -e " ✅ ${COLOR_GREEN}Users restored successfully!${CoR}"
          ;;
        *settings_*.json)
          echo -e "\n 🩹 Restoring settings from $global_file..."
          RESPONSE=$(cat "$global_file")
          curl -s -X POST "$BASE_URL/nginx/settings/bulk" \
          -H "Authorization: Bearer $(get_token)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE"
          echo -e " ✅ ${COLOR_GREEN}Settings restored successfully!${CoR}"
          ;;
        *access_lists_*.json)
          echo -e "\n 🩹 Restoring access lists from $global_file..."
          RESPONSE=$(cat "$global_file")
          curl -s -X POST "$BASE_URL/nginx/access-lists/bulk" \
          -H "Authorization: Bearer $(get_token)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE"
          echo -e " ✅ ${COLOR_GREEN}Access lists restored successfully!${CoR}"
          ;;
      esac
    else
      echo -e " ⛔ ${COLOR_RED}Invalid selection.${CoR}"
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
          -H "Authorization: Bearer $(get_token)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE")

        HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS:*/}
        HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

        if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 201 ]; then
          echo -e " ✅ ${COLOR_GREEN}Proxy host restored successfully!${CoR}"
        else
          echo -e " ⛔ ${COLOR_RED}Failed to restore proxy host. Error: $HTTP_BODY${CoR}"
        fi
      fi

      if [ -n "$SSL_FILES" ]; then
        for SSL_FILE in $SSL_FILES; do
          echo -e "\n 🩹 Restoring SSL certificate from $SSL_FILE..."
          CERT_RESPONSE=$(cat "$SSL_FILE")
          HTTP_CERT_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/certificates" \
            -H "Authorization: Bearer $(get_token)" \
            -H "Content-Type: application/json; charset=UTF-8" \
            --data-raw "$CERT_RESPONSE")

          HTTP_CERT_BODY=${HTTP_CERT_RESPONSE//HTTPSTATUS:*/}
          HTTP_CERT_STATUS=${HTTP_CERT_RESPONSE##*HTTPSTATUS:}

          if [ "$HTTP_CERT_STATUS" -eq 200 ] || [ "$HTTP_CERT_STATUS" -eq 201 ]; then
            echo -e " ✅ ${COLOR_GREEN}SSL certificate restored successfully!${CoR}"
          else
            echo -e " ⛔ ${COLOR_RED}Failed to restore SSL certificate. Error: $HTTP_CERT_BODY${CoR}"
          fi
        done
      fi
    fi
  done

  echo -e "\n ✅ ${COLOR_GREEN}All configurations restored successfully!${CoR}\n"
}

######################################################
##   test  BACKUP RESTORE
######################################################
# Function to list backup versions for a given host ID
list_backup_versions_t() {
  echo -e "\n 🔍 Listing available backup versions for host ID $HOST_ID..."
  find "$BACKUP_DIR" -name "proxy_host_ID_+${HOST_ID}_IP_${NGINX_IP//./_}_*.json" -type f -printf "%T@ %p\n" | sort -nr | head -n 10 | cut -d' ' -f2- | while read -r file; do
    timestamp=$(grep -oE '[0-9]{14}' <<< "$file")
    echo " - $timestamp"
  done
}

## en test
# Function to show content of the backup
show_backup_content() {
  BACKUP_FILE=$(find "$BACKUP_DIR" -name "proxy_host_ID_+${HOST_ID}_IP_${NGINX_IP//./_}_*.json" -type f -printf "%T@ %p\n" | sort -nr | head -n1 | cut -d' ' -f2-)
  if [ -f "$BACKUP_FILE" ]; then
    echo -e "\n 🔄 Content of the backup for host ID $HOST_ID:"
    jq . "$BACKUP_FILE" | less
  else
    echo -e "\n ⛔ ${COLOR_RED}No backup file found for host ID $HOST_ID.${CoR}"
  fi
}

## en test
# Function to show differences between current and backup versions
show_backup_differences() {
  CURRENT_HOST=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(get_token)")

  BACKUP_FILE=$(find "$BACKUP_DIR" -name "proxy_host_ID_+${HOST_ID}_IP_${NGINX_IP//./_}_*.json" -type f -printf "%T@ %p\n" | sort -nr | head -n1 | cut -d' ' -f2-)
  BACKUP_HOST=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$BACKUP_FILE")

  echo -e "\n 🔄 Differences between current and backup versions for host ID $HOST_ID:"
  diff <(echo "$CURRENT_HOST" | jq .) <(echo "$BACKUP_HOST" | jq .) | less
}

##### restore-host
# Function to restore a single host configuration and its certificate (if exists)
restore_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 🩹 The --host-restore-id option requires a host ID."
    help
  fi

  # Get the current date in a formatted string
  DATE=$(date +"_%Y_%m_%d__%H_%M_%S")

  # Verify if host ID exists
  HOST_ID_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" -H "Authorization: Bearer $(get_token)")
  if [ -z "$HOST_ID_RESPONSE" ] || [ "$(echo "$HOST_ID_RESPONSE" | jq -r '.id')" != "$HOST_ID" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Host ID $HOST_ID does not exist. Aborting restore.${CoR}"
    exit 1
  fi

  # Fetch the host name to identify the directory
  HOST_NAME=$(echo "$HOST_ID_RESPONSE" | jq -r '.domain_names[0]')
  if [ -z "$HOST_NAME" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Host name not found in the response. Aborting restore.${CoR}"
    exit 1
  fi
  SANITIZED_HOST_NAME=${HOST_NAME//[^a-zA-Z0-9]/_}
  HOST_DIR="$BACKUP_DIR/$SANITIZED_HOST_NAME"

  #echo -e " 🐛 Debug: SANITIZED_HOST_NAME = $SANITIZED_HOST_NAME"
  #echo -e " 🐛 Debug: HOST_DIR = $HOST_DIR"

  # Verify the existence of the host directory
  if [ ! -d "$HOST_DIR" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Backup directory for host $HOST_ID not found: $HOST_DIR${CoR}"
    exit 1
  fi

  # Verify the existence of backup files
  mapfile -t BACKUP_FILES < <(find "$HOST_DIR" -type f -name "proxy_host_${HOST_ID}_*.json")

  if [ ${#BACKUP_FILES[@]} -eq 0 ]; then
    echo -e "\n ⛔ ${COLOR_RED}No backup file found for host ID $HOST_ID in '$HOST_DIR'. Aborting restore.${CoR}"
    exit 1
  fi

  # Count the number of backup files
  BACKUP_COUNT=${#BACKUP_FILES[@]}

  if [ "$BACKUP_COUNT" -gt 0 ]; then
    echo -e "\n 🔍 Found ${COLOR_ORANGE}$BACKUP_COUNT${CoR} backups for host ${COLOR_ORANGE}$SANITIZED_HOST_NAME${CoR} ID $HOST_ID."
    PROXY_HOST_FILE=$(printf '%s\n' "${BACKUP_FILES[@]}" | xargs -I {} find {} -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2-)
    echo -e " 🩹 Latest Backup File found: $PROXY_HOST_FILE \n"
    read -r -p " 👉 Do you want to (1) restore the latest backup, (2) list backups and choose one, or (3) abandon? (1/2/3): " -r choice
    case $choice in
      1)
        echo -e "\n 🩹 Proxy Host backup file : $PROXY_HOST_FILE"
        ;;
      2)
        mapfile -t BACKUP_LIST < <(ls -t "${BACKUP_FILES[@]}")
        echo -e "\nAvailable backups:"
        for i in "${!BACKUP_LIST[@]}"; do
          echo "$i) ${BACKUP_LIST[$i]}"
        done
        read -r -p " 👉 Enter the number of the backup you want to restore: " -r backup_number
        PROXY_HOST_FILE="${BACKUP_LIST[$backup_number]}"
        if [ ! -f "$PROXY_HOST_FILE" ]; then
          echo -e "\n ⛔ ${COLOR_RED}Selected backup file not found: $PROXY_HOST_FILE${CoR}"
          exit 1
        fi
        ;;
      3)
        echo -e "\n${COLOR_RED} Abandoned.${CoR}\n"
        exit 0
        ;;
      *)
        echo -e "\n ${COLOR_ORANGE}Invalid choice.${CoR}\n"
        exit 1
        ;;
    esac
  fi

  # Verify if the proxy host exists
  if [ -n "$HOST_ID_RESPONSE" ] && [ "$(echo "$HOST_ID_RESPONSE" | jq -r '.id')" = "$HOST_ID" ]; then
    echo -e " 🔔 Proxy host for ID $HOST_ID already exists.\n ${COLOR_ORANGE}"
    if [ "$AUTO_YES" = true ]; then
      echo -e "🔔 The -y parameter is active. Skipping confirmation prompt..."
      confirm="y"
    else
      read -r -p " 👉 Do you want to delete the existing proxy host and restore from the backup? (y/n): " -r confirm
    fi
    echo -e "${CoR}"
    if [[ $confirm =~ ^[Yy]$ ]]; then
      echo -e "${CoR}"
      if ! host_delete; then
        echo -e "${COLOR_RED} ⛔ Failed to delete existing proxy host. Aborting restore.${CoR}\n"
        exit 1
      fi
    else
      echo " ⛔ Abandoned."
      exit 0
    fi
  fi

  if [ -f "$PROXY_HOST_FILE" ]; then
    RESPONSE=$(jq 'del(.id, .created_on, .modified_on, .owner_user_id)' "$PROXY_HOST_FILE")
    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/nginx/proxy-hosts" \
      -H "Authorization: Bearer $(get_token)" \
      -H "Content-Type: application/json; charset=UTF-8" \
      --data-raw "$RESPONSE")

    HTTP_BODY=${HTTP_RESPONSE//HTTPSTATUS\\:.*/}
    HTTP_STATUS=${HTTP_RESPONSE##*HTTPSTATUS:}

    if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 201 ]; then
      echo -e " ✅ ${COLOR_GREEN}Proxy host restored 🆗 from file: $PROXY_HOST_FILE${CoR}\n"
    else
      echo -e " ⛔ ${COLOR_RED}Failed to restore proxy host. Error: $HTTP_BODY${CoR}\n"
      exit 1
    fi
  else
    echo -e "\n ⛔ ${COLOR_RED}Proxy host backup file not found: $PROXY_HOST_FILE${CoR}\n"
    exit 1
  fi
}

##############################################################
# Main logic
##############################################################
if [ "$INFO" = true ]; then
  display_info
elif [ "$SHOW_DEFAULT" = true ]; then
  show_default
elif [ "$EXAMPLES" = true ]; then
  examples_cli
elif [ "$CHECK_TOKEN" = true ]; then
  check_token true

# Commandes de listing
elif [ "$HOSTS_LIST" = true ]; then
  host_list
elif [ "$HOSTS_LIST_FULL" = true ]; then
  host_list_full
elif [ "$LIST_USERS" = true ]; then
  list_users
elif [ "$LIST_SSL_CERT" = true ]; then
  if [ -n "$DOMAIN" ]; then
    list_ssl_cert "$DOMAIN"
  else
    list_ssl_cert
  fi
elif [ "$ACCESS_LIST" = true ]; then
  access_list
elif [ "$HOST_SEARCH" = true ]; then
  host_search
elif [ "$HOST_SHOW" = true ]; then
  host_show "$HOST_ID"

# Actions utilisateurs
elif [ "$CREATE_USER" = true ]; then
  create_user "$USERNAME" "$PASSWORD" "$EMAIL"
elif [ "$DELETE_USER" = true ]; then
  delete_user "$USER_ID"

# Actions hôtes
elif [ "$HOST_DELETE" = true ]; then
  host_delete
elif [ "$HOST_ENABLE" = true ]; then
  host_enable
elif [ "$HOST_DISABLE" = true ]; then
  host_disable
elif [ "$HOST_UPDATE" = true ]; then
  host-update "$HOST_ID" "$FIELD" "$VALUE"

# Actions ACL
elif [ "$HOST_ACL_ENABLE" = true ]; then
  host_acl_enable
elif [ "$HOST_ACL_DISABLE" = true ]; then
  host_acl_disable

# Actions SSL
elif [ "$GENERATE_CERT" = true ]; then
  generate_certificate
elif [ "$DELETE_CERT" = true ]; then
  delete_certificate
elif [ "$ENABLE_SSL" = true ]; then
  enable_ssl
elif [ "$DISABLE_SSL" = true ]; then
  disable_ssl
elif [ "$SSL_REGENERATE" = true ]; then
  regenerate_all_ssl_certificates
elif [ "$SSL_RESTORE" = true ]; then
  restore_ssl_certificates

# Actions backup/restore
elif [ "$BACKUP" = true ]; then
  full_backup
elif [ "$BACKUP_HOST" = true ]; then
  backup_host
elif [ "$BACKUP_LIST" = true ]; then
  list_backups
elif [ "$RESTORE_BACKUP" = true ]; then
  restore_backup
elif [ "$RESTORE_HOST" = true ]; then
  restore_host
elif [ "$CLEAN_HOSTS" = true ]; then
  clean-hosts

elif [ "$CREATE_HOST" = true ]; then
  create_host

# Default action if no other condition matches
else
  help
fi

