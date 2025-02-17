#!/bin/bash

# Nginx Proxy Manager CLI Script
#   Github [ https://github.com/Erreur32/nginx-proxy-manager-Bash-API ]
#   By Erreur32 - July 2024

VERSION="2.6.0"

#
# This script allows you to manage Nginx Proxy Manager via the API. It provides
# functionalities such as creating proxy hosts, managing users, listing hosts,
# backing up configurations, and more.
#
# Usage:
#   $0 [OPTIONS]
#
# TIPS: Create manually a Config file for persistent variables 'nginx_proxy_manager_cli.conf' :
#       With these variables:
#          NGINX_IP="127.0.0.1"
#          API_USER="admin@example.com"
#          API_PASS="changeme"
#          BASE_DIR="/path/nginx_proxy_script/data" 
#
# Examples:
# 📦 Backup First!
#   $0 --backup
#
# 🌐 Host Creation:
#   $0 -d example.com -i 192.168.1.10 -p 8080 (check default values below)
#   $0 --show-default
#   $0 --host-list
#   $0 --host-ssl-enable 10
#
# 👤 User Creation: 
#   $0 --create-user newuser password123 user@example.com
#   $0 --delete-user 'username'
#
# 🔧 Advanced Example:
#   $0 -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'
#
# 🔒 Custom Certificate:
#   $0 --generate-cert example.com user@example.com 
#
# 📂 Custom locations:
#   $0 -d example.com -i 192.168.1.10 -p 8080 -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'
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
#   -y                                    Automatic yes prompts !
#
# 📦 Backup and Restore:
#   --backup                              Backup all configurations to a file
#   --backup-host id                      Backup a single host configuration and its certificate (if exists)
#
# DISABLE
#   --restore commands  DISABLED ,  i need to think the best way to do it !!
#
# 🔧 Miscellaneous:
#   --check-token                         Check if the current token is valid
#   --create-user user pass email         Create a user with a username, password and email
#   --delete-user ID                      Delete a user by username
#   --host-delete id                      Delete a proxy host by ID
#   --host-show id                        Show full details for a specific host by ID
#   --show-default                        Show default settings for creating hosts
#   --host-list                           List the names of all proxy hosts
#   --host-list-full                      List all proxy hosts with full details
#   --list-users                     List all users
#   --host-search hostname                Search for a proxy host by domain name
#   --host-enable id                      Enable a proxy host by ID
#   --host-disable id                     Disable a proxy host by ID
#   --host-ssl-enable id                  Enable SSL, HTTP/2, and HSTS for a proxy host
#   --host-ssl-disable id                 Disable SSL, HTTP/2, and HSTS for a proxy host
#   --list-ssl-certificates               List All SSL certificates availables (JSON)
#   --generate-cert domain email          Generate certificate for the given domain and email
#   --delete-cert domain                  Delete   certificate for the given domain
#   --list-access                         List all available access lists (ID and name)
#   --host-acl-enable id,access_list_id   Enable ACL for a proxy host by ID with an access list ID       
#   --host-acl-disable id                 Disable ACL for a proxy host by ID   
#   --exemples                            Display some command exemples
#         
#   --help                                Display this help

################################
# Variables to Edit (required) #
#   or create a config file    #
################################

NGINX_IP="127.0.0.1"
NGINX_PORT="81"
API_USER="user@nginx"
API_PASS="pass nginx"
BASE_DIR="/path/nginx_proxy_script/data"

# Check if config file nginx_proxy_manager_cli.conf exist
SCRIPT_DIR="$(dirname "$0")"
CONFIG_FILE="$SCRIPT_DIR/nginx_proxy_manager_cli.conf" 

################################
# PERSISTENT Config
# Create config file  $SCRIPT_DIR/nginx_proxy_manager_cli.conf and Edit Variables (required)
# NGINX_IP="127.0.0.1"
# API_USER="admin@example.com"
# API_PASS="changeme"
# BASE_DIR="/path/nginx_proxy_script/dir"
################################

if [ -f "$CONFIG_FILE" ]; then
  #echo -e "\n  ✅ Loading variables from file $CONFIG_FILE"
  # configuration file loading
  source "$CONFIG_FILE"
else
  echo -e "  ⚠️ Configuration file $CONFIG_FILE doesn't exists. Using Default Variables... "
fi


# API Endpoints
BASE_URL="http://$NGINX_IP:$NGINX_PORT/api"
API_ENDPOINT="/tokens"
# Directory will be create automatically.
TOKEN_DIR="$BASE_DIR/token"
BACKUP_DIR="$BASE_DIR/backups"
EXPIRY_FILE="$TOKEN_DIR/expiry_${NGINX_IP}.txt"
TOKEN_FILE="$TOKEN_DIR/token_${NGINX_IP}.txt"

# Set Token duration validity.
#TOKEN_EXPIRY="365d"
#TOKEN_EXPIRY="31536000s"
TOKEN_EXPIRY="1y"

# Default variables (you can adapt)
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
DOMAIN=""

# Don't touch below that line (or you know ...)
# Control variables
CREATE_USER=false
DELETE_USER=false
DELETE_HOST=false
LIST_HOSTS=false
LIST_HOSTS_FULL=false
LIST_SSL_CERTIFICATES=false
LIST_USERS=false
UPDATE_FIELD=false
SEARCH_HOST=false
ENABLE_HOST=false
DISABLE_HOST=false
CHECK_TOKEN=false
BACKUP_LIST=false
BACKUP=false
BACKUP_HOST=false
RESTORE=false
RESTORE_HOST=false
GENERATE_CERT=false
ENABLE_SSL=false
DISABLE_SSL=false
HOST_SHOW=false
SHOW_DEFAULT=false
ENABLE_ACL=false
DISABLE_ACL=false
ACCESS_LIST=false
EXAMPLES=false
SSL_REGENERATE=false
SSL_RESTORE=false
INFO=false
AUTO_YES=false

# Colors Custom
COLOR_GREEN="\033[32m"
COLOR_RED="\033[41;1m"
COLOR_ORANGE="\033[38;5;202m"
COLOR_YELLOW="\033[93m"
CoR="\033[0m"
COLOR_GREY="\e[90m"
WHITE_ON_GREEN="\033[30;48;5;83m"

DEBUG=false
###############################################
# Check if necessary dependencies are installed
check_dependencies() {
  local dependencies=("curl" "jq")
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      missing+=("$dep")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
      echo -e "⛔ ${COLOR_RED}Missing dependencies. Please install:${CoR}"
      printf "   - %s\n" "${missing[@]}"
      exit 1
  fi

  # Check if directories exist and create them if they don't
  for dir in "$BASE_DIR" "$TOKEN_DIR" "$BACKUP_DIR"; do
    if [ ! -d "$dir" ]; then
      echo -e "\n  ${COLOR_YELLOW}Creating directory: $dir${CoR}"
      mkdir -p "$dir"
      if [ $? -ne 0 ]; then
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
  
  while [ $retry_count -lt $max_retries ]; do
    if curl --output /dev/null --silent --head --fail --connect-timeout 5 "$BASE_URL"; then
      echo -e "  ✅ Nginx url: $BASE_URL"
      return 0
    fi
    retry_count=$((retry_count + 1))
    [ $retry_count -lt $max_retries ] && sleep 2
  done
  
  echo -e " ⛔ ${COLOR_RED}Nginx url $BASE_URL is not accessible after $max_retries attempts.${CoR}"
  exit 1
}

# check_nginx_access

# !!! Filter only directory name !
# Function to list available backups
list_backups() {
  echo "Available backups:"
  for domain in $(ls -td "$BACKUP_DIR"/*/); do
    domain_name=$(basename "$domain")
    echo "  - ${domain_name//_/.}"
  done
}

################################
# Display help
usage() {
  echo -e "Options:"
  echo -e "  -d ${COLOR_ORANGE}DOMAIN_NAMES${CoR}                       Domain name (${COLOR_RED}required${CoR})"
  echo -e "  -i ${COLOR_ORANGE}FORWARD_HOST${CoR}                       IP address or domain name of the target server (${COLOR_RED}required${CoR})"
  echo -e "  -p ${COLOR_ORANGE}FORWARD_PORT${CoR}                       Port of the target server (${COLOR_RED}required${CoR})"
  echo -e "\n (Check default settings,no argument needed if already set!)"
  echo -e "  -f FORWARD_SCHEME                       Scheme for forwarding (http/https, default: $(colorize_booleanh $FORWARD_SCHEME))"
  echo -e "  -c CACHING_ENABLED                      Enable caching (true/false, default: $(colorize_boolean $CACHING_ENABLED))"
  echo -e "  -b BLOCK_EXPLOITS                       Block exploits (true/false, default: $(colorize_boolean $BLOCK_EXPLOITS))"
  echo -e "  -w ALLOW_WEBSOCKET_UPGRADE              Allow WebSocket upgrade (true/false, default: $(colorize_boolean $ALLOW_WEBSOCKET_UPGRADE))"
  echo -e "  -l CUSTOM_LOCATIONS                     Custom locations (${COLOR_YELLOW}JSON array${CoR} of location objects)"
  echo -e "  -a ADVANCED_CONFIG                      Advanced configuration (${COLOR_YELLOW}string${CoR})"
  echo -e "  -y                                      Automatic ${COLOR_YELLOW}yes${CoR} prompts!"
  echo ""
  echo -e "  --info                                 📣 ${COLOR_YELLOW}Display${CoR}  Script Variables Information"
  echo -e "  --show-default                         🔍 ${COLOR_YELLOW}Show${CoR}     Default settings for creating hosts"
  echo -e "  --check-token                          🔧 ${COLOR_YELLOW}Check${CoR}    Check current token info"
  echo -e "  --host-search hostname                 🔍 ${COLOR_GREEN}Search${CoR}   Proxy host by domain name"
  echo ""
  echo -e "  --backup                               📦 ${COLOR_GREEN}Backup${CoR}   All configurations to a different files in \$BACKUP_DIR"
  echo -e "  --backup-host id                       📦 ${COLOR_GREEN}Backup${CoR}   Single host configuration and its certificate (if exists)"
  #echo -e "  --restore                              📦 ${COLOR_GREEN}Restore${CoR} All configurations from a backup file"
  #echo -e "  --restore-host id                      📦 ${COLOR_GREEN}Restore${CoR} Restore single host with list with empty arguments or a Domain name"
  echo ""
  echo -e "  --create-user user pass email          👤 ${COLOR_GREEN}Create${CoR}   User with a ${COLOR_YELLOW}username, ${COLOR_YELLOW}password${CoR} and ${COLOR_YELLOW}email${CoR}"
  echo -e "  --delete-user ID                       🗑️ ${COLOR_ORANGE} Delete${CoR}   User by ${COLOR_YELLOW}username${CoR}"
  echo ""
  echo -e "  --host-list                            📋 ${COLOR_YELLOW}List${CoR}     All Proxy hosts (to find ID)"
  echo -e "  --host-list-full                       📋 ${COLOR_YELLOW}List${CoR}     All Proxy hosts full details (JSON)"
  echo -e "  --list-users                           📋 ${COLOR_YELLOW}List${CoR}     All Users"
  echo ""
  echo -e "  --host-show id                         🔍 ${COLOR_YELLOW}Show${CoR}     Full details for a specific host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-enable id                       ✅ ${COLOR_GREEN}Enable${CoR}   Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-disable id                      ❌ ${COLOR_ORANGE}Disable${CoR}  Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-delete id                       🗑️ ${COLOR_ORANGE} Delete${CoR}   Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo ""
  echo -e "  --access-list                          📋 ${COLOR_YELLOW}List${CoR}     All available Access Lists (ID and Name)"
  echo ""
  echo -e "  --host-acl-enable id,access_list_id    ✅ ${COLOR_GREEN}Enable   ACL${CoR} for Proxy host by ${COLOR_YELLOW}ID${CoR} with Access List ID (e.g., --host-acl-enable 16,2)"
  echo -e "  --host-acl-disable id                  ❌ ${COLOR_ORANGE}Disable  ACL${CoR} for Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo ""
  echo -e "  --host-ssl-enable id                   🔒 ${COLOR_GREEN}Enable${CoR}   SSL, HTTP/2, and HSTS for a proxy host (Enabled only if exist, check ${COLOR_ORANGE}--generate-cert${CoR} to creating one)"
  echo -e "  --host-ssl-disable id                  🔓 ${COLOR_ORANGE}Disable${CoR}  SSL, HTTP/2, and HSTS for a proxy host"
  echo -e "  --list-ssl-certificates [domain]       📋 ${COLOR_YELLOW}List${CoR}     All SSL certificates availables or filtered by [domain name]  (JSON)"  
  echo -e "  --generate-cert domain email           🌀 ${COLOR_GREEN}Generate${CoR} Certificate for the given '${COLOR_YELLOW}domain${CoR}' and '${COLOR_YELLOW}email${CoR}'"
  echo -e "  --delete-cert domain                   🗑️ ${COLOR_ORANGE} Delete${CoR}   Certificate for the given '${COLOR_YELLOW}domain${CoR}' "
  echo ""
  echo -e "  --update-host id field=value           🔄 ${COLOR_GREEN}Update${CoR}   One specific field of an existing proxy host by ${COLOR_YELLOW}ID${CoR} (e.g., --update-host 42 forward_host=foobar.local)"
  echo ""
  echo -e "  --examples                             🔖 ${COLOR_YELLOW}Examples${CoR} commands, more explicits"

  echo -e "  --help                                 👉 ${COLOR_YELLOW}It's me${CoR}"
  echo ""
  exit 0
}

################################
# Examples CLI Commands
################################
# Examples CLI Commands
examples_cli() {

    echo -e "\n${COLOR_YELLOW}💡 Tips:${CoR}"
    echo -e "  • Use -y flag to skip confirmation prompts"
    echo -e "  • Check --help for complete command list"
    echo -e "  • Always backup before making major changes"
    echo -e "  • Use --host-list to find host IDs\n"
    echo -e "\n${COLOR_YELLOW}🔰 Common Usage Examples:${CoR}"
    # Commandes de base
    echo -e "\n${COLOR_GREEN}📋 Basic Commands:${CoR}"
    echo -e "${COLOR_GREY}  # List all hosts in table format${CoR}"
    echo -e "  $0 --host-list"
    echo -e "${COLOR_GREY}  # Show detailed information about a specific host${CoR}"
    echo -e "  $0 --host-show 42"
    echo -e "${COLOR_GREY}  # Display default settings${CoR}"
    echo -e "  $0 --show-default"
    # Backup & Restore
    echo -e "\n${COLOR_GREEN}📦 Backup Operations:${CoR}"
    echo -e "${COLOR_GREY}  # Backup all configurations${CoR}"
    echo -e "  $0 --backup"
    echo -e "${COLOR_GREY}  # Backup specific host${CoR}"
    echo -e "  $0 --backup-host 42"
    # Host Management
    echo -e "\n${COLOR_GREEN}🌐 Host Management:${CoR}"
    echo -e "${COLOR_GREY}  # Create new proxy host (basic)${CoR}"
    echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080"
    echo -e "${COLOR_GREY}  # Create host with SSL and advanced config${CoR}"
    echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080 --generate-cert example.com admin@example.com"
    echo -e "${COLOR_GREY}  # Create host with custom locations${CoR}"
    echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080 -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"
    # SSL Management
    echo -e "\n${COLOR_GREEN}🔒 SSL Certificate Management:${CoR}"
    echo -e "${COLOR_GREY}  # Generate new SSL certificate${CoR}"
    echo -e "  $0 --generate-cert example.com admin@example.com"
    echo -e "${COLOR_GREY}  # Enable SSL for existing host${CoR}"
    echo -e "  $0 --host-ssl-enable 42"
    echo -e "${COLOR_GREY}  # List all SSL certificates${CoR}"
    echo -e "  $0 --list-ssl-certificates"
    # User Management
    echo -e "\n${COLOR_GREEN}👤 User Management:${CoR}"
    echo -e "${COLOR_GREY}  # Create new user${CoR}"
    echo -e "  $0 --create-user john.doe secretpass john.doe@example.com"
    echo -e "${COLOR_GREY}  # List all users${CoR}"
    echo -e "  $0 --list-users"
    echo -e "${COLOR_GREY}  # Delete user${CoR}"
    echo -e "  $0 --delete-user 42"
    # Access Control
    echo -e "\n${COLOR_GREEN}🔑 Access Control Management:${CoR}"
    echo -e "${COLOR_GREY}  # List all access lists${CoR}"
    echo -e "  $0 --access-list"
    echo -e "${COLOR_GREY}  # Enable ACL for a host${CoR}"
    echo -e "  $0 --host-acl-enable 42,2"
    # Advanced Configuration
    echo -e "\n${COLOR_GREEN}⚙️ Advanced Configuration:${CoR}"
    echo -e "${COLOR_GREY}  # Create host with custom headers${CoR}"
    echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP \$remote_addr;'"
    echo -e "${COLOR_GREY}  # Update specific field of existing host${CoR}"
    echo -e "  $0 --update-host 42 forward_host=new.example.com"
    # Maintenance
    echo -e "\n${COLOR_GREEN}🔧 Maintenance Operations:${CoR}"
    echo -e "${COLOR_GREY}  # Check token validity${CoR}"
    echo -e "  $0 --check-token"
    echo -e "${COLOR_GREY}  # Display script information${CoR}"
    echo -e "  $0 --info"
    # Full Option Example
    echo -e "\n${COLOR_GREEN}🔰 Full Option Example:${CoR}"
    echo -e "${COLOR_GREY}  # Create host with all available options${CoR}"
    echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080 \\"
    echo -e "     -f https \\"
    echo -e "     -c true \\"
    echo -e "     -b true \\"
    echo -e "     -w true \\"
    echo -e "     -a 'proxy_set_header X-Real-IP \$remote_addr;' \\"
    echo -e "     -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"
    echo -e "\n${COLOR_GREY}  Where:${CoR}"
    echo -e "   -d : Domain name"
    echo -e "   -i : Forward host (IP or hostname)"
    echo -e "   -p : Forward port"
    echo -e "   -f : Forward scheme (http/https)"
    echo -e "   -c : Enable caching"
    echo -e "   -b : Block exploits"
    echo -e "   -w : Allow WebSocket upgrade"
    echo -e "   -a : Advanced configuration"
    echo -e "   -l : Custom locations (JSON array)"

    exit 0
}

################################
# Display script variables info
display_info() {

  check_dependencies
  check_nginx_access

  echo -e "\n${COLOR_YELLOW} Script Info:  ${COLOR_GREEN}${VERSION}${CoR}"
  echo -e " ${COLOR_YELLOW}Script Variables Information:${CoR}"
  echo -e "  ${COLOR_GREEN}BASE_DIR${CoR}    ${BASE_DIR}"
  echo -e "  ${COLOR_YELLOW}Config${CoR}      ${BASE_DIR}/nginx_proxy_manager_cli.conf"
  echo -e "  ${COLOR_GREEN}BASE_URL${CoR}    ${BASE_URL}"
  echo -e "  ${COLOR_GREEN}NGINX_IP${CoR}    ${NGINX_IP}"
  echo -e "  ${COLOR_GREEN}API_USER${CoR}    ${API_USER}"
  echo -e "  ${COLOR_GREEN}BACKUP_DIR${CoR}  ${BACKUP_DIR}"

  if [ -d "$BACKUP_DIR" ]; then
    backup_count=$(ls -1 "$BACKUP_DIR" | wc -l)
    echo -e "  ${COLOR_GREEN}BACKUP HOST ${COLOR_YELLOW}$backup_count ${CoR}"
  else
    echo -e "  ${COLOR_RED}Backup directory does not exist.${CoR}"
  fi

  if [ -f "$TOKEN_FILE" ]; then
    echo -e "  ${COLOR_GREEN}Token NPM ${COLOR_YELLOW}  $TOKEN_FILE ${CoR}"
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

  echo -e "\n --help (Show all commands)"
}


# Function to display dashboard
display_dashboard() {
    echo -e "\n${COLOR_YELLOW}📊 NGINX - Proxy Manager - Dashboard 🔧 ${CoR}"
    echo -e "${COLOR_GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CoR}"

    # Get proxy hosts count
    local proxy_hosts=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    local proxy_count=$(echo "$proxy_hosts" | jq '. | length')
    local enabled_proxy_count=$(echo "$proxy_hosts" | jq '[.[] | select(.enabled == true)] | length')

    # Get redirection hosts count
    local redirection_hosts=$(curl -s -X GET "$BASE_URL/nginx/redirection-hosts" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    local redirect_count=$(echo "$redirection_hosts" | jq '. | length')

    # Get stream hosts count
    local stream_hosts=$(curl -s -X GET "$BASE_URL/nginx/streams" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    local stream_count=$(echo "$stream_hosts" | jq '. | length')

    # Get certificates count
    local certificates=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    local cert_count=$(echo "$certificates" | jq '. | length')
    # Correction ici : on compte les certificats où expired est false
    local expired_cert_count=$(echo "$certificates" | jq '[.[] | select(.expired == true)] | length')
    local valid_cert_count=$((cert_count - expired_cert_count))

    # Get users count
    local users=$(curl -s -X GET "$BASE_URL/users" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    local user_count=$(echo "$users" | jq '. | length')

    # Display counts with icons and colors
    echo -e "\n ${COLOR_GREEN}🌐 Proxy Hosts:${CoR}"
    echo -e "   • Total:    ${COLOR_YELLOW}$proxy_count${CoR}"
    echo -e "   • Enabled:  ${COLOR_GREEN}$enabled_proxy_count${CoR}"
    echo -e "   • Disabled: ${COLOR_RED}$((proxy_count - enabled_proxy_count))${CoR}"

    echo -e "\n ${COLOR_GREEN}🔄 Redirections:${CoR}"
    echo -e "   • Total: ${COLOR_YELLOW}$redirect_count${CoR}"

    echo -e "\n ${COLOR_GREEN}🔌 Stream Hosts:${CoR}"
    echo -e "   • Total: ${COLOR_YELLOW}$stream_count${CoR}"

    echo -e "\n ${COLOR_GREEN}🔒 SSL Certificates:${CoR}"
    echo -e "   • Total:   ${COLOR_YELLOW}$cert_count${CoR}"
    echo -e "   • Valid:   ${COLOR_GREEN}$valid_cert_count${CoR}"
    echo -e "   • Expired: ${COLOR_RED}$((cert_count - valid_cert_count))${CoR}"

    echo -e "\n ${COLOR_GREEN}👥 Users:${CoR}"
    echo -e "   • Total: ${COLOR_YELLOW}$user_count${CoR}"

    # Display server status if available
    echo -e "\n ${COLOR_GREEN}🆙 Server Status:${CoR}"
    local uptime=$(uptime | sed 's/.*up \([^,]*\),.*/\1/')
    echo -e "   • Uptime: ${COLOR_YELLOW}$uptime${CoR}"
    
    # Display version info if available
    local version_info=$(curl -s -X GET "$BASE_URL/nginx/version" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    if [ -n "$version_info" ]; then
        echo -e "   • Version: ${COLOR_YELLOW}$(echo "$version_info" | jq -r '.version')${CoR}"
    fi

    echo -e "\n${COLOR_GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CoR}"
    echo -e "${COLOR_YELLOW}💡 Use --help to see available commands${CoR}\n"
}

# shellcheck disable=SC2120
# check_no_arguments() {
#   if [ $# -eq 0 ]; then
#     echo -e "\n ${COLOR_RED}No arguments provided. Use --help to see all command options.${CoR}"
#     echo ""
#     #display_info
#     exit 1
#   fi
# }

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

# Validate the existing token
validate_token() {
  if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ]; then
    echo -e "\n ⛔ ${COLOR_RED}No valid token found. Generating a new token...${CoR}"
    generate_token
    return
  fi

  # Check the expiration
  local expires=$(cat "$EXPIRY_FILE")
  local current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local expiry_timestamp=$(date -d "$expires" +%s)
  local current_timestamp=$(date -d "$current_time" +%s)
  local time_diff=$((expiry_timestamp - current_timestamp))

  # Renew the token if less than 1 hour before expiration
  if [ $time_diff -lt 3600 ]; then
    echo -e " 🔄 ${COLOR_YELLOW}Token expires soon. Generating new token...${CoR}"
    generate_token
  fi

}

# Renew the token if needed
renew_token_if_needed() {
  if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ]; then
    generate_token
    return 1
  fi

  local token=$(cat "$TOKEN_FILE")
  local expires=$(cat "$EXPIRY_FILE")
  local current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  if [[ $(date -d "$current_time" +%s) -ge $(date -d "$expires" +%s) ]]; then
    generate_token
    return 1
  fi
  
  
  return 0
}

################################
# Generate a new API token
generate_token() {
  # Step 1: Get initial token
  initial_response=$(curl -s -X POST "$BASE_URL$API_ENDPOINT" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "{\"identity\":\"$API_USER\",\"secret\":\"$API_PASS\"}")

  initial_token=$(echo "$initial_response" | jq -r '.token')
  
  if [ "$initial_token" = "null" ]; then
    echo -e "  ${COLOR_RED}Error getting initial token - Check credentials${CoR}"
    exit 1
  fi

  # Step 2: Renew with desired expiry
  renew_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X GET "$BASE_URL$API_ENDPOINT?expiry=$TOKEN_EXPIRY" \
    -H "Authorization: Bearer $initial_token" \
    -H "Accept: application/json")

  HTTP_BODY=$(echo "$renew_response" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$renew_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ "$HTTP_STATUS" -eq 200 ]; then
    new_token=$(echo "$HTTP_BODY" | jq -r '.token')
    new_expires=$(echo "$HTTP_BODY" | jq -r '.expires')

    if [ "$new_token" != "null" ]; then
      echo "$new_token" > "$TOKEN_FILE"
      echo "$new_expires" > "$EXPIRY_FILE"
      echo -e "  ✅ ${COLOR_GREEN}New token generated, valid until: $new_expires (${TOKEN_EXPIRY})${CoR}"
    else
      echo -e " ⚠️  ${COLOR_RED}Error: Invalid token response${CoR}"
      exit 1
    fi
  else
    echo -e " ⚠️  ${COLOR_RED}Error renewing token. Status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}"
    exit 1
  fi
}

################################
# Check token validity 
check_token_validity() {
    echo -e "\n🔑 Checking token validity..."
    
    if [ ! -f "$TOKEN_FILE" ]; then
        echo -e "⛔ ${COLOR_RED}No token file found. Generating new token...${CoR}"
        generate_token
        return
    fi

    # Get token expiry date
    if [ ! -f "$EXPIRY_FILE" ]; then
        echo -e "⛔ ${COLOR_RED}No expiry file found. Generating new token...${CoR}"
        generate_token
        return
    fi

    local token=$(cat "$TOKEN_FILE")
    local expires=$(cat "$EXPIRY_FILE")
    local current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Test token with a simple API call
    local test_response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -H "Authorization: Bearer $token" \
        "$BASE_URL/tokens")
    
    local http_status=$(echo "$test_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$http_status" -eq 200 ]; then
        echo -e "✅ ${COLOR_GREEN}Token is valid${CoR}"
        echo -e "📅 Expires: ${COLOR_YELLOW}$expires${CoR}"
    else
        echo -e "⛔ ${COLOR_RED}Token is invalid or expired. Generating new token...${CoR}"
        generate_token
    fi
}

check_token_validity_back() {
  if renew_token_if_needed; then
    exit 0
  else
    exit 1
  fi
}

 
#################################
# Main menu logic
#################################
while getopts "d:i:p:f:c:b:w:a:l:y-:" opt; do
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
    y) AUTO_YES=true ;;
    -)
      case "${OPTARG}" in
          show-default) SHOW_DEFAULT=true ;;
          backup) BACKUP=true ;;
          backup-host)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              if [ -z "$HOST_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --backup-host option requires a host ID.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                exit 1
              fi
              BACKUP_HOST=true
              ;;
          backup-list)  BACKUP_LIST=true  ;;              
          restore-host)
              if [ -n "${!OPTIND}" ] && [[ "${!OPTIND}" != -* ]]; then
                RESTORE_HOST=true
                DOMAIN="${!OPTIND}"; shift
              else
                list_backups
                echo -n "Enter domain to restore: "
                read DOMAIN
                RESTORE_HOST=true
              fi
              ;;
          ssl-regenerate) validate_token; SSL_REGENERATE=true ;;
          ssl-restore) validate_token; SSL_RESTORE=true ;;
          create-user)
              validate_token
              USERNAME="${!OPTIND}"; shift
              PASSWORD="${!OPTIND}"; shift
              EMAIL="${!OPTIND}"; shift
              if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$EMAIL" ]; then
                  echo -e "\n 👤 ${COLOR_RED}The --create-user option requires username, password, and email.${CoR}"
                  echo -e " Usage: ${COLOR_ORANGE}$0 --create-user username password email${CoR}"
                  echo -e " Example:"
                  echo -e "   ${COLOR_GREEN}$0 --create-user john secretpass john@domain.com${CoR}\n"
                  exit 1
              fi
              CREATE_USER=true
              ;;
          delete-user)
              validate_token
              USER_ID="${!OPTIND}"; shift
              if [ -z "$USER_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --delete-user option requires a user ID.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --list-users${CoR}\n"
                exit 1
              fi
              DELETE_USER=true
              ;;
          host-delete)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              if [ -z "$HOST_ID" ]; then
                  echo -e "\n 🗑️ ${COLOR_RED}The --host-delete option requires a host ID.${CoR}"
                  echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                  exit 1
              fi
              DELETE_HOST=true
              ;;
          host-show)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              if [ -z "$HOST_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --host-show option requires a host ID.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                exit 1
              fi
              HOST_SHOW=true              
              ;;
          host-list) validate_token; LIST_HOSTS=true ;;
          host-list-full) validate_token; LIST_HOSTS_FULL=true ;;
          list-users) validate_token; LIST_USERS=true ;;
          host-search)
              validate_token
              SEARCH_HOSTNAME="${!OPTIND}"; shift
              if [ -z "$SEARCH_HOSTNAME" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --host-search option requires a host name.${CoR}"
                echo -e " Usage: ${COLOR_ORANGE}$0 --host-search hostname${CoR}"
                exit 1
              fi
              SEARCH_HOST=true
              ;;
          host-enable)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              if [ -z "$HOST_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --host-enable option requires a host ID.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                exit 1
              fi
              ENABLE_HOST=true              
              ;;
          host-disable)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              if [ -z "$HOST_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --host-disable option requires a host ID.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                exit 1
              fi
              DISABLE_HOST=true
              ;;
          host-acl-enable)
              validate_token
              # Expecting "HOST_ID,ACCESS_LIST_ID"
              ACL_ARG="${!OPTIND}"; shift
              IFS=',' read -r HOST_ID ACCESS_LIST_ID <<< "$ACL_ARG"
              if [ -z "$HOST_ID" ] || [ -z "$ACCESS_LIST_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}Erreur : --host-acl-enable need HOST_ID et ACCESS_LIST_ID separated by a comma (e.g., --host-acl-enable 16,2).${CoR}"
                usage
              fi
              ENABLE_ACL=true
              ;;
          host-acl-disable)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              if [ -z "$HOST_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --host-acl-disable option requires a host ID.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                exit 1
              fi
              DISABLE_ACL=true
              ;;
          check-token) CHECK_TOKEN=true
              ;;
          generate-cert)
              validate_token
              DOMAIN="${!OPTIND}"; shift
              EMAIL="${!OPTIND}"; shift
              if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --generate-cert option requires a domain and email.${CoR}"
                echo -e " Usage: ${COLOR_ORANGE}$0 --generate-cert domain email${CoR}"
                exit 1
              fi
              GENERATE_CERT=true              
              ;;
          delete-cert)
              validate_token
              DOMAIN="${!OPTIND}"; shift
              if [ -z "$DOMAIN" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --delete-cert option requires a domain.${CoR}"
                echo -e " Usage: ${COLOR_ORANGE}$0 --delete-cert domain${CoR}"
                exit 1
              fi
              DELETE_CERT=true              
              ;;
          host-ssl-enable)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              if [ -z "$HOST_ID" ]; then
                echo -e " \n⛔ ${COLOR_RED}Error: Missing host ID for --host-ssl-enable.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                exit 1
              fi
              ENABLE_SSL=true
              ;;
          host-ssl-disable)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              if [ -z "$HOST_ID" ]; then
                echo -e " \n⛔ ${COLOR_RED}Error: Missing host ID for --host-ssl-disable.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                exit 1
              fi
              DISABLE_SSL=true              
              ;;
          force-cert-creation)
              validate_token
              FORCE_CERT_CREATION=true ;;
          list-ssl-certificates)
              validate_token
              DOMAIN="${!OPTIND}"; shift
              if [ -z "$DOMAIN" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --list-ssl-certificates option requires a domain.${CoR}"
                echo -e " Usage: ${COLOR_ORANGE}$0 --list-ssl-certificates domain${CoR}"
                exit 1
              fi
              LIST_SSL_CERTIFICATES=true             
              ;;
          access-list) validate_token; ACCESS_LIST=true  ;;
          update-host)
              validate_token
              HOST_ID="${!OPTIND}"; shift
              FIELD_VALUE="${!OPTIND}"; shift
              if [ -z "$FIELD_VALUE" ]; then
                echo -e "\n ⛔ ${COLOR_RED}The --update-host option requires a field value.${CoR}"
                echo -e " Usage: ${COLOR_ORANGE}$0 --update-host host_id field=value${CoR}"
                exit 1
              fi
              FIELD=$(echo "$FIELD_VALUE" | cut -d= -f1)
              VALUE=$(echo "$FIELD_VALUE" | cut -d= -f2-)
              UPDATE_FIELD=true
              ;;
          examples) EXAMPLES=true ;;
          info)  INFO=true ;;
          debug) DEBUG=true ;;
          help) usage; exit 0  ;;
      esac ;;
      *) INFO=true  # display_info; exit 0
       ;;
  esac
done

# If no arguments are provided, display usage
if [ $# -eq 0 ]; then
  #echo -e "\n  Unknown option --${OPTARG}" ; 
  #display_info
  # usage
    if renew_token_if_needed; then
        display_dashboard
    fi
  exit 0
fi

# For invalid commands, show simplified error message
if ! [[ "$*" =~ ^--(help|examples|info|host-list|host-list-full|list-users|check-token|backup|access-list|host-search|host-show|host-enable|host-disable|host-delete|host-acl-enable|host-acl-disable|create-user|delete-user|generate-cert|delete-cert|host-ssl-enable|host-ssl-disable|list-ssl-certificates|update-host).*$ ]] && ! [[ "$*" =~ ^-(d|i|p|f|c|b|w|a|l|y).* ]]; then
    echo -e "\n${COLOR_RED}⚠️  Invalid or missing command! ${CoR}"
    echo -e "\n${COLOR_YELLOW}💡 Help:${CoR}"
    echo -e "  • Use   ${COLOR_ORANGE}$0 --help${CoR}        to see all available options"
    echo -e "  • Check ${COLOR_ORANGE}$0 --examples${CoR}    for more usage examples"
    echo -e "  • Check ${COLOR_ORANGE}$0 --info${CoR}        for more information\n"
    echo -e "  • Check ${COLOR_ORANGE}$0 --host-search${CoR}    for host search"
    echo -e "  • Check ${COLOR_ORANGE}$0 --host-show${CoR}      for host show"
    echo -e "  • Check ${COLOR_ORANGE}$0 --host-enable${CoR}    for host enable"
    echo -e "  • Check ${COLOR_ORANGE}$0 --create-user${CoR}     for create user"
    echo -e "  • Check ${COLOR_ORANGE}$0 --generate-cert${CoR}   for generate cert"
    echo -e "  • Check ${COLOR_ORANGE}$0 --host-ssl-enable${CoR} for host ssl enable\n"

    exit 1
fi

################################
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

# List all access lists
list_access() {
    echo -e "\n📋 Available Access Lists:"  
    local response=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")

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

    # Afficher les détails des clients pour chaque liste
    echo -e "${COLOR_YELLOW}Details of Access Lists:${CoR}"
    echo "$response" | jq -r '.[] | "🔒 List: \(.name) (ID: \(.id))
   • Pass Auth: \(.pass_auth)
   • Satisfy: \(.satisfy)
   • Clients (\(.clients | length)):\(.clients | if length > 0 then map("     - \(.address)") | join("\n") else " (No clients)" end)"'
    echo -e "\n"

  exit 0
}

##############################################################
# Function to confirm dangerous operations  
confirm_dangerous_operation() {
    local operation=$1
    local id=$2
    
    if [ "$AUTO_YES" = true ]; then
        return 0
    fi
    
    echo -e "\n📣 ${COLOR_RED}Warning: You are about to $operation ID: $id${CoR}"
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
# ACL  proxy host 
enable_acl() {
  if [ -z "$HOST_ID" ] || [ -z "$ACCESS_LIST_ID" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Error: HOST_ID and ACCESS_LIST_ID are required to enable the ACL.${CoR}"
    usage
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
    -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

  if [ "$(echo "$RESPONSE" | jq -r '.error | length')" -eq 0 ]; then
    echo -e " ✅ ${COLOR_GREEN}ACL successfully enabled for host ID $HOST_ID!${CoR}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to enable ACL. Error: $(echo "$RESPONSE" | jq -r '.message')${CoR}\n"
  fi
}

# Disable ACL for a given proxy host
disable_acl() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Error: HOST_ID is required to disable the ACL.${CoR}"
    usage
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
    -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

  if [ "$(echo "$RESPONSE" | jq -r '.error | length')" -eq 0 ]; then
    echo -e " ✅ ${COLOR_GREEN}ACL successfully disabled for host ID $HOST_ID!${CoR}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to disable ACL. Error: $(echo "$RESPONSE" | jq -r '.message')${CoR}\n"
  fi
}

# Function to check if the host ID exists
host-check-id() {
  local host_id=$1
  # shellcheck disable=SC2155
  local host_list=$($0 --host-list)

  if echo "$host_list" | grep -q ""id": $host_id"; then
    return 0
  else
    echo "Error: Host ID $host_id does not exist."
    exit 1
  fi
}



######################################
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


######################################

# Function to regenerate SSL certificates for all hosts
regenerate_all_ssl_certificates() {
  echo -e "\n🔄 Regenerating SSL certificates for all hosts..."

  # shellcheck disable=SC2155
  local hosts=$(curl -s -X GET -H "Authorization: Bearer $TOKEN" "$NGINX_API_URL/nginx/proxy-hosts")
  
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
delete_all_proxy_hosts() {
  echo -e "\n 🗑️ ${COLOR_ORANGE}Deleting all existing proxy hosts...${CoR}"

  existing_hosts=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)" | jq -r '.[].id')

  for host_id in $existing_hosts; do
    echo -e " 💣 Deleting host ID $host_id..."
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/nginx/proxy-hosts/$host_id" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)")

    http_body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
    http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$http_status" -ne 200 ]; then
      echo -e " ⛔ ${COLOR_RED}Failed to delete host ID $host_id. HTTP status: $http_status. Response: $http_body${CoR}"
      return 1
    fi
  done

  echo -e " ✅ ${COLOR_GREEN}All existing proxy hosts deleted successfully!${CoR}"
  return 0
}


##############################################################
# Delete a proxy host by ID
delete_proxy_host() {
    local host_id=$1
    
    # Vérifier si l'ID est fourni
    if [ -z "$host_id" ]; then
        echo -e "\n 🗑️ ${COLOR_RED}The --host-delete option requires a host ID.${CoR}"
        echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
        return 1
    fi
    
    # Confirmer l'opération
    if ! confirm_dangerous_operation "delete host" "$host_id"; then
        return 1
    fi
    
    echo -e " 🗑️ Deleting proxy host ID: ${host_id}..."
    
    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/nginx/proxy-hosts/${host_id}" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")

    HTTP_BODY=$(echo "$RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e " ✅ ${COLOR_GREEN}Proxy host $host_id deleted successfully!${CoR}"
        return 0
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete proxy host. Status: $HTTP_STATUS. Error: $HTTP_BODY${CoR}"
        return 1
    fi
}

################################
# Check if a proxy host with the given domain names already exists
check_existing_proxy_host() {
  echo -e "\n 🔎 Checking if proxy host $DOMAIN_NAMES already exists..."

  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

#  echo -e "\n 🔍 Raw API Response: $RESPONSE"  # Debugging API response
  EXISTING_HOST=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN_NAMES" '.[] | select(.domain_names[] == $DOMAIN)')

  if [ -n "$EXISTING_HOST" ]; then
    echo -e "\n 🔔 Proxy host for $DOMAIN_NAMES already exists."
    if [ "$AUTO_YES" = true ]; then
        REPLY="y"
        echo -e "🔔 Option -y detected. Skipping confirmation prompt and proceeding with update..."
    else
        read -p " 👉 Do you want to update it? (y/n): " -r
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

################################
# Update an existing proxy host
update_proxy_host() {
  HOST_ID=$1
  echo -e "\n 🔄 Updating proxy host for $DOMAIN_NAMES..."

  # 🔥 Vérifier que les variables obligatoires sont bien définies
  if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ] || [ -z "$FORWARD_SCHEME" ]; then
    echo -e "  ⛔${COLOR_RED} ERROR: Missing required parameters (domain, forward host, forward port, forward scheme).${CoR}"
    exit 1
  fi

  # 🔥 Vérifier que FORWARD_PORT est un nombre valide
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

	# 🔍 Debugging variables before JSON update:
	debug_var

  # 🔥 Générer le JSON proprement
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

  # 🔍 Vérifier si le JSON est valide avant l'envoi
  if ! echo "$DATA" | jq empty > /dev/null 2>&1; then
    echo -e "  ⛔${COLOR_RED} ERROR: Invalid JSON generated:\n$DATA ${CoR}"
    exit 1
  fi

  # 🚀 Envoyer la requête API pour mise à jour
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  # 📢 Vérifier la réponse de l'API
  ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // empty')
  if [ -z "$ERROR_MSG" ]; then
    echo -e "\n  ✅ ${COLOR_GREEN}SUCCESS: Proxy host 🔗$DOMAIN_NAMES updated successfully! 🎉${CoR}"
  else
    echo -e "  ⛔ ${COLOR_RED}Failed to update proxy host. Error: $ERROR_MSG ${CoR}"
    exit 1
  fi
}

###########################
# Create a new proxy host
create_new_proxy_host() {
  echo -e "\n 🌍 Creating proxy host for $DOMAIN_NAMES..."

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

  # 🔥 Générer le JSON proprement  
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

  # Vérifier si le JSON est valide avant l'envoi
  if ! echo "$DATA" | jq empty > /dev/null 2>&1; then
    echo -e " ${COLOR_RED} ⛔ ERROR: Invalid JSON generated:\n$DATA ${CoR}"
    exit 1
  fi

  # 🚀 Send API payload
  RESPONSE=$(curl -s -X POST "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")

  # 📢 Check answer from API
  ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // empty')
if [ -z "$ERROR_MSG" ]; then
    echo -e "\n  ${COLOR_GREEN} ✅  SUCCESS: Proxy host 🔗$DOMAIN_NAMES was created successfully! 🎉${CoR}\n"
else
    echo -e "  ⛔${COLOR_RED} Failed to create proxy host. Error: $ERROR_MSG ${CoR}"
    exit 1
fi

	# 🔥 Affichage du JSON généré
	echo -e "\n📝 JSON envoyé à l'API :"
	echo "$DATA" | jq .
}

###############################
# Create or update a proxy host based on the existence of the domain
create_or_update_proxy_host() {
  if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ]; then
        echo -e "\n${COLOR_RED}⚠️  Missing Required Options:${CoR}"
        echo -e " The following options are required to create/update a proxy host:"
        echo -e "   -d DOMAIN     : Domain name ${COLOR_GREY}(e.g., example.com)${CoR}"
        echo -e "   -i HOST       : Forward host ${COLOR_GREY}(e.g., 192.168.1.10)${CoR}"
        echo -e "   -p PORT       : Forward port ${COLOR_GREY}(e.g., 8080)${CoR}"
        
        echo -e "\n${COLOR_YELLOW}📝 Example:${CoR}"
        echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080"
        
        echo -e "\n${COLOR_YELLOW}💡 Help:${CoR}"
        echo -e "  • Use --help to see all available options"
        echo -e "  • Check --examples for more usage examples\n"
        
        exit 1
  fi

  check_existing_proxy_host
}


################################
# Update field of existing proxy host
update_field() {
  HOST_ID="$1"
  FIELD="$2"
  NEW_VALUE="$3"

  # ✅ 1) Vérifier si les trois arguments sont passés
  if [ -z "$HOST_ID" ] || [ -z "$FIELD" ] || [ -z "$NEW_VALUE" ]; then
    echo -e "  ⛔ ${COLOR_RED}ERROR:${CoR} Missing parameters. Usage:"
    echo -e "  ./nginx_proxy_manager_cli.sh --update-host ID FIELD=VALUE"
    exit 1
  fi

  # ✅ 2) Récupérer la config complète du proxy depuis l'API
  CURRENT_DATA=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")")

  # Vérifier qu'elle est valide
  if ! echo "$CURRENT_DATA" | jq empty > /dev/null 2>&1; then
    echo -e "  ⛔ ${COLOR_RED}ERROR:${CoR} Failed to fetch current proxy configuration."
    exit 1
  fi

  # ✅ 3) Filtrer les champs autorisés par l’API (liste blanche)
  #    (Retire ainsi les champs qui causent 'additional properties')
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

  # ✅ 4)  Modifier UN champ dans l'objet filtré
  #     Certains champs (comme forward_port) doivent être convertis en nombre
  if [ "$FIELD" = "forward_port" ]; then
    # Si c'est forward_port, on force en nombre
    UPDATED_DATA=$(echo "$FILTERED_DATA" \
      | jq --argjson newVal "$(echo "$NEW_VALUE" | jq -R 'tonumber? // 0')" \
           '.forward_port = $newVal')
  else
    # Sinon, on traite la nouvelle valeur comme une chaîne
    UPDATED_DATA=$(echo "$FILTERED_DATA" \
      | jq --arg newVal "$NEW_VALUE" \
           ".$FIELD = \$newVal")
  fi

  # Vérifier si le JSON final est valide
  if ! echo "$UPDATED_DATA" | jq empty > /dev/null 2>&1; then
    echo -e "  ⛔ ${COLOR_RED}ERROR: Invalid JSON generated:${CoR}\n$UPDATED_DATA"
    exit 1
  fi

  # ✅ 5) Envoyer la mise à jour via API (PUT)
  echo -e "\n  🔄 Updating proxy host ${COLOR_ORANGE}🆔${CoR} ${COLOR_YELLOW}$HOST_ID${CoR} with ${COLOR_ORANGE}$FIELD${CoR} ${COLOR_YELLOW}$NEW_VALUE${CoR}"
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
    -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$UPDATED_DATA")

  # ✅ 6) Vérifier la réponse API
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
list_proxy_hosts() {
  echo -e "\n${COLOR_ORANGE} 👉 List of proxy hosts (simple)${CoR}"
  printf "  %-6s %-36s %-9s %-4s %-36s\n" "ID" "Domain" "Status" "SSL" "Certificate Domain"

  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

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
      -H "Authorization: Bearer $(cat $TOKEN_FILE)")

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
# List all proxy hosts with full details
list_proxy_hosts_full() {
  echo -e "\n${COLOR_ORANGE} 👉 List of proxy hosts with full details...${CoR}\n"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -c '.[]' | while read -r proxy; do
    echo "$proxy" | jq .
  done
  echo ""
  exit 0
}

################################
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

    echo -e " 🔎 id: ${COLOR_YELLOW}$id${CoR} ${COLOR_GREEN}$domain_names${CoR}"
  done
	echo ""
}

# List all SSL certificates
list_ssl_certificates_back() {
  echo " 👉 List of SSL certificates..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq
}

################################
# Function to list all SSL certificates or filter by domain
list_ssl_certificates() {

  # Regex to validate domain or subdomain
  DOMAIN_REGEX="^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

  if [ -n "$DOMAIN" ]; then
    # Validate domain format
    if [[ ! $DOMAIN =~ $DOMAIN_REGEX ]]; then
      echo " ⛔ Invalid domain format: $DOMAIN"
      exit 1
    fi

    echo " 👉 Listing SSL certificates for domain: $DOMAIN..."

    # Fetch all certificates
    RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)")

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
    -H "Authorization: Bearer $(cat $TOKEN_FILE)")

    # List all certificates
    echo "$RESPONSE" | jq
  fi
}

############################
# List all users
list_users() {
  echo -e "\n 👉 List of users..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo -e "\n $RESPONSE" | jq
  exit 0
}

############################
# Create a new user
create_user() {
  if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$EMAIL" ]; then
    echo -e "\n 👤 ${COLOR_RED}The --create-user option requires username, password, and email.${CoR}"
    echo -e " Usage: ${COLOR_ORANGE}$0 --create-user username password email${CoR}"
    echo -e " Example:"
    echo -e "   ${COLOR_GREEN}$0 --create-user john secretpass john@domain.com${CoR}\n"
    return 1
  fi

  # Vérifier si l'utilisateur existe déjà
  EXISTING_USERS=$(curl -s -X GET "$BASE_URL/users" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  
  # Vérifier si l'email existe déjà
  if echo "$EXISTING_USERS" | jq -e --arg email "$EMAIL" '.[] | select(.email == $email)' > /dev/null; then
      echo -e "\n ⛔ ${COLOR_RED}Error: A user with email $EMAIL already exists.${CoR}"
      return 1
  fi

  # Vérifier si le nom d'utilisateur existe déjà
  if echo "$EXISTING_USERS" | jq -e --arg name "$USERNAME" '.[] | select(.name == $name)' > /dev/null; then
      echo -e "\n ⛔ ${COLOR_RED}Error: A user with name $USERNAME already exists.${CoR}"
      return 1
  fi

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

    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/users" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
        -H "Content-Type: application/json; charset=UTF-8" \
        --data-raw "$DATA")

    HTTP_BODY=$(echo "$RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 201 ]; then
        # Déboguer la réponse si nécessaire
        echo "Debug response: $HTTP_BODY" >> /tmp/npm_debug.log

        # Récupérer l'ID du nouvel utilisateur en listant tous les utilisateurs
        USERS_RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
            -H "Authorization: Bearer $(cat $TOKEN_FILE)")
        
        USER_ID=$(echo "$USERS_RESPONSE" | jq -r --arg email "$EMAIL" --arg name "$USERNAME" \
            '.[] | select(.email == $email and .name == $name) | .id')

        if [ -n "$USER_ID" ]; then
            echo -e " ✅ ${COLOR_GREEN}User $USERNAME created successfully!${CoR}"
            echo -e " 📧 Email: ${COLOR_YELLOW}$EMAIL${CoR}"
            echo -e " 🆔 User ID: ${COLOR_YELLOW}$USER_ID${CoR}\n"            
        else
            echo -e " ✅ ${COLOR_GREEN}User created but couldn't fetch ID${CoR}"
            echo -e " 📧 Email: ${COLOR_YELLOW}$EMAIL${CoR}\n"
        fi
        return 0
    else
        echo -e " ⛔ ${COLOR_RED}Failed to create user. Status: $HTTP_STATUS${CoR}"
        echo -e " Error: ${COLOR_RED}$HTTP_BODY${CoR}\n"
        return 1
    fi
  exit 0
}

################################
# Update delete_user function to use ID instead of username
delete_user() {
    local user_id=$1
    
    if [ -z "$user_id" ]; then
        echo -e "\n 🗑️ ${COLOR_RED}The --delete-user option requires a user ID.${CoR}"
        echo -e " To find ID Check with ${COLOR_ORANGE}$0 --list-users${CoR}\n"
        return 1
    fi

    if ! confirm_dangerous_operation "delete user" "$user_id"; then
        return 1
    fi

    echo " 🗑️ Deleting user 👤  ${user_id}..."

    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/users/$user_id" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")

    HTTP_BODY=$(echo "$RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e " ✅ ${COLOR_GREEN}User $user_id deleted successfully!${CoR}"
        return 0
    else
        echo -e " ⛔ ${COLOR_RED}Failed to delete user. Status: $HTTP_STATUS. Error: $HTTP_BODY${CoR}"
        return 1
    fi
  exit 0
}

################################
# Enable a proxy host by ID
enable_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 💣 The --host-enable option requires a host ID."
    usage
  fi

  # Validate that HOST_ID is a number
  if ! [[ "$HOST_ID" =~ ^[0-9]+$ ]]; then
    echo -e " ⛔ ${COLOR_RED}Invalid host ID: $HOST_ID. It must be a numeric value.${CoR}\n"
    exit 1
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
      echo -e " ✅ ${COLOR_GREEN}Proxy host enabled successfully!${CoR}\n"
    else
      echo -e " ⛔ ${COLOR_RED}Failed to enable proxy host. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
    fi
  else
    echo -e " ⛔ ${COLOR_RED}Proxy host with ID $HOST_ID does not exist.${CoR}\n"
  fi
}

############################
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
    echo -e " ✅ ${COLOR_GREEN}Proxy host disabled successfully!${CoR}\n"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to disable proxy host. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
  fi
}

#############################
# Delete a certificate in NPM
delete_certificate() {
  if [ -z "$DOMAIN" ]; then
    echo -e "\n 🛡️ The --delete-cert option requires a domain."
    usage
  fi
  echo -e "\n 👀 Checking if certificate for domain: $DOMAIN exists..."

  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  # Search for the certificate for the specified domain
  EXISTING_CERT=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN" '.[] | select(.domain_names[] == $DOMAIN)')

  if [ -z "$EXISTING_CERT" ]; then
    echo -e " ⛔ No certificate found for domain: $DOMAIN. \n"
    exit 0
  fi

  CERTIFICATE_ID=$(echo "$EXISTING_CERT" | jq -r '.id')
  EXPIRES_ON=$(echo "$EXISTING_CERT" | jq -r '.expires_on')
  PROVIDER=$(echo "$EXISTING_CERT" | jq -r '.provider')

  echo -e " ✅ Certificate found for $DOMAIN (Provider: $PROVIDER, Expires on: $EXPIRES_ON)."

  # Ask for confirmation before deleting the certificate
  if [ "$AUTO_YES" = true ]; then
    echo -e "🔔 The -y option was provided. Skipping confirmation prompt and proceeding with certificate creation..."
    CONFIRM="y"
  else
    read -p "📣 Are you sure you want to delete the certificate for $DOMAIN? (y/n): " CONFIRM
  fi
  if [[ "$CONFIRM" != "y" ]]; then
    echo -e " ❌ Certificate deletion aborted."
    exit 0
  fi

  echo -e " 🗑️ Deleting certificate for domain: $DOMAIN..."

  # Send DELETE request to remove the certificate
  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/nginx/certificates/$CERTIFICATE_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ "$HTTP_STATUS" -eq 204 ] || ([ "$HTTP_STATUS" -eq 200 ] && [ "$HTTP_BODY" == "true" ]); then
    echo -e " ✅ ${COLOR_GREEN}Certificate deleted successfully!${CoR}\n"
  else
    echo " Data sent: Certificate ID = $CERTIFICATE_ID"  # Log the certificate ID being deleted
    echo -e " ⛔ ${COLOR_RED}Failed to delete certificate. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
  fi
}


################################
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
    echo -e " 🔔 Certificate for $DOMAIN already exists and is valid until $EXPIRES_ON.\n"
    exit 0
  fi

  # Ask for confirmation before creating a new certificate
  if [ "$AUTO_YES" = true ]; then
    echo -e "🔔 The -y option was provided. Skipping confirmation prompt and proceeding with certificate creation..."
    CONFIRM="y"
  else
    read -p "⚠️ No existing certificate found for $DOMAIN. Do you want to create a new Let's Encrypt certificate? (y/n): " CONFIRM
  fi

  if [[ "$CONFIRM" != "y" ]]; then
    echo -e " ❌ Certificate creation aborted."
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

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$BASE_URL/users" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "$DATA")

  HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ "$HTTP_STATUS" -eq 201 ]; then
    echo -e " ✅ ${COLOR_GREEN}Certificate generated successfully!${CoR}\n"
  else
    echo " Data sent: $DATA"  # Log the data sent
    echo -e " ⛔ ${COLOR_RED}Failed to generate certificate. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
  fi
}


################################
# Enable SSL for a proxy host
enable_ssl() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 🛡️ The --host-ssl-enable option requires a host ID."
    echo -e "  --host-ssl-enable id                   🔒 ${COLOR_GREEN}Enable${CoR}  SSL, HTTP/2, and HSTS for a proxy host (Enabled only if exist, check ${COLOR_ORANGE}--generate-cert${CoR} to create one)"
    exit 1  # Exit if no HOST_ID is provided
  fi

  # Validate that HOST_ID is a number
  if ! [[ "$HOST_ID" =~ ^[0-9]+$ ]]; then
    echo -e " ⛔ ${COLOR_RED}Invalid host ID: $HOST_ID. It must be a numeric value.${CoR}\n"
    exit 1
  fi

  echo -e "\n ✅ Enabling 🔒 SSL, HTTP/2, and HSTS for proxy host ID: $HOST_ID..."

  # Check host details
  CHECK_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  CERTIFICATE_ID=$(echo "$CHECK_RESPONSE" | jq -r '.certificate_id')
  DOMAIN_NAMES=$(echo "$CHECK_RESPONSE" | jq -r '.domain_names[]')

  # Fetch all certificates (custom and Let's Encrypt)
  CERTIFICATES=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  # Find all certificates for the given domain based on either domain_names or nice_name
  DOMAIN_CERTS=$(echo "$CERTIFICATES" | jq -c --arg domain "$DOMAIN_NAMES" \
    '[.[] | select((.domain_names[] == $domain) or (.nice_name == $domain))]')

  # Count the number of certificates found
  CERT_COUNT=$(echo "$DOMAIN_CERTS" | jq 'length')

  # Ensure CERT_COUNT is treated as an integer
  CERT_COUNT=${CERT_COUNT:-0}

  if [ "$CERT_COUNT" -eq 0 ]; then
    echo -e " ⛔ No certificate associated with this host.\n"

    # Ask user if they want to generate a new certificate
    echo -e "\n 👀 Checking if Let's Encrypt certificate for domain: $DOMAIN_NAMES exists..."
    EXISTING_CERT=$(echo "$CERTIFICATES" | jq -r --arg DOMAIN "$DOMAIN_NAMES" '.[] | select(.domain_names[] == $DOMAIN)')

    if [ -n "$EXISTING_CERT" ]; then
      EXPIRES_ON=$(echo "$EXISTING_CERT" | jq -r '.expires_on')
      echo -e " 🔔 Certificate for $DOMAIN_NAMES already exists and is valid until $EXPIRES_ON.\n"
    else
      if [ "$AUTO_YES" = true ]; then
        echo -e "🔔 The -y option was provided. Skipping confirmation prompt and proceeding with certificate creation..."
        CONFIRM_CREATE="y"
      else
        read -p "⚠️ No certificate found for $DOMAIN_NAMES. Do you want to create a new Let's Encrypt certificate? (y/n): " CONFIRM_CREATE
      fi
      if [[ "$CONFIRM_CREATE" == "y" ]]; then
        # Prompt for email if not set
        read -p "Please enter your email for Let's Encrypt: " EMAIL

        # Call the function to generate the certificate
        DOMAIN="$DOMAIN_NAMES"
        generate_certificate
        return  # Exit after generating the certificate
      else
        echo -e " ❌ Certificate creation aborted. Exiting."
        exit 1
      fi
    fi
  elif [ "$CERT_COUNT" -gt 1 ]; then
    echo " ⚠️ Multiple certificates found for domain $DOMAIN_NAMES. Please select one:"

    # Display the certificates with provider and validity dates
    echo "$DOMAIN_CERTS" | jq -r 'to_entries[] | "\(.key + 1)) Provider: \(.value.provider), Valid From: \(.value.valid_from), Valid To: \(.value.valid_to)"'

    # Ask the user to choose the certificate
    read -p "Enter the number of the certificate you want to use: " CERT_INDEX

    # Ensure proper handling of the selected certificate
    CERT_INDEX=$((CERT_INDEX - 1))  # Adjust for 0-index
    CERTIFICATE_ID=$(echo "$DOMAIN_CERTS" | jq -r ".[$CERT_INDEX].id")

  else
    # Only one certificate found, use it
    CERTIFICATE_ID=$(echo "$DOMAIN_CERTS" | jq -r '.[0].id')
    echo " ✅ Using certificate ID: $CERTIFICATE_ID"
  fi

  # Verify if CERTIFICATE_ID is empty
  if [ -z "$CERTIFICATE_ID" ]; then
    echo " ⛔ No valid certificate ID found. Aborting."
    exit 1
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
    echo -e "\n ✅ ${COLOR_GREEN}SSL, HTTP/2, and HSTS enabled successfully!${CoR}\n"
  else
    echo -e "\n 👉Data sent: $DATA"  # Log the data sent
    echo -e "\n ⛔ ${COLOR_RED}Failed to enable SSL, HTTP/2, and HSTS. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
  fi
}


################################
# list_certificates function
list_certificates() {
  if [ -z "$DOMAIN" ]; then
    echo -e "\n 🌐 The --list-certificates option requires a domain name."
    usage
  fi
  echo -e "\n 📜 Listing all certificates for domain: $DOMAIN..."

  # Fetch all certificates (custom and Let's Encrypt)
  CERTIFICATES=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

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
      echo -e " ✅ ${COLOR_GREEN}SSL disabled successfully!${CoR}\n"
    else
      echo " Data sent: $DATA"  # Log the data sent
      echo -e " ⛔ ${COLOR_RED}Failed to disable SSL. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
    fi
  else
    echo -e " ⛔ ${COLOR_RED}Proxy host with ID $HOST_ID does not exist.${CoR}\n"
  fi
}


#########################################################
# host_show
# Function to show full details for a specific host by ID
 host_show_() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n ⛔ The --host-show option requires a host ID."
    usage
  fi
  echo -e "\n${COLOR_ORANGE} 👉 Full details for proxy host ID: $HOST_ID...${CoR}\n"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

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

    local response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -X GET "$BASE_URL/nginx/proxy-hosts/$host_id" \
        -H "Authorization: Bearer $(cat $TOKEN_FILE)")

    local http_body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
    local http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

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
  echo -e "  Forward Scheme:           $(colorize_booleanh $FORWARD_SCHEME)"
  echo -e "  Caching Enabled:          $(colorize_boolean $CACHING_ENABLED)"
  echo -e "  Block Exploits:           $(colorize_boolean $BLOCK_EXPLOITS)"
  echo -e "  Allow Websocket Upgrade:  $(colorize_boolean $ALLOW_WEBSOCKET_UPGRADE)"
  
  echo -e "\n ${COLOR_GREEN}SSL Settings:${CoR}"
  echo -e "  HTTP/2 Support:           $(colorize_boolean $HTTP2_SUPPORT)"
  echo -e "  SSL Forced:               $(colorize_boolean $SSL_FORCED)"
  echo -e "  HSTS Enabled:             $(colorize_boolean $HSTS_ENABLED)"
  echo -e "  HSTS Subdomains:          $(colorize_boolean $HSTS_SUBDOMAINS)"
  
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
################################
## backup
# Function to make a full backup
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
  # Create subdirectories
  mkdir -p "$BACKUP_DIR/.user"
  mkdir -p "$BACKUP_DIR/.settings"
  mkdir -p "$BACKUP_DIR/.access_lists"
  mkdir -p "$BACKUP_DIR/.ssl"

  # Backup users
  USERS_FILE="$BACKUP_DIR/.user/users_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$USERS_FILE"
    USER_COUNT=$(echo "$RESPONSE" | jq '. | length')
    echo -e " ✅ ${COLOR_GREEN}Users backup completed        🆗${COLOR_GREY}: $USERS_FILE${CoR}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup users.${CoR}"
  fi

  # Backup settings
  SETTINGS_FILE="$BACKUP_DIR/.settings/settings_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/settings" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$SETTINGS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Settings backup completed     🆗${COLOR_GREY}: $SETTINGS_FILE${CoR}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup settings.${CoR}"
  fi

  # Backup SSL certificates
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq -c '.[]' | while read -r cert; do
      CERT_ID=$(echo "$cert" | jq -r '.id')
      CERT_NICE_NAME=$(echo "$cert" | jq -r '.nice_name')
      SANITIZED_CERT_NAME=$(sanitize_name "$CERT_NICE_NAME")
      CERT_FILE="$BACKUP_DIR/.ssl/ssl_cert_${SANITIZED_CERT_NAME}_${CERT_ID}_${NGINX_IP//./_}$DATE.json"
      echo "$cert" | jq '.' > "$CERT_FILE"
    done
    CERT_COUNT=$(echo "$RESPONSE" | jq '. | length')
    echo -e " ✅ ${COLOR_GREEN}SSL certif backup completed   🆗${COLOR_GREY}: $CERT_COUNT certificates saved.${CoR}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup SSL certificates.${CoR}"
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
          echo -e " ⛔ ${COLOR_RED}Failed to backup SSL certificate for certificate ID $CERTIFICATE_ID.${CoR}"
        fi
      else
        echo -e " ⚠️ ${COLOR_YELLOW}No SSL certificate associated with host ID $HOST_ID.${CoR}"
      fi
    done    
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup proxy hosts.${CoR}"
    exit 1
  fi

  echo -e " ✅ ${COLOR_GREEN}Proxy host backup completed   🆗${COLOR_GREY}: $BACKUP_DIR ${CoR}"

  # Backup access lists
  ACCESS_LISTS_FILE="$BACKUP_DIR/.access_lists/access_lists_${NGINX_IP//./_}$DATE.json"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ -n "$RESPONSE" ]; then
    echo "$RESPONSE" | jq '.' > "$ACCESS_LISTS_FILE"
    echo -e " ✅ ${COLOR_GREEN}Access lists backup completed 🆗${COLOR_GREY}: $ACCESS_LISTS_FILE${CoR}"
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup access lists.${CoR}"
    exit 1
  fi

  # Count the number of host directories
  HOST_COUNT=$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)

  # Count total number of backup files
  TOTAL_BACKUPS=$(find "$BACKUP_DIR" -type f -name "*.json" | wc -l)

  echo -e " ✅ ${COLOR_GREEN}Backup 🆗 ${CoR}"
  echo -e " 📦 ${COLOR_YELLOW}Backup Summary:${CoR}"
  echo -e "   - Number of users backed up: ${COLOR_CYAN}$USER_COUNT${CoR}"
  echo -e "   - Number of proxy hosts backed up: ${COLOR_CYAN}$HOST_COUNT${CoR}"
  echo -e "   - Total number of backup files: ${COLOR_CYAN}$TOTAL_BACKUPS${CoR}\n"

  exit 0
}


################################
# backup-host
# Function to backup a single host configuration and its certificate (if exists)
backup_host() {
  if [ -z "$HOST_ID" ]; then
    echo " 📦 The --backup-host option requires a host ID."
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

    echo "$RESPONSE" | jq '.' > "$HOST_DIR/proxy_host_${NGINX_IP//./_}_$DATE.json"
    echo -e "\n ✅ ${COLOR_GREEN}Proxy host backup completed      🆗${COLOR_GREY}: ${HOST_DIR}/proxy_host_${NGINX_IP//./_}_$DATE.json${CoR}"

    # Fetch SSL certificate if it exists
    CERTIFICATE_ID=$(echo "$RESPONSE" | jq -r '.certificate_id')
    if [ "$CERTIFICATE_ID" != "null" ]; then
      CERT_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates/$CERTIFICATE_ID" \
      -H "Authorization: Bearer $(cat $TOKEN_FILE)")
      if [ -n "$CERT_RESPONSE" ]; then
        echo "$CERT_RESPONSE" | jq '.' > "$HOST_DIR/ssl_certif_${NGINX_IP//./_}_$DATE.json"
        echo -e " ✅ ${COLOR_GREEN}SSL certificate backup completed 🆗${COLOR_GREY}: ${HOST_DIR}/ssl_certif_${NGINX_IP//./_}_$DATE.json${CoR}"
      else
        echo -e " ⛔ ${COLOR_RED}Failed to backup SSL certificate for certificate ID $CERTIFICATE_ID.${CoR}"
      fi
    else
      echo -e " ⚠️ ${COLOR_YELLOW}No SSL certificate associated with host ID $HOST_ID.${CoR}"
    fi
  else
    echo -e " ⛔ ${COLOR_RED}Failed to backup proxy host for host ID $HOST_ID.${CoR}"
  fi
  echo ""
}


######################################################
# Function to list global backup files
list_global_backup_files() {
  ls -t "$BACKUP_DIR"/*_*.json
}

# Function to list SSL backup files
list_ssl_backup_files() {
  ls -t "$BACKUP_DIR"/ssl_certif_*.json
}


######################################################
### Function to restore from backup file
restore_backup() {
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
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE"
          echo -e " ✅ ${COLOR_GREEN}Users restored successfully!${CoR}"
          ;;
        *settings_*.json)
          echo -e "\n 🩹 Restoring settings from $global_file..."
          RESPONSE=$(cat "$global_file")
          curl -s -X POST "$BASE_URL/nginx/settings/bulk" \
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE"
          echo -e " ✅ ${COLOR_GREEN}Settings restored successfully!${CoR}"
          ;;
        *access_lists_*.json)
          echo -e "\n 🩹 Restoring access lists from $global_file..."
          RESPONSE=$(cat "$global_file")
          curl -s -X POST "$BASE_URL/nginx/access-lists/bulk" \
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
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
          -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
          -H "Content-Type: application/json; charset=UTF-8" \
          --data-raw "$RESPONSE")

        HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
        HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

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
            -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
            -H "Content-Type: application/json; charset=UTF-8" \
            --data-raw "$CERT_RESPONSE")

          HTTP_CERT_BODY=$(echo "$HTTP_CERT_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
          HTTP_CERT_STATUS=$(echo "$HTTP_CERT_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

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
    echo -e "\n ⛔ ${COLOR_RED}No backup file found for host ID $HOST_ID.${CoR}"
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


##### restore-host
# Function to restore a single host configuration and its certificate (if exists)

restore_host() {
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 🩹 The --host-restore-id option requires a host ID."
    usage
  fi

  # Get the current date in a formatted string
  DATE=$(date +"_%Y_%m_%d__%H_%M_%S")

  # Verify if host ID exists
  HOST_ID_RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts/$HOST_ID" -H "Authorization: Bearer $(cat $TOKEN_FILE)")
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
  SANITIZED_HOST_NAME=$(echo "$HOST_NAME" | sed 's/[^a-zA-Z0-9]/_/g')
  HOST_DIR="$BACKUP_DIR/$SANITIZED_HOST_NAME"

  #echo -e " 🐛 Debug: SANITIZED_HOST_NAME = $SANITIZED_HOST_NAME"
  #echo -e " 🐛 Debug: HOST_DIR = $HOST_DIR"

  # Verify the existence of the host directory
  if [ ! -d "$HOST_DIR" ]; then
    echo -e "\n ⛔ ${COLOR_RED}Backup directory for host $HOST_ID not found: $HOST_DIR${CoR}"
    exit 1
  fi

  # Verify the existence of backup files
  BACKUP_FILES=($(find "$HOST_DIR" -type f -name "proxy_host_${HOST_ID}_*.json"))

  if [ ${#BACKUP_FILES[@]} -eq 0 ]; then
    echo -e "\n ⛔ ${COLOR_RED}No backup file found for host ID $HOST_ID in '$HOST_DIR'. Aborting restore.${CoR}"
    exit 1
  fi

  # Count the number of backup files
  BACKUP_COUNT=${#BACKUP_FILES[@]}

  if [ "$BACKUP_COUNT" -gt 0 ]; then
    echo -e "\n 🔍 Found ${COLOR_ORANGE}$BACKUP_COUNT${CoR} backups for host ${COLOR_ORANGE}$SANITIZED_HOST_NAME${CoR} ID $HOST_ID."
    PROXY_HOST_FILE=$(ls -t "${BACKUP_FILES[@]}" | head -n 1)
    echo -e " 🩹 Latest Backup File found: $PROXY_HOST_FILE \n"
    read -p " 👉 Do you want to (1) restore the latest backup, (2) list backups and choose one, or (3) abandon? (1/2/3): " -r choice
    case $choice in
      1)
        echo -e "\n 🩹 Proxy Host backup file : $PROXY_HOST_FILE"
        ;;
      2)
        BACKUP_LIST=($(ls -t "${BACKUP_FILES[@]}"))
        echo -e "\nAvailable backups:"
        for i in "${!BACKUP_LIST[@]}"; do
          echo "$i) ${BACKUP_LIST[$i]}"
        done
        read -p " 👉 Enter the number of the backup you want to restore: " -r backup_number
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
      read -p " 👉 Do you want to delete the existing proxy host and restore from the backup? (y/n): " -r confirm
    fi
    echo -e "${CoR}" 
    if [[ $confirm =~ ^[Yy]$ ]]; then
      echo -e "${CoR}" 
      if ! delete_proxy_host; then
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
      -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
      -H "Content-Type: application/json; charset=UTF-8" \
      --data-raw "$RESPONSE")

    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\\n' | sed -e 's/.*HTTPSTATUS://')

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





 
#################################
# Main logic
if [ "$INFO" = true ]; then
  display_info
elif [ "$SHOW_DEFAULT" = true ]; then
  show_default
elif [ "$EXAMPLES" = true ]; then
  examples_cli
elif [ "$CHECK_TOKEN" = true ]; then
  check_token_validity

# Commandes de listing
elif [ "$LIST_HOSTS" = true ]; then
  list_proxy_hosts
elif [ "$LIST_HOSTS_FULL" = true ]; then
  list_proxy_hosts_full
elif [ "$LIST_USERS" = true ]; then
  list_users
elif [ "$LIST_SSL_CERTIFICATES" = true ]; then
  if [ -n "$DOMAIN" ]; then
    list_ssl_certificates "$DOMAIN"
  else
    list_ssl_certificates
  fi
elif [ "$ACCESS_LIST" = true ]; then
  list_access
elif [ "$SEARCH_HOST" = true ]; then
  search_proxy_host
elif [ "$HOST_SHOW" = true ]; then
  host_show

# Actions utilisateurs
elif [ "$CREATE_USER" = true ]; then
  create_user "$USERNAME" "$PASSWORD" "$EMAIL"
elif [ "$DELETE_USER" = true ]; then
  delete_user "$USER_ID"

# Actions hôtes
elif [ "$DELETE_HOST" = true ]; then
  delete_proxy_host
elif [ "$ENABLE_HOST" = true ]; then
  enable_proxy_host
elif [ "$DISABLE_HOST" = true ]; then
  disable_proxy_host
elif [ "$UPDATE_FIELD" = true ]; then
  update_field "$HOST_ID" "$FIELD" "$VALUE"

# Actions ACL
elif [ "$ENABLE_ACL" = true ]; then
  enable_acl
elif [ "$DISABLE_ACL" = true ]; then
  disable_acl

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
elif [ "$RESTORE" = true ]; then
  restore_backup
elif [ "$RESTORE_HOST" = true ]; then
  restore_host
else
  create_or_update_proxy_host
fi