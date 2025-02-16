#!/bin/bash

# Nginx Proxy Manager CLI Script
#   Github [ https://github.com/Erreur32/nginx-proxy-manager-Bash-API ]
#   By Erreur32 - July 2024

VERSION="2.5.9"

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
#   --delete-user username                Delete a user by username
#   --host-delete id                      Delete a proxy host by ID
#   --host-show id                        Show full details for a specific host by ID
#   --show-default                        Show default settings for creating hosts
#   --host-list                           List the names of all proxy hosts
#   --host-list-full                      List all proxy hosts with full details
#   --host-list-users                     List all users
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


# Don't touch below that line (or you know ...)
# Control variables
CREATE_USER=false
DELETE_USER=false
DELETE_HOST=false
LIST_HOSTS=false
LIST_HOSTS_FULL=false
LIST_SSL_CERTIFICATES=false
LIST_USERS=false
INFO=false
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
AUTO_YES=false  # Added: Flag for automatic confirmation (y)
# Colors Custom
COLOR_GREEN="\033[32m"
COLOR_RED="\033[41;1m"
COLOR_ORANGE="\033[38;5;202m"
COLOR_YELLOW="\033[93m"
CoR="\033[0m"
COLOR_GREY="\e[90m"
WHITE_ON_GREEN="\033[30;48;5;83m"


###############################################
# Check if necessary dependencies are installed
check_dependencies() {

  local dependencies=("curl" "jq")
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      echo -e "${COLOR_RED}Dependency $dep is not installed. Please install it before running this script.${CoR}"
      exit 1
    fi
  done

  
  # Vérification et création des dossiers si nécessaires
  if [ ! -d "$BASE_DIR" ]; then
    echo -e "\n  ${COLOR_RED}Error : BASE_DIR  $BASE_DIR  Don't exist. Check config.${CoR} \n  check config variables !"
    exit 1
  fi

  if [ ! -d "$TOKEN_DIR" ]; then
    #echo -e "${COLOR_YELLOW}Info : Le dossier de tokens $TOKEN_DIR n'existe pas. Création en cours...${CoR}"
    mkdir -p "$TOKEN_DIR"
    if [ $? -ne 0 ]; then
      echo -e "\n  ${COLOR_RED}Error: Failed to create token directory $TOKEN_DIR.${CoR} \n  check config variables !"
      exit 1
    fi
  fi

  if [ ! -d "$BACKUP_DIR" ]; then
    #echo -e "${COLOR_YELLOW}Info : Le dossier de backups $BACKUP_DIR n'existe pas. Création en cours...${CoR}"
    mkdir -p "$BACKUP_DIR"
    if [ $? -ne 0 ]; then
        echo -e "\n  ${COLOR_RED}Dependency $dep is not installed. Please install it before running this script.${CoR}"
      exit 1
    fi
  fi

}

check_dependencies


# Check if the Nginx Proxy Manager API is accessible
check_nginx_access() {
  if ping -c 2 -W 2 $NGINX_IP &> /dev/null; then
    if curl --output /dev/null --silent --head --fail "$BASE_URL"; then
      echo -e "  ✅ Nginx url: $BASE_URL"
    else
      echo -e " ⛔ Nginx url ⛔ $BASE_URL is NOT accessible."
      exit 1
    fi
  else
    echo -e " ⛔ $NGINX_IP ⛔ is not responding. Houston, we have a problem."
    exit 1
  fi
}

# check_nginx_access

# !!! ne filtrer que les dossiers !
# Function to list available backups
list_backups() {
  echo "Available backups:"
  for domain in $(ls -td "$BACKUP_DIR"/*/); do
    domain_name=$(basename "$domain")
    echo "  - ${domain_name//_/.}"
  done
}


# Display help
usage() {
  echo -e "Options:"
  echo -e "  -d ${COLOR_ORANGE}DOMAIN_NAMES${CoR}                       Domain name (${COLOR_RED}required${CoR})"
  echo -e "  -i ${COLOR_ORANGE}FORWARD_HOST${CoR}                       IP address or domain name of the target server (${COLOR_RED}required${CoR})"
  echo -e "  -p ${COLOR_ORANGE}FORWARD_PORT${CoR}                       Port of the target server (${COLOR_RED}required${CoR})"
  echo -e "\n  (Check default settings,no argument needed if already set!)"
  echo -e "  -f FORWARD_SCHEME                       Scheme for forwarding (http/https, default: $(colorize_booleanh $FORWARD_SCHEME))"
  echo -e "  -c CACHING_ENABLED                      Enable caching (true/false, default: $(colorize_boolean $CACHING_ENABLED))"
  echo -e "  -b BLOCK_EXPLOITS                       Block exploits (true/false, default: $(colorize_boolean $BLOCK_EXPLOITS))"
  echo -e "  -w ALLOW_WEBSOCKET_UPGRADE              Allow WebSocket upgrade (true/false, default: $(colorize_boolean $ALLOW_WEBSOCKET_UPGRADE))"
  echo -e "  -l CUSTOM_LOCATIONS                     Custom locations (${COLOR_YELLOW}JSON array${CoR} of location objects)"
  echo -e "  -a ADVANCED_CONFIG                      Advanced configuration (${COLOR_YELLOW}string${CoR})"
  echo -e "  -y                                      Automatic yes prompts !"
  echo ""
  echo -e "  --info                                 ℹ️  ${COLOR_YELLOW}Display${CoR} Script Variables Information"
  echo -e "  --show-default                         🔍 ${COLOR_YELLOW}Show${CoR}    Default settings for creating hosts"
  echo -e "  --backup                               📦 ${COLOR_GREEN}Backup${CoR}  All configurations to a different files in \$BACKUP_DIR"
  echo -e "  --backup-host id                       📦 ${COLOR_GREEN}Backup${CoR}  Single host configuration and its certificate (if exists)"
  #echo -e "  --restore                              📦 ${COLOR_GREEN}Restore${CoR} All configurations from a backup file"
  #echo -e "  --restore-host id                      📦 ${COLOR_GREEN}Restore${CoR} Restore single host with list with empty arguments or a Domain name"
  echo -e "  --check-token                          🔧 ${COLOR_YELLOW}Check${CoR}   If the current token is valid"
  echo -e "  --create-user user pass email          👤 ${COLOR_GREEN}Create${CoR}  User with a ${COLOR_YELLOW}username, ${COLOR_YELLOW}password${CoR} and ${COLOR_YELLOW}email${CoR}"
  echo -e "  --delete-user username                 💣 ${COLOR_ORANGE}Delete${CoR}  User by ${COLOR_YELLOW}username${CoR}"
  echo -e "  --host-delete id                       💣 ${COLOR_ORANGE}Delete${CoR}  Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-search hostname                 🔍 ${COLOR_GREEN}Search${CoR}  Proxy host by domain name"
  echo -e "  --host-show id                         🔍 ${COLOR_YELLOW}Show${CoR}    Full details for a specific host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-list                            📋 ${COLOR_YELLOW}List${CoR}    All Proxy hosts (table form)"
  echo -e "  --host-list-full                       📋 ${COLOR_YELLOW}List${CoR}    All Proxy hosts full details (JSON)"
  echo -e "  --host-list-users                      📋 ${COLOR_YELLOW}List${CoR}    All Users"
  echo -e "  --host-enable id                       ✅ ${COLOR_GREEN}Enable${CoR}  Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-disable id                      ❌ ${COLOR_ORANGE}Disable${CoR} Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --access-list                          📋 ${COLOR_YELLOW}List${CoR}    All available Access Lists (ID and Name)"
  echo -e "  --host-acl-enable id,access_list_id    ✅ ${COLOR_GREEN}Enable ACL${CoR} for Proxy host by ${COLOR_YELLOW}ID${CoR} with Access List ID (e.g., --host-acl-enable 16,2)"
  echo -e "  --host-acl-disable id                  ❌ ${COLOR_ORANGE}Disable ACL${CoR} for Proxy host by ${COLOR_YELLOW}ID${CoR}"
  echo -e "  --host-ssl-enable id                   🔒 ${COLOR_GREEN}Enable${CoR}  SSL, HTTP/2, and HSTS for a proxy host (Enabled only if exist, check ${COLOR_ORANGE}--generate-cert${CoR} to creating one)"
  echo -e "  --host-ssl-disable id                  🔓 ${COLOR_ORANGE}Disable${CoR} SSL, HTTP/2, and HSTS for a proxy host"
  echo -e "  --list-ssl-certificates [domain]       📋 ${COLOR_YELLOW}List${CoR}    All SSL certificates availables or filtered by [domain name]  (JSON)"  
  echo -e "  --generate-cert domain email           🌀 ${COLOR_GREEN}Generate${CoR} Certificate for the given '${COLOR_YELLOW}domain${CoR}' and '${COLOR_YELLOW}email${CoR}'"
  echo -e "  --delete-cert domain                   💣 ${COLOR_ORANGE}Delete${CoR}  Certificate for the given '${COLOR_YELLOW}domain${CoR}' "
  echo -e "  --update-host id field=value           🔄 ${COLOR_GREEN}Update${CoR} a specific field of an existing proxy host by ${COLOR_YELLOW}ID${CoR} (e.g., --update-host 42 forward_host=foobar.local)"
  
  echo -e "  --examples                             🔖 Examples commands, more explicits"

  echo -e "  --help                                 👉 It's me"
  echo ""
  exit 0
}

# Examples CLI Commands
examples_cli() {
  echo -e "\n${COLOR_YELLOW}Usage: $0 -d domain -i ip -p port [-f forward_scheme] [-c caching_enabled] [-b block_exploits] [-w allow_websocket_upgrade] [-a advanced_config] [-t token_expiry] [--create-user username password email] [--delete-user username] [--host-delete id] [--host-list] [--host-list-full] [--host-list-certificates] [--host-list-users] [--host-search hostname] [--host-enable id] [--host-disable id] [--check-token] [--backup] [--backup-host id] [--restore] [--restore-host id] [--generate-cert domain email [--custom]] [--host-ssl-enable id] [--host-ssl-disable id] [--host-show id] [--show-default] [--help]${CoR}"
  echo -e ""
  echo -e "Examples:"
  echo -e "\n 📋 List host"
  echo -e "${COLOR_GREY}  $0 --host-list${CoR}"
  echo -e "\n 📦 Backup First before doing anything!${COLOR_GREY}"
  echo -e "  $0 --backup"
  echo -e "  $0 --backup-host 1"
 # echo -e "  $0 --restore"
 # echo -e "  $0 --restore-host 1"
  echo -e "\n ${CoR}🌐 Host Creation${COLOR_GREY}"
  echo -e "  $0 --show-default"
  echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080"
  echo -e "  $0 --host-ssl-enable 10"
  echo -e "  $0 --host-show 10"
  echo -e "  $0 --host-list"
  echo -e "\n  $0 --list-ssl-certificates domain.com"
  echo -e "\n ${CoR}👤 User Management${COLOR_GREY}"
  echo -e "  $0 --create-user newuser password123 user@example.com"
  echo -e "  $0 --delete-user 'username'"
  echo -e "\n ${CoR}🔧 Advanced Example:${COLOR_GREY}"
  echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;'"
  echo -e "  $0 --generate-cert example.com user@example.com --custom"
  echo -e "\n ${CoR}📁 Custom locations:${COLOR_GREY}"
  echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080 -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"
  echo -e "\n ${CoR}🔖 Full option:${COLOR_GREY}"
  echo -e "  $0 -d example.com -i 192.168.1.10 -p 8080 -f https -c true -b true -w true -a 'proxy_set_header X-Real-IP \$remote_addr;' -l '[{\"path\":\"/api\",\"forward_host\":\"192.168.1.11\",\"forward_port\":8081}]'"
  echo -e "${CoR}"
  echo ""
  exit 0
}



# Display script variables info
display_info() {

  check_dependencies
  check_nginx_access

  echo -e "\n${COLOR_YELLOW}Script Info:  ${COLOR_GREEN}${VERSION}${CoR}"

  echo -e "\n${COLOR_YELLOW}Script Variables Information:${CoR}"
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

# shellcheck disable=SC2120
# check_no_arguments() {
#   if [ $# -eq 0 ]; then
#     echo -e "\n ${COLOR_RED}No arguments provided. Use --help to see all command options.${CoR}"
#     echo ""
#     #display_info
#     exit 1
#   fi
# }

# Colorize boolean values for display
colorize_boolean() {
  local value=$1
  if [ "$value" = true ]; then
    echo -e "${COLOR_GREEN}true${CoR}"
  else
    echo -e "${COLOR_YELLOW}false${CoR}"
  fi
}

colorize_booleanh() {
  local value=$1
  if [ "$value" = https ]; then
    echo -e "${COLOR_GREEN}https${CoR}"
  else
    echo -e "${COLOR_YELLOW}http${CoR}"
  fi
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
  renew_response=$(curl -s -X GET "$BASE_URL$API_ENDPOINT?expiry=$TOKEN_EXPIRY" \
    -H "Authorization: Bearer $initial_token" \
    -H "Accept: application/json")

  new_token=$(echo "$renew_response" | jq -r '.token')
  new_expires=$(echo "$renew_response" | jq -r '.expires')

  if [ "$new_token" != "null" ]; then
    echo "$new_token" > "$TOKEN_FILE"
    echo "$new_expires" > "$EXPIRY_FILE"
    echo -e "  ✅ ${COLOR_GREEN}Token valid until: $new_expires (${TOKEN_EXPIRY})${CoR}"
  else
    echo -e " ⚠️  ${COLOR_RED}Error renewing token. API response: $renew_response${CoR}"
    exit 1
  fi
}

renew_token_if_needed() {
  # Check if token files exist
  if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ]; then
    echo -e "⚠️ ${COLOR_YELLOW}  No valid token found. Generating new token...${CoR}"
    generate_token
    return 1
  fi

  # Read current token data
  local token=$(cat "$TOKEN_FILE")
  local expires=$(cat "$EXPIRY_FILE")
  local current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Check token expiration
  if [[ "$current_time" < "$expires" ]]; then
    echo -e "✅ ${COLOR_GREEN} Token valid. Expires: $expires${CoR}"
    return 0
  else
    echo -e "⚠️ ${COLOR_RED}  Token expired at $expires${CoR}"
    echo -e "🔄 ${COLOR_YELLOW} Generating new token...${CoR}"
    generate_token
    return 1
  fi
}

check_token_validity() {
  if renew_token_if_needed; then
    exit 0
  else
    exit 1
  fi
}

# Validate the existing token
validate_token() {
  if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ]; then
    echo -e "\n ⛔ ${COLOR_RED}No valid token found. Generating a new token...${CoR}"
    generate_token
  fi

  expires=$(cat $EXPIRY_FILE)
  current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


  if [[ "$current_time" < "$expires" ]]; then
    echo -e " ✅ ${COLOR_GREEN}1 The token is valid. Expiry: $expires${CoR}"
		#    return 0
  else
    echo -e " ⛔ ${COLOR_RED}1 The token is expired. Expiry: $expires${CoR}"
		echo -e " 🔄 ${COLOR_GREEN}1 Processing NEW Token${CoR}"
		generate_token
		#    return 1
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
              BACKUP_HOST=true
              HOST_ID="${!OPTIND}"; shift
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
              CREATE_USER=true
              USERNAME="${!OPTIND}"; shift
              PASSWORD="${!OPTIND}"; shift
              EMAIL="${!OPTIND}"; shift
              ;;
          delete-user)
              validate_token
              DELETE_USER=true
              USERNAME="${!OPTIND}"; shift
              ;;
          host-delete)
              validate_token
              DELETE_HOST=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          host-show)
              validate_token
              HOST_SHOW=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          host-list) validate_token; LIST_HOSTS=true ;;
          host-list-full) validate_token; LIST_HOSTS_FULL=true ;;
          host-list-users) validate_token; LIST_USERS=true ;;
          host-search)
              validate_token
              SEARCH_HOST=true
              SEARCH_HOSTNAME="${!OPTIND}"; shift
              ;;
          host-enable)
              validate_token
              ENABLE_HOST=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          host-disable)
              validate_token
              DISABLE_HOST=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          host-acl-enable)
              validate_token
              ENABLE_ACL=true
              # Expecting "HOST_ID,ACCESS_LIST_ID"
              ACL_ARG="${!OPTIND}"; shift
              IFS=',' read -r HOST_ID ACCESS_LIST_ID <<< "$ACL_ARG"
              if [ -z "$HOST_ID" ] || [ -z "$ACCESS_LIST_ID" ]; then
                echo -e "\n ⛔ ${COLOR_RED}Erreur : --host-acl-enable need HOST_ID et ACCESS_LIST_ID separated by a comma (e.g., --host-acl-enable 16,2).${CoR}"
                usage
              fi
              ;;
          host-acl-disable)
              validate_token
              DISABLE_ACL=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          check-token) CHECK_TOKEN=true
              ;;
          generate-cert)
              validate_token
              GENERATE_CERT=true
              DOMAIN="${!OPTIND}"; shift
              EMAIL="${!OPTIND}"; shift
              ;;
          delete-cert)
              validate_token
              DELETE_CERT=true
              DOMAIN="${!OPTIND}"; shift
              ;;
          host-ssl-enable)
              validate_token
              ENABLE_SSL=true
              HOST_ID="${!OPTIND}"; shift
              # Check if HOST_ID is provided
              if [ -z "$HOST_ID" ]; then
                echo -e " \n⛔ ${COLOR_RED}Error: Missing host ID for --host-ssl-enable.${CoR}"
                echo -e " To find ID Check with ${COLOR_ORANGE}$0 --host-list${CoR}\n"
                exit 1
              fi  
              ;;
          host-ssl-disable)
              validate_token
              DISABLE_SSL=true
              HOST_ID="${!OPTIND}"; shift
              ;;
          force-cert-creation)
              validate_token
              FORCE_CERT_CREATION=true ;;
          list-ssl-certificates)
              validate_token
              LIST_SSL_CERTIFICATES=true
              DOMAIN="$2"
              #DOMAIN="${!OPTIND}"; shift
              ;;
          access-list) validate_token; ACCESS_LIST=true  ;;
          update-host)
              validate_token
              UPDATE_FIELD=true
              HOST_ID="${!OPTIND}"; shift
              FIELD_VALUE="${!OPTIND}"; shift
              FIELD=$(echo "$FIELD_VALUE" | cut -d= -f1)
              VALUE=$(echo "$FIELD_VALUE" | cut -d= -f2-)
              ;;
          examples) EXAMPLES=true ;;
          info) INFO=true ;;
      esac ;;
      *) INFO=true  # display_info; exit 0
       ;;
  esac
done

# If no arguments are provided, display usage
if [ $# -eq 0 ]; then
  #echo -e "\n  Unknown option --${OPTARG}" ; 
  display_info
  # usage
  exit 0
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

list_access() {

  echo -e " \n Available Access Lists:"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/access-lists" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)")

	# Check if the response is a valid JSON array
	if echo " $RESPONSE" | jq -e 'type == "array"' > /dev/null; then
	  # Loop through and display the elements of the list
	echo -e "${COLOR_YELLOW}"
	echo "   $RESPONSE" | jq -r '.[] | " \(.id): \(.name)"'
 	echo -e "${CoR}"
	else
	  # In case of an error, check if there is an error message in the response
    if echo " $RESPONSE" | jq -e '.error // empty' > /dev/null; then
      echo -e " ⛔ API Error: $(echo "$RESPONSE" | jq -r '.message')"
    else
      echo -e " ⛔ Unknown Error: $RESPONSE"
    fi
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
# Function to delete all existing proxy hosts
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
  if [ -z "$HOST_ID" ]; then
    echo -e "\n 💣 The --host-delete option requires a host ID."
    usage
  fi
  echo -e "  💣 Deleting proxy host ID: $HOST_ID..."

  RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X DELETE "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  HTTP_BODY=$(echo "$RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if ! [[ "$HTTP_STATUS" =~ ^[0-9]+$ ]] || [ "$HTTP_STATUS" -ne 200 ]; then
    echo -e " ⛔ ${COLOR_RED}Failed to delete proxy host. HTTP status: $HTTP_STATUS. Error: $HTTP_BODY${CoR}"
    return 1
  else
    echo -e " ✅ ${COLOR_GREEN}Proxy host successfully deleted! 💣${CoR}\n"
    return 0
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
    echo -e "\n 🌍  The -d, -i, and -p options are required to ${COLOR_YELLOW}create${CoR} or ${COLOR_YELLOW}update${CoR} a proxy host."
    echo -e " 🔖  Check some examples commands with ${COLOR_GREEN}$0 --examples${CoR} \n"
    usage
  fi

  check_existing_proxy_host
}


###############################
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
}


# List all proxy hosts with full details
list_proxy_hosts_full() {
  echo -e "\n${COLOR_ORANGE} 👉 List of proxy hosts with full details...${CoR}\n"
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
}

############################
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
    echo -e " ✅ ${COLOR_GREEN}User created successfully!${CoR}\n"
  else
    echo "Data sent: $DATA"  # Log the data sent
    echo -e " ⛔ ${COLOR_RED}Failed to create user. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
  fi
}

############################
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
      echo -e " ✅ ${COLOR_GREEN}User deleted successfully!${CoR}\n"
    else
      echo -e " ⛔ ${COLOR_RED}Failed to delete user. HTTP status: $HTTP_STATUS. Response: $HTTP_BODY${CoR}\n"
    fi
  else
    echo -e " ${COLOR_RED}User not found: $USERNAME${CoR}\n"
  fi
}

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
    read -p "⚠️ Are you sure you want to delete the certificate for $DOMAIN? (y/n): " CONFIRM
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


##################################################
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


####################################
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


##########################################
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
host_show() {
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

# show_default
# Display default settings for creating hosts
show_default() {
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

##################################
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
}


## backup-host
# Function to backup a single host configuration and its certificate (if exists)
backup-host() {
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
  if [ -n "$DOMAIN_ARG" ]; then
    list_ssl_certificates "$DOMAIN_ARG"
  else
    list_ssl_certificates
  fi
elif [ "$LIST_USERS" = true ]; then
  list_users
elif [ "$SEARCH_HOST" = true ]; then
  search_proxy_host
elif [ "$ENABLE_HOST" = true ]; then
  enable_proxy_host
elif [ "$DISABLE_HOST" = true ]; then
  disable_proxy_host
 elif [ "$ACCESS_LIST" = true ]; then
  list_access
elif [ "$ENABLE_ACL" = true ]; then
  enable_acl
elif [ "$DISABLE_ACL" = true ]; then
  disable_acl
elif [ "$CHECK_TOKEN" = true ]; then
	#generate_token   validate_token
  check_token_validity
elif [ "$BACKUP_LIST" = true ]; then
  list_backups
elif [ "$BACKUP" = true ]; then
  full_backup
elif [ "$BACKUP_HOST" = true ]; then
  backup-host
elif [ "$GENERATE_CERT" = true ]; then
  generate_certificate
elif [ "$DELETE_CERT" = true ]; then
  delete_certificate
elif [ "$ENABLE_SSL" = true ]; then
  enable_ssl
elif [ "$DISABLE_SSL" = true ]; then
  disable_ssl
elif [ "$SHOW_DEFAULT" = true ]; then
  show_default
elif [ "$SSL_REGENERATE" = true ]; then
  regenerate_all_ssl_certificates
elif [ "$INFO" = true ]; then
  display_info
elif [ "$EXAMPLES" = true ]; then
  examples_cli
elif [ "$RESTORE" = true ]; then
  restore_backup
elif [ "$RESTORE_HOST" = true ]; then
  restore-host
elif [ "$SSL_RESTORE" = true ]; then
  restore_ssl_certificates
elif [ "$UPDATE_FIELD" = true ]; then
	update_field "$HOST_ID" "$FIELD" "$VALUE"
else
  create_or_update_proxy_host
fi
