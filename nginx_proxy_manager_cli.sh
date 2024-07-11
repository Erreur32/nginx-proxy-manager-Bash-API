#!/bin/bash

###############################################################################
# Nginx Proxy Manager CLI Script
# Erreur32 - July 2024
#
# This script allows you to manage Nginx Proxy Manager via the API. It provides
# functionalities such as creating proxy hosts, managing users, and displaying
# configurations.
#
# Usage:
#   ./nginx_proxy_manager_cli.sh [OPTIONS]
#
# Examples:
#   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -s true
#   ./nginx_proxy_manager_cli.sh --create-user newuser password123
#   ./nginx_proxy_manager_cli.sh --list-hosts
#
###############################################################################

# Variables to edit (required)
NGINX_IP="127.0.0.1"
# Existing nginx user
API_USER="user@nginx"
API_PASS="pass nginx"


################################
# Colors
COLOR_GREEN="\033[32m"
COLOR_RED="\033[41;1m"
COLOR_ORANGE="\033[38;5;202m"
COLOR_YELLOW="\033[93m"
COLOR_RESET="\033[0m"
WHITE_ON_GREEN="\033[97m\033[42m"

# API Endpoints
BASE_URL="http://$NGINX_IP:81/api"
API_ENDPOINT="/tokens"
EXPIRY_FILE="expiry_${NGINX_IP}.txt"
TOKEN_FILE="token_${NGINX_IP}.txt"
# Change Time velidity here
TOKEN_EXPIRY="1y"

# Default variables
SSL_FORCED=false
CACHING_ENABLED=false
BLOCK_EXPLOITS=true
ALLOW_WEBSOCKET_UPGRADE=true
HTTP2_SUPPORT=true
ADVANCED_CONFIG=""
LETS_ENCRYPT_AGREE=false
LETS_ENCRYPT_EMAIL=""
DNS_CHALLENGE=false
FORWARD_SCHEME="http"

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

# Check if necessary dependencies are installed
check_dependencies() {
  local dependencies=("curl" "jq")
  for dep in "${dependencies[@]}"; do
    if ! command -v $dep &> /dev/null; then
      echo -e "${COLOR_RED}Dependency $dep is not installed. Please install it before running this script.${COLOR_RESET}"
      exit 1
    fi
  done
}

# Check if necessary dependencies are installed
check_dependencies

# Display help
usage() {
  echo -e "\n${COLOR_YELLOW}Usage: $0 -d domain -i ip -p port [-f forward_scheme] [-s ssl_forced] [-c caching_enabled] [-b block_exploits] [-w allow_websocket_upgrade] [-h http2_support] [-a advanced_config] [-e lets_encrypt_agree] [-m lets_encrypt_email] [-n dns_challenge] [-t token_expiry] [--create-user username password] [--delete-user username] [--delete-host id] [--list-hosts] [--list-hosts-full] [--list-ssl-certificates] [--list-users] [--search-host hostname] [--enable-host id] [--disable-host id] [--help]${COLOR_RESET}"
  echo ""
  echo -e "Examples:"
  echo -e "  ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -s true"
  echo -e "  ./nginx_proxy_manager_cli.sh --create-user newuser password123"
  echo -e "  ./nginx_proxy_manager_cli.sh --list-hosts"
  echo -e ""
  echo -e "Options:"
  echo -e "  -d ${COLOR_ORANGE}DOMAIN_NAMES${COLOR_RESET}            Domain name (${COLOR_RED} required ${COLOR_RESET})"
  echo -e "  -i ${COLOR_ORANGE}FORWARD_HOST${COLOR_RESET}            IP address or domain name of the target server (${COLOR_RED} required ${COLOR_RESET})"
  echo -e "  -p ${COLOR_ORANGE}FORWARD_PORT${COLOR_RESET}            Port of the target server (${COLOR_RED} required ${COLOR_RESET})"
  echo -e "  -f FORWARD_SCHEME          Scheme for forwarding (http/https, default: http)"
  echo -e "  -s SSL_FORCED              Force SSL (true/false, default: $(colorize_boolean $SSL_FORCED))"
  echo -e "  -c CACHING_ENABLED         Enable caching (true/false, default: $(colorize_boolean $CACHING_ENABLED))"
  echo -e "  -b BLOCK_EXPLOITS          Block exploits (true/false, default: $(colorize_boolean $BLOCK_EXPLOITS))"
  echo -e "  -w ALLOW_WEBSOCKET_UPGRADE Allow WebSocket upgrade (true/false, default: $(colorize_boolean $ALLOW_WEBSOCKET_UPGRADE))"
  echo -e "  -h HTTP2_SUPPORT           Support HTTP/2 (true/false, default: $(colorize_boolean $HTTP2_SUPPORT))"
  echo -e "  -a ADVANCED_CONFIG         Advanced configuration (string)"
  echo -e "  -e LETS_ENCRYPT_AGREE      Accept Let's Encrypt (true/false, default: $(colorize_boolean $LETS_ENCRYPT_AGREE))"
  echo -e "  -m LETS_ENCRYPT_EMAIL      Email for Let's Encrypt (${COLOR_ORANGE}required${COLOR_RESET} if LETS_ENCRYPT_AGREE is true)"
  echo -e "  -n DNS_CHALLENGE           DNS challenge (true/false, default: $(colorize_boolean $DNS_CHALLENGE))"
  echo -e "  -t TOKEN_EXPIRY            Token expiry duration (default: ${COLOR_YELLOW}1y${COLOR_RESET})"
  echo -e "  --create-user user pass    Create a user with a username and password"
  echo -e "  --delete-user username     Delete a user by username"
  echo -e "  --delete-host id           Delete a proxy host by ID"
  echo -e "  --list-hosts               List the names of all proxy hosts"
  echo -e "  --list-hosts-full          List all proxy hosts with full details"
  echo -e "  --list-ssl-certificates    List all SSL certificates"
  echo -e "  --list-users               List all users"
  echo -e "  --search-host hostname     Search for a proxy host by domain name"
  echo -e "  --enable-host id           Enable a proxy host by ID"
  echo -e "  --disable-host id          Disable a proxy host by ID"
  echo -e "  --help                     Display this help"
  echo
  exit 0
}

# Function to colorize true and false values
colorize_boolean() {
  local value=$1
  if [ "$value" = true ]; then
    echo -e "${COLOR_GREEN}true${COLOR_RESET}"
  else
    echo -e "${COLOR_YELLOW}false${COLOR_RESET}"
  fi
}

# Parse command-line options
while getopts "d:i:p:f:s:c:b:w:h:a:e:m:n:t:-:" opt; do
  case $opt in
    d) DOMAIN_NAMES="$OPTARG" ;;
    i) FORWARD_HOST="$OPTARG" ;;
    p) FORWARD_PORT="$OPTARG" ;;
    f) FORWARD_SCHEME="$OPTARG" ;;
    s) SSL_FORCED="$OPTARG" ;;
    c) CACHING_ENABLED="$OPTARG" ;;
    b) BLOCK_EXPLOITS="$OPTARG" ;;
    w) ALLOW_WEBSOCKET_UPGRADE="$OPTARG" ;;
    h) HTTP2_SUPPORT="$OPTARG" ;;
    a) ADVANCED_CONFIG="$OPTARG" ;;
    e) LETS_ENCRYPT_AGREE="$OPTARG" ;;
    m) LETS_ENCRYPT_EMAIL="$OPTARG" ;;
    n) DNS_CHALLENGE="$OPTARG" ;;
    t) TOKEN_EXPIRY="$OPTARG" ;;
    -)
      case "${OPTARG}" in
        help) usage ;;
        create-user)
          CREATE_USER=true
          USERNAME="${!OPTIND}"; shift
          PASSWORD="${!OPTIND}"; shift
          ;;
        delete-user)
          DELETE_USER=true
          USERNAME="${!OPTIND}"; shift
          ;;
        delete-host)
          DELETE_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        list-hosts) LIST_HOSTS=true ;;
        list-hosts-full) LIST_HOSTS_FULL=true ;;
        list-ssl-certificates) LIST_SSL_CERTIFICATES=true ;;
        list-users) LIST_USERS=true ;;
        search-host)
          SEARCH_HOST=true
          SEARCH_HOSTNAME="${!OPTIND}"; shift
          ;;
        enable-host)
          ENABLE_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        disable-host)
          DISABLE_HOST=true
          HOST_ID="${!OPTIND}"; shift
          ;;
        *) echo "Unknown option --${OPTARG}" ; usage ;;
      esac ;;
    *) usage ;;
  esac
done

# Check if Nginx IP and port are accessible
check_nginx_access() {
  if ping -c 2 -W 2 $NGINX_IP &> /dev/null; then
    if curl --output /dev/null --silent --head --fail "$BASE_URL"; then
      echo "Nginx url ✅ $BASE_URL"
    else
      echo "Nginx url ⛔ $BASE_URL is NOT accessible."
      exit 1
    fi
  else
    echo "$NGINX_IP ⛔ is not responding. Houston, we have a problem."
    exit 1
  fi
}

# Function to generate the token
generate_token() {
  response=$(curl -s -X POST "$BASE_URL$API_ENDPOINT" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "{\"identity\":\"$API_USER\",\"secret\":\"$API_PASS\",\"expiry\":\"$TOKEN_EXPIRY\"}")

  token=$(echo $response | jq -r '.token')
  expires=$(echo $response | jq -r '.expires')

  if [ "$token" != "null" ]; then
    echo $token > $TOKEN_FILE
    echo $expires > $EXPIRY_FILE
    echo "Token: $token"
    echo "Expiry: $expires"
  else
    echo -e "${COLOR_RED}Error generating token.${COLOR_RESET}"
		echo -e "Check your [user] and [pass] and [IP]"
    exit 1
  fi
}

# Function to validate the token
validate_token() {
  if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ]; then
    return 1
  fi

  token=$(cat $TOKEN_FILE)
  expires=$(cat $EXPIRY_FILE)
  current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  if [[ "$current_time" < "$expires" ]]; then
    echo -e " ${COLOR_GREEN}The token is valid. Expiry: $expires${COLOR_RESET}"
    return 0
  else
    echo -e " ${COLOR_RED}The token is invalid. Expiry: $expires${COLOR_RESET}"
    return 1
  fi
}

# Check if Nginx is accessible
check_nginx_access

# Check if the token file exists
if ! validate_token; then
  echo "No valid token found. Generating a new token..."
  generate_token
fi

# Check required parameters for displaying help
if [ -z "$DOMAIN_NAMES" ] && ! $CREATE_USER && ! $DELETE_USER && ! $DELETE_HOST && ! $LIST_HOSTS && ! $LIST_HOSTS_FULL && ! $LIST_SSL_CERTIFICATES && ! $LIST_USERS && ! $SEARCH_HOST && ! $ENABLE_HOST && ! $DISABLE_HOST; then
  usage
fi

# Function to check if proxy host exists
check_existing_proxy_host() {
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  EXISTING_HOST=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN_NAMES" '.[] | select(.domain_names[] == $DOMAIN)')

  if [ -n "$EXISTING_HOST" ]; then
    echo -e "\n 🔔 Proxy host for $DOMAIN_NAMES already exists.${COLOR_GREEN}"
    read -p " Do you want to update it with the new configuration? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      HOST_ID=$(echo "$EXISTING_HOST" | jq -r '.id')
      update_proxy_host $HOST_ID
    else
      echo -e "${COLOR_RESET} No changes made."
      exit 0
    fi
  else
    create_new_proxy_host
  fi
}

# Function to update a proxy host
update_proxy_host() {
  HOST_ID=$1
  echo -e "\n Updating proxy host for $DOMAIN_NAMES..."
  DATA='{
    "domain_names": ["'"$DOMAIN_NAMES"'"],
    "forward_host": "'"$FORWARD_HOST"'",
    "forward_port": '"$FORWARD_PORT"',
    "access_list_id": null,
    "certificate_id": null,
    "ssl_forced": '"$SSL_FORCED"',
    "caching_enabled": '"$CACHING_ENABLED"',
    "block_exploits": '"$BLOCK_EXPLOITS"',
    "advanced_config": "'"$ADVANCED_CONFIG"'",
    "meta": {
      "letsencrypt_agree": '"$LETS_ENCRYPT_AGREE"',
      "dns_challenge": '"$DNS_CHALLENGE"',
      "letsencrypt_email": "'"$LETS_ENCRYPT_EMAIL"'"
    },
    "allow_websocket_upgrade": '"$ALLOW_WEBSOCKET_UPGRADE"',
    "http2_support": '"$HTTP2_SUPPORT"',
    "forward_scheme": "'"$FORWARD_SCHEME"'",
    "enabled": true,
    "locations": []
  }'

  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")
  if [ $(echo "$RESPONSE" | jq -r '.error | length') -eq 0 ]; then
    echo -e " ${COLOR_GREEN}Proxy host updated successfully!${COLOR_RESET} ✅"
  else
    echo -e " ${COLOR_RED}Failed to update proxy host. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
  fi
}

# Function to create a new proxy host
create_new_proxy_host() {
  echo "Creating proxy host for $DOMAIN_NAMES..."
  DATA='{
    "domain_names": ["'"$DOMAIN_NAMES"'"],
    "forward_host": "'"$FORWARD_HOST"'",
    "forward_port": '"$FORWARD_PORT"',
    "access_list_id": null,
    "certificate_id": null,
    "ssl_forced": '"$SSL_FORCED"',
    "caching_enabled": '"$CACHING_ENABLED"',
    "block_exploits": '"$BLOCK_EXPLOITS"',
    "advanced_config": "'"$ADVANCED_CONFIG"'",
    "meta": {
      "letsencrypt_agree": '"$LETS_ENCRYPT_AGREE"',
      "dns_challenge": '"$DNS_CHALLENGE"',
      "letsencrypt_email": "'"$LETS_ENCRYPT_EMAIL"'"
    },
    "allow_websocket_upgrade": '"$ALLOW_WEBSOCKET_UPGRADE"',
    "http2_support": '"$HTTP2_SUPPORT"',
    "forward_scheme": "'"$FORWARD_SCHEME"'",
    "enabled": true,
    "locations": []
  }'

  RESPONSE=$(curl -s -X POST "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")
  if [ $(echo "$RESPONSE" | jq -r '.error | length') -eq 0 ]; then
    echo -e " ${COLOR_GREEN}Proxy host created successfully!${COLOR_RESET} ✅"
  else
    echo -e " ${COLOR_RED}Failed to create proxy host. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
  fi
}

# Function to create or update a proxy host
create_or_update_proxy_host() {
  if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ]; then
    echo "The -d, -i, and -p options are required to create or update a proxy host."
    usage
  fi
  if $LETS_ENCRYPT_AGREE && [ -z "$LETS_ENCRYPT_EMAIL" ]; then
    echo "The -m option is required when -e is true."
    usage
  fi

  check_existing_proxy_host
}


# Function to delete a proxy host
delete_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo "The --delete-host option requires a host ID."
    usage
  fi
  echo " Deleting proxy host ID: $HOST_ID..."
  RESPONSE=$(curl -s -X DELETE "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  if [ $(echo "$RESPONSE" | jq -r '.error | length') -eq 0 ]; then
    echo -e " ${COLOR_GREEN}Proxy host deleted successfully!${COLOR_RESET} ✅"
  else
    echo -e " ${COLOR_RED}Failed to delete proxy host. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
  fi
}

# Function to list all proxy hosts (simple)
list_proxy_hosts() {
  echo -e "\n${COLOR_ORANGE} List of proxy hosts (simple)${COLOR_RESET}"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -r '.[] | "\(.id) \(.domain_names | join(", ")) \(.enabled)"' | while read -r id domain enabled; do
    if [ "$enabled" -eq 1 ]; then
      status="[${WHITE_ON_GREEN}enabled${COLOR_RESET}]"
    else
      status="[${COLOR_RED}disabled${COLOR_RESET}]"
    fi

    printf "  id: ${COLOR_YELLOW}%-4s${COLOR_RESET} ${COLOR_GREEN}%-20s${COLOR_RESET} %b\n" "$id" "$domain" "$status"
  done
}


# Function to list all proxy hosts with full details
list_proxy_hosts_full() {
  echo -e "\n${COLOR_ORANGE} List of proxy hosts with full details...${COLOR_RESET}\n"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

# Parcourt chaque élément du tableau JSON et l'affiche
echo "$RESPONSE" | jq -c '.[]' | while read -r proxy; do
  echo "$proxy" | jq .
done

#  echo "$RESPONSE" | jq -c '.[]' | while IFS= read -r line; do
#    domain_names=$(echo "$line" | jq -r '.domain_names[]')
#    advanced_config=$(echo "$line" | jq -r '.advanced_config')
#
#    echo -e "${COLOR_GREEN}$domain_names${COLOR_RESET}"
#    echo -e "$advanced_config" | awk '{
#      gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, "'${COLOR_ORANGE}'&'${COLOR_RESET}'");
#      print
#    }' | sed 's/^/ /'
#    echo
#  done
}

# todo
list_proxy_hosts_advanced() {
  echo -e "\n${COLOR_ORANGE} List of proxy hosts with full details...${COLOR_RESET}\n"
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq -c '.[]' | while IFS= read -r line; do
    domain_names=$(echo "$line" | jq -r '.domain_names[]')
    advanced_config=$(echo "$line" | jq -r '.advanced_config')

    echo -e "${COLOR_GREEN}$domain_names${COLOR_RESET}"
    echo -e "$advanced_config" | awk '{
     gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, "'${COLOR_ORANGE}'&'${COLOR_RESET}'");
      print
    }' | sed 's/^/ /'
    echo
  done
}



# Function to search for a proxy host and display details if found
search_proxy_host() {
  if [ -z "$SEARCH_HOSTNAME" ]; then
    echo "The --search-host option requires a domain name."
    usage
  fi
  echo -e "\n Searching for proxy host for $SEARCH_HOSTNAME..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -c --arg search "$SEARCH_HOSTNAME" '.[] | select(.domain_names[] | contains($search))' | while IFS= read -r line; do
    id=$(echo "$line" | jq -r '.id')
    domain_names=$(echo "$line" | jq -r '.domain_names[]')

    echo -e " id: ${COLOR_YELLOW}$id${COLOR_RESET} ${COLOR_GREEN}$domain_names${COLOR_RESET}"
  done
}

# Function to list all SSL certificates
list_ssl_certificates() {
  echo "List of SSL certificates..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq
}

# Function to list all users
list_users() {
  echo "List of users..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq
}

# Function to create a user
create_user() {
  if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo "The username and password parameters are required to create a user."
    usage
  fi
  echo "Creating user $USERNAME..."
  RESPONSE=$(curl -s -X POST "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw '{
    "username": "'"$USERNAME"'",
    "password": "'"$PASSWORD"'",
    "roles": ["user"]
  }')
  if [ $(echo "$RESPONSE" | jq -r '.error | length') -eq 0 ]; then
    echo -e " ${COLOR_GREEN}User created successfully!${COLOR_RESET} ✅"
  else
    echo -e " ${COLOR_RED}Failed to create user. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
  fi
}

# Function to delete a user
delete_user() {
  if [ -z "$USERNAME" ]; then
    echo "The --delete-user option requires a username."
    usage
  fi
  echo "Deleting user $USERNAME..."
  USER_ID=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" | jq -r '.[] | select(.username == "'"$USERNAME"'") | .id')

  if [ -n "$USER_ID" ]; then
    RESPONSE=$(curl -s -X DELETE "$BASE_URL/users/$USER_ID" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    if [ $(echo "$RESPONSE" | jq -r '.error | length') -eq 0 ]; then
      echo -e " ${COLOR_GREEN}User deleted successfully!${COLOR_RESET} ✅"
    else
      echo -e " ${COLOR_RED}Failed to delete user. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
    fi
  else
    echo "User not found: $USERNAME"
  fi
}

# Function to enable a proxy host
enable_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo "The --enable-host option requires a host ID."
    usage
  fi
  echo " Enabling proxy host ID: $HOST_ID..."
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID/enable" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8")
  if [ $(echo "$RESPONSE" | jq -r '.error | length') -eq 0 ]; then
    echo -e " ${COLOR_GREEN}Proxy host enabled successfully!${COLOR_RESET} ✅"
  else
    echo -e " ${COLOR_RED}Failed to enable proxy host. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
  fi
}

# Function to disable a proxy host
disable_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo "The --disable-host option requires a host ID."
    usage
  fi
  echo " Disabling proxy host ID: $HOST_ID..."
  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID/disable" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8")
  if [ $(echo "$RESPONSE" | jq -r '.error | length') -eq 0 ]; then
    echo -e " ${COLOR_GREEN}Proxy host disabled successfully!${COLOR_RESET} ✅"
  else
    echo -e " ${COLOR_RED}Failed to disable proxy host. Error: $(echo "$RESPONSE" | jq -r '.message')${COLOR_RESET}"
  fi
}

# Call functions based on options
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
else
  create_or_update_proxy_host
fi
