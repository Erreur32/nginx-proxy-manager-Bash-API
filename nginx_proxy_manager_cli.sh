#!/bin/bash

###############################################################################
# Nginx Proxy Manager CLI Script by Erreur32  July 2024
#
# This script allows you to manage Nginx Proxy Manager via the API. It provides
# functionalities such as creating proxy hosts, managing users, and displaying
# configurations.
#
# Usage:
#   ./nginx_proxy_manager_cli.sh [OPTIONS]
#
# Options:
#   -d DOMAIN_NAMES                  Domain name (required)
#   -i FORWARD_HOST                  IP address or domain name of the target server (required)
#   -p FORWARD_PORT                  Port of the target server (required)
#   -f FORWARD_SCHEME                Scheme for forwarding (http/https, default: http)
#   -s SSL_FORCED                    Force SSL (true/false, default: false)
#   -c CACHING_ENABLED               Enable caching (true/false, default: false)
#   -b BLOCK_EXPLOITS                Block exploits (true/false, default: true)
#   -w ALLOW_WEBSOCKET_UPGRADE       Allow WebSocket upgrade (true/false, default: false)
#   -h HTTP2_SUPPORT                 Support HTTP/2 (true/false, default: true)
#   -a ADVANCED_CONFIG               Advanced configuration (string)
#   -e LETS_ENCRYPT_AGREE            Accept Let's Encrypt (true/false, default: false)
#   -m LETS_ENCRYPT_EMAIL            Email for Let's Encrypt (required if LETS_ENCRYPT_AGREE is true)
#   -n DNS_CHALLENGE                 DNS challenge (true/false, default: false)
#   -t TOKEN_EXPIRY                  Token expiry duration (default: 1y)
#   --create-user username password  Create a user with a username and password
#   --delete-user username           Delete a user by username
#   --delete-host id                 Delete a proxy host by ID
#   --list-hosts                     List the names of all proxy hosts
#   --list-hosts-full                List all proxy hosts with full details
#   --list-ssl-certificates          List all SSL certificates
#   --list-users                     List all users
#   --search-host hostname           Search for a proxy host by domain name
#   --help                           Display this help
#
# Examples:
#   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -s true
#   ./nginx_proxy_manager_cli.sh --create-user newuser password123
#   ./nginx_proxy_manager_cli.sh --list-hosts
#
###############################################################################


######## Variables to edit ##########
# Address IP server Nginx (your nginx ip server)
NGINX_IP="192.168.1.1"
# Token creation (user pass) with valid user on npm.
API_USER="your@email.com"
API_PASS="password"
# Default token expiry duration
TOKEN_EXPIRY="1y"

# Colors
COLOR_TRUE="\e[42;1mtrue\e[0m"  # Light green for true
COLOR_FALSE="\e[93mfalse\e[0m"  # Red for false
COLOR_ERROR="\e[41;1m"          # Red for errors

############################
# Don't need to touch below
############################
# Definition variables TOKEN
BASE_URL="http://$NGINX_IP:81/api"
API_ENDPOINT="/tokens"
# File storage token
TOKEN_FILE="token.txt"

# Check if Nginx IP and port are accessible
check_nginx_access() {
  if ! curl -s --head --request GET "$BASE_URL" | grep "200 OK" > /dev/null; then
    echo -e "${COLOR_ERROR}Error: Nginx is not accessible at $NGINX_IP:81${COLOR_FALSE}"
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
    echo "Token: $token"
    echo "Expiry: $expires"
  else
    echo -e "${COLOR_ERROR}Error generating token.${COLOR_FALSE}"
    exit 1
  fi
}

# Function to validate the token
validate_token() {
  if [ ! -f "$TOKEN_FILE" ]; then
    return 1
  fi

  token=$(cat $TOKEN_FILE)
  current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  if [[ "$current_time" < "$expires" ]]; then
    echo -e "\e[42;1mThe token is valid. Expiry: $expires\033[0m"
    return 0
  else
    echo -e "\e[41;1mThe token is invalid. Expiry: $expires\033[0m"
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

# Function to colorize true and false values
colorize_boolean() {
  local value=$1
  if [ "$value" = true ]; then
    echo -e "\e[92mtrue\e[0m"
  else
    echo -e "\e[93mfalse\e[0m"
  fi
}

# Display help
usage() {
  echo -e "\n\e[33mUsage: $0 -d domain -i ip -p port [-f forward_scheme] [-s ssl_forced] [-c caching_enabled] [-b block_exploits] [-w allow_websocket_upgrade] [-h http2_support] [-a advanced_config] [-e lets_encrypt_agree] [-m lets_encrypt_email] [-n dns_challenge] [-t token_expiry] [--create-user username password] [--delete-user username] [--delete-host id] [--list-hosts] [--list-hosts-full] [--list-ssl-certificates] [--list-users] [--search-host hostname] [--help]\e[0m"

  echo -e ""
  echo -e "Options:"
  echo -e "  -d \e[33mDOMAIN_NAMES\e[0m            Domain name (\e[41;1m required \e[0m)"
  echo -e "  -i \e[33mFORWARD_HOST\e[0m            IP address or domain name of the target server (\e[41;1m required \e[0m)"
  echo -e "  -p \e[33mFORWARD_PORT\e[0m            Port of the target server (\e[41;1m required \e[0m)"
  echo -e "  -f \e[33mFORWARD_SCHEME\e[0m          Scheme for forwarding (http/https, default: http)"
  echo -e "  -s SSL_FORCED              Force SSL (true/false, default: $(colorize_boolean $SSL_FORCED))"
  echo -e "  -c CACHING_ENABLED         Enable caching (true/false, default: $(colorize_boolean $CACHING_ENABLED))"
  echo -e "  -b BLOCK_EXPLOITS          Block exploits (true/false, default: $(colorize_boolean $BLOCK_EXPLOITS))"
  echo -e "  -w ALLOW_WEBSOCKET_UPGRADE Allow WebSocket upgrade (true/false, default: $(colorize_boolean $ALLOW_WEBSOCKET_UPGRADE))"
  echo -e "  -h HTTP2_SUPPORT           Support HTTP/2 (true/false, default: $(colorize_boolean $HTTP2_SUPPORT))"
  echo -e "  -a ADVANCED_CONFIG         Advanced configuration (string)"
  echo -e "  -e LETS_ENCRYPT_AGREE      Accept Let's Encrypt (true/false, default: $(colorize_boolean $LETS_ENCRYPT_AGREE))"
  echo -e "  -m LETS_ENCRYPT_EMAIL      Email for Let's Encrypt (required if LETS_ENCRYPT_AGREE is true)"
  echo -e "  -n DNS_CHALLENGE           DNS challenge (true/false, default: $(colorize_boolean $DNS_CHALLENGE))"
  echo -e "  -t TOKEN_EXPIRY            Token expiry duration (default: 1y)"
  echo -e "  --create-user username password Create a user with a username and password"
  echo -e "  --delete-user username     Delete a user by username"
  echo -e "  --delete-host id           Delete a proxy host by ID"
  echo -e "  --list-hosts               List the names of all proxy hosts"
  echo -e "  --list-hosts-full          List all proxy hosts with full details"
  echo -e "  --list-ssl-certificates    List all SSL certificates"
  echo -e "  --list-users               List all users"
  echo -e "  --search-host hostname     Search for a proxy host by domain name"
  echo -e "  --help                     Display this help"
        echo
  exit 1
}

# Default variables
SSL_FORCED=false
CACHING_ENABLED=false
BLOCK_EXPLOITS=true
ALLOW_WEBSOCKET_UPGRADE=false
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
        *) echo "Unknown option --${OPTARG}" ; usage ;;
      esac ;;
    *) usage ;;
  esac
done

# Check required parameters for displaying help
if [ -z "$DOMAIN_NAMES" ] && ! $CREATE_USER && ! $DELETE_USER && ! $DELETE_HOST && ! $LIST_HOSTS && ! $LIST_HOSTS_FULL && ! $LIST_SSL_CERTIFICATES && ! $LIST_USERS && ! $SEARCH_HOST; then
  usage
fi

###################################################

# Function to check if proxy host exists
check_existing_proxy_host() {
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  EXISTING_HOST=$(echo "$RESPONSE" | jq -r --arg DOMAIN "$DOMAIN_NAMES" '.[] | select(.domain_names[] == $DOMAIN)')

  if [ -n "$EXISTING_HOST" ]; then
    echo "Proxy host for $DOMAIN_NAMES already exists."
    read -p "Do you want to update it with the new configuration? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      HOST_ID=$(echo "$EXISTING_HOST" | jq -r '.id')
      update_proxy_host $HOST_ID
    else
      echo "No changes made."
      exit 0
    fi
  fi
}

# Function to update a proxy host
update_proxy_host() {
  HOST_ID=$1
  echo "Updating proxy host for $DOMAIN_NAMES..."
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

  echo "Data sent: $DATA"

  RESPONSE=$(curl -s -X PUT "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")
  echo "Response from updating proxy host: $RESPONSE"
  echo "$RESPONSE" | jq
}

# Function to create a proxy host
create_proxy_host() {
  if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ]; then
    echo "The -d, -i, and -p options are required to create a proxy host."
    usage
  fi
  if $LETS_ENCRYPT_AGREE && [ -z "$LETS_ENCRYPT_EMAIL" ]; then
    echo "The -m option is required when -e is true."
    usage
  fi

  check_existing_proxy_host

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

  echo "Data sent: $DATA"

  RESPONSE=$(curl -s -X POST "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")
  echo "Response from creating proxy host: $RESPONSE"
  echo "$RESPONSE" | jq
}

# Function to delete a proxy host
delete_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo "The --delete-host option requires a host ID."
    usage
  fi
  echo "Deleting proxy host ID: $HOST_ID..."
  RESPONSE=$(curl -s -X DELETE "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "Response from deleting proxy host: $RESPONSE"
  echo "$RESPONSE" | jq
}

# Function to list all proxy hosts (simple)
list_proxy_hosts() {
  echo "List of proxy hosts..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -r '.[] | "\(.id) \(.domain_names[])"' | awk '{ printf "  id: \033[33m%-4s\033[0m \033[32m%s\033[0m\n", $1, $2 }'
}

# Function to list all proxy hosts with full details
list_proxy_hosts_full() {
  echo "List of proxy hosts with full details..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -c '.[]' | while IFS= read -r line; do
    domain_names=$(echo "$line" | jq -r '.domain_names[]')
    advanced_config=$(echo "$line" | jq -r '.advanced_config')

    # Colorize domain names in green
    echo -e "\033[32m$domain_names\033[0m"

    # Colorize IPs in yellow without overlap
    echo -e "$advanced_config" | awk '{
      gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, "\033[33m&\033[0m");
      print
    }' | sed 's/^/ /'  # Indentation of each line
    echo
  done
}

# Function to search for a proxy host and display details if found
search_proxy_host() {
  if [ -z "$SEARCH_HOSTNAME" ]; then
    echo "The --search-host option requires a domain name."
    usage
  fi
  echo "Searching for proxy host for $SEARCH_HOSTNAME..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq -c --arg search "$SEARCH_HOSTNAME" '.[] | select(.domain_names[] | contains($search))' | while IFS= read -r line; do
    domain_names=$(echo "$line" | jq -r '.domain_names[]')
    advanced_config=$(echo "$line" | jq -r '.advanced_config')

    echo "domain_names: $domain_names"
    echo "$advanced_config" | sed 's/^/ /'  # Indentation of each line
    echo
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
  echo "Response from creating user: $RESPONSE"
  echo "$RESPONSE" | jq
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
    echo "Response from deleting user: $RESPONSE"
    echo "$RESPONSE" | jq
  else
    echo "User not found: $USERNAME"
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
else
  create_proxy_host
fi
