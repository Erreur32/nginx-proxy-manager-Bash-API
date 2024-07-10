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
#   -s SSL_FORCED                    Force SSL (true/false, default: false)
#   -c CACHING_ENABLED               Enable caching (true/false, default: false)
#   -b BLOCK_EXPLOITS                Block exploits (true/false, default: true)
#   -w ALLOW_WEBSOCKET_UPGRADE       Allow WebSocket upgrade (true/false, default: false)
#   -h HTTP2_SUPPORT                 Support HTTP/2 (true/false, default: true)
#   -a ADVANCED_CONFIG               Advanced configuration (string)
#   -e LETS_ENCRYPT_AGREE            Accept Let's Encrypt (true/false, default: false)
#   -n DNS_CHALLENGE                 DNS challenge (true/false, default: false)
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

# Colors
COLOR_TRUE="\e[42;1mtrue\e[0m"  # Vert clair pour true
COLOR_FALSE="\e[93mfalse\e[0m"  # Rouge pour false


############################
# Don't need to touch bellow
############################
# Definition variables TOKEN
BASE_URL="http://$NGINX_IP:81/api"
API_ENDPOINT="/tokens"
EXPIRY_FILE="expiry.txt"
# File storage token
TOKEN_FILE="token.txt"


# Fonction pour générer le token
generate_token() {
  response=$(curl -s -X POST "$BASE_URL$API_ENDPOINT" \
    -H "Content-Type: application/json; charset=UTF-8" \
    --data-raw "{\"identity\":\"$API_USER\",\"secret\":\"$API_PASS\",\"expiry\":\"1y\"}")

  token=$(echo $response | jq -r '.token')
  expires=$(echo $response | jq -r '.expires')

  if [ "$token" != "null" ]; then
    echo $token > $TOKEN_FILE
    echo $expires > $EXPIRY_FILE
    echo "Token: $token"
    echo "Expiry: $expires"
  else
    echo "Erreur lors de la génération du token."
    exit 1
  fi
}

# Fonction pour valider le token
validate_token() {
  if [ ! -f "$TOKEN_FILE" ] || [ ! -f "$EXPIRY_FILE" ]; then
    return 1
  fi

  token=$(cat $TOKEN_FILE)
  expires=$(cat $EXPIRY_FILE)
  current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  if [[ "$current_time" < "$expires" ]]; then
    echo -e "\e[42;1mLe token est valide. Expiration: $expires\033[0m"
    return 0
  else
    echo -e "\e[41;1mLe token est invalide. Expiration: $expires\033[0m"
    return 1
  fi
}

# Vérifier si le fichier de token existe
if ! validate_token; then
  echo "Aucun token valide trouvé. Génération d'un nouveau token..."
  generate_token
fi

# Fonction pour coloriser les valeurs true et false
colorize_boolean() {
  local value=$1
  if [ "$value" = true ]; then
    echo -e "\e[92mtrue\e[0m"
  else
    echo -e "\e[93mfalse\e[0m"
  fi
}

# Afficher l'aide
usage() {
  echo -e "\n\e[33mUsage: $0 -d domain -i ip -p port [-s ssl_forced] [-c caching_enabled] [-b block_exploits] [-w allow_websocket_upgrade] [-h http2_support] [-a advanced_config] [-e lets_encrypt_agree] [-n dns_challenge] [--create-user username password] [--delete-user username] [--delete-host id] [--list-hosts] [--list-hosts-full] [--list-ssl-certificates] [--list-users] [--search-host hostname] [--help]\e[0m"

  echo -e ""
  echo -e "Options:"
  echo -e "  -d \e[33mDOMAIN_NAMES\e[0m            Nom de domaine (\e[41;1m obligatoire \e[0m)"
  echo -e "  -i \e[33mFORWARD_HOST\e[0m            Adresse IP ou nom de domaine du serveur cible (\e[41;1m obligatoire \e[0m)"
  echo -e "  -p \e[33mFORWARD_PORT\e[0m            Port du serveur cible (\e[41;1m obligatoire \e[0m)"
  echo -e "  -s SSL_FORCED              Forcer SSL (true/false, par défaut: $(colorize_boolean $SSL_FORCED))"
  echo -e "  -c CACHING_ENABLED         Activer le caching (true/false, par défaut: $(colorize_boolean $CACHING_ENABLED))"
  echo -e "  -b BLOCK_EXPLOITS          Bloquer les exploits (true/false, par défaut: $(colorize_boolean $BLOCK_EXPLOITS))"
  echo -e "  -w ALLOW_WEBSOCKET_UPGRADE Autoriser l'upgrade WebSocket (true/false, par défaut: $(colorize_boolean $ALLOW_WEBSOCKET_UPGRADE))"
  echo -e "  -h HTTP2_SUPPORT           Support HTTP/2 (true/false, par défaut: $(colorize_boolean $HTTP2_SUPPORT))"
  echo -e "  -a ADVANCED_CONFIG         Configuration avancée (chaîne de caractères)"
  echo -e "  -e LETS_ENCRYPT_AGREE      Accepter Let's Encrypt (true/false, par défaut: $(colorize_boolean $LETS_ENCRYPT_AGREE))"
  echo -e "  -n DNS_CHALLENGE           Défi DNS (true/false, par défaut: $(colorize_boolean $DNS_CHALLENGE))"
  echo -e "  --create-user username password Créer un utilisateur avec un nom d'utilisateur et un mot de passe"
  echo -e "  --delete-user username     Supprimer un utilisateur par son nom d'utilisateur"
  echo -e "  --delete-host id           Supprimer un proxy host par son ID"
  echo -e "  --list-hosts               Lister les noms de tous les proxy hosts"
  echo -e "  --list-hosts-full          Lister tous les proxy hosts avec les détails complets"
  echo -e "  --list-ssl-certificates    Lister tous les certificats SSL"
  echo -e "  --list-users               Lister tous les utilisateurs"
  echo -e "  --search-host hostname     Rechercher un proxy host par nom de domaine"
  echo -e "  --help                     Afficher cette aide"
        echo
  exit 1
}

# Variables par défaut
SSL_FORCED=false
CACHING_ENABLED=false
BLOCK_EXPLOITS=true
ALLOW_WEBSOCKET_UPGRADE=false
HTTP2_SUPPORT=true
ADVANCED_CONFIG=""
LETS_ENCRYPT_AGREE=false
DNS_CHALLENGE=false

# Variables de contrôle
CREATE_USER=false
DELETE_USER=false
DELETE_HOST=false
LIST_HOSTS=false
LIST_HOSTS_FULL=false
LIST_SSL_CERTIFICATES=false
LIST_USERS=false
SEARCH_HOST=false

# Parse les options en ligne de commande
while getopts "d:i:p:s:c:b:w:h:a:e:n:-:" opt; do
  case $opt in
    d) DOMAIN_NAMES="$OPTARG" ;;
    i) FORWARD_HOST="$OPTARG" ;;
    p) FORWARD_PORT="$OPTARG" ;;
    s) SSL_FORCED="$OPTARG" ;;
    c) CACHING_ENABLED="$OPTARG" ;;
    b) BLOCK_EXPLOITS="$OPTARG" ;;
    w) ALLOW_WEBSOCKET_UPGRADE="$OPTARG" ;;
    h) HTTP2_SUPPORT="$OPTARG" ;;
    a) ADVANCED_CONFIG="$OPTARG" ;;
    e) LETS_ENCRYPT_AGREE="$OPTARG" ;;
    n) DNS_CHALLENGE="$OPTARG" ;;
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
        *) echo "Option inconnue --${OPTARG}" ; usage ;;
      esac ;;
    *) usage ;;
  esac
done

# Vérifie les paramètres obligatoires pour afficher l'aide
if [ -z "$DOMAIN_NAMES" ] && ! $CREATE_USER && ! $DELETE_USER && ! $DELETE_HOST && ! $LIST_HOSTS && ! $LIST_HOSTS_FULL && ! $LIST_SSL_CERTIFICATES && ! $LIST_USERS && ! $SEARCH_HOST; then
  usage
fi

###################################################

# Fonction pour créer un proxy host
create_proxy_host() {
  if [ -z "$DOMAIN_NAMES" ] || [ -z "$FORWARD_HOST" ] || [ -z "$FORWARD_PORT" ]; then
    echo "Les paramètres -d, -i et -p sont obligatoires pour créer un proxy host."
    usage
  fi
  echo "Création du proxy host pour $DOMAIN_NAMES..."
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
      "dns_challenge": '"$DNS_CHALLENGE"'
    },
    "allow_websocket_upgrade": '"$ALLOW_WEBSOCKET_UPGRADE"',
    "http2_support": '"$HTTP2_SUPPORT"',
    "forward_scheme": "http",
    "enabled": true,
    "locations": []
  }'

  echo "Données envoyées: $DATA"

  RESPONSE=$(curl -s -X POST "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw "$DATA")
  echo "Réponse de la création du proxy host: $RESPONSE"
  echo "$RESPONSE" | jq
}

# Fonction pour supprimer un proxy host
delete_proxy_host() {
  if [ -z "$HOST_ID" ]; then
    echo "L'option --delete-host nécessite un ID de host."
    usage
  fi
  echo "Suppression du proxy host ID: $HOST_ID..."
  RESPONSE=$(curl -s -X DELETE "$BASE_URL/nginx/proxy-hosts/$HOST_ID" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "Réponse de la suppression du proxy host: $RESPONSE"
  echo "$RESPONSE" | jq
}

# Fonction pour lister tous les proxy hosts (simple)
list_proxy_hosts_old() {
  echo " Liste des proxy hosts..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq -c '.[] | {id, domain_names}'
}

list_proxy_hosts() {
  echo " Liste des proxy hosts..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -r '.[] | "\(.id) \(.domain_names[])"' | awk '{ printf "  id: \033[33m%-4s\033[0m \033[32m%s\033[0m\n", $1, $2 }'
#  echo "$RESPONSE" | jq -r '.[] | "\(.id) \(.domain_names[])"' | sort -n | awk '{ printf "id: \033[33m%-4s\033[0m \033[32m%s\033[0m\n", $1, $2 }'

}


list_proxy_hosts_full() {
  echo "Liste des proxy hosts avec détails complets..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

  echo "$RESPONSE" | jq -c '.[]' | while IFS= read -r line; do
    domain_names=$(echo "$line" | jq -r '.domain_names[]')
    advanced_config=$(echo "$line" | jq -r '.advanced_config')

    # Colorisation des noms de domaines en vert
    echo -e "\033[32m$domain_names\033[0m"

    # Colorisation des IPs en jaune sans chevauchement
    echo -e "$advanced_config" | awk '{
      gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, "\033[33m&\033[0m");
      print
    }' | sed 's/^/ /'  # Indentation de chaque ligne
    echo
  done
}


# Fonction pour lister tous les proxy hosts avec détails formatés
list_proxy_hosts_full_old() {
  echo " Liste des proxy hosts avec détails complets..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq -c '.[]' | while IFS= read -r line; do
    domain_names=$(echo "$line" | jq -r '.domain_names[]')
    advanced_config=$(echo "$line" | jq -r '.advanced_config')

    echo "domain_names: $domain_names"
    echo "$advanced_config" | sed 's/^/ /'  # Indentation de chaque ligne
    echo
  done
}

# Fonction pour rechercher un proxy host et afficher les détails si trouvé
search_proxy_host() {
  if [ -z "$SEARCH_HOSTNAME" ]; then
    echo "L'option --search-host nécessite un nom de domaine."
    usage
  fi
  echo "Recherche du proxy host pour $SEARCH_HOSTNAME..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/proxy-hosts" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq -c --arg search "$SEARCH_HOSTNAME" '.[] | select(.domain_names[] | contains($search))' | while IFS= read -r line; do
    domain_names=$(echo "$line" | jq -r '.domain_names[]')
    advanced_config=$(echo "$line" | jq -r '.advanced_config')

    echo "domain_names: $domain_names"
    echo "$advanced_config" | sed 's/^/ /'  # Indentation de chaque ligne
    echo
  done
}

# Fonction pour lister tous les certificats SSL
list_ssl_certificates() {
  echo "Liste des certificats SSL..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/nginx/certificates" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq
}

# Fonction pour lister tous les utilisateurs
list_users() {
  echo "Liste des utilisateurs..."
  RESPONSE=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
  echo "$RESPONSE" | jq
}

# Fonction pour créer un utilisateur
create_user() {
  if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo "Les paramètres username et password sont obligatoires pour créer un utilisateur."
    usage
  fi
  echo "Création de l'utilisateur $USERNAME..."
  RESPONSE=$(curl -s -X POST "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
  -H "Content-Type: application/json; charset=UTF-8" \
  --data-raw '{
    "username": "'"$USERNAME"'",
    "password": "'"$PASSWORD"'",
    "roles": ["user"]
  }')
  echo "Réponse de la création de l'utilisateur: $RESPONSE"
  echo "$RESPONSE" | jq
}

# Fonction pour supprimer un utilisateur
delete_user() {
  if [ -z "$USERNAME" ]; then
    echo "L'option --delete-user nécessite un nom d'utilisateur."
    usage
  fi
  echo "Suppression de l'utilisateur $USERNAME..."
  USER_ID=$(curl -s -X GET "$BASE_URL/users" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)" | jq -r '.[] | select(.username == "'"$USERNAME"'") | .id')

  if [ -n "$USER_ID" ]; then
    RESPONSE=$(curl -s -X DELETE "$BASE_URL/users/$USER_ID" \
    -H "Authorization: Bearer $(cat $TOKEN_FILE)")
    echo "Réponse de la suppression de l'utilisateur: $RESPONSE"
    echo "$RESPONSE" | jq
  else
    echo "Utilisateur non trouvé : $USERNAME"
  fi
}

# Appel des fonctions en fonction des options
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
