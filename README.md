# Nginx Proxy Manager CLI Script

## Description

_by Erreur32_

🛠️ This BASH script allows you to manage Nginx Proxy Manager via the API.

🔑 It automatically generates and manages the tokens, ensuring their validity, so you don't have to worry about token expiration.

⚙️ It provides functionalities such as creating and deleting proxy hosts, managing users, displaying configurations, and more.

Ce script permet de gérer Nginx Proxy Manager via l'API. Il fournit des fonctionnalités telles que la création de hosts proxy, la gestion des utilisateurs, et l'affichage des configurations.

## Prerequisites

- `curl`
- `jq`

```bash
sudo apt-get install jq curl
```

## Installation 
```
wget https://raw.githubusercontent.com/Erreur32/nginx-proxy-manager-API/main/nginx_proxy_manager_cli.sh
chmod +x nginx_proxy_manager_cli.sh
```

## Settings:
Only edit these 3 variables:

```
## IP address of the Nginx server (your Nginx server IP)
NGINX_IP="127.0.0.1"
## Existing user (user and password) on NPM
API_USER="existingUser@mail.com"
API_PASS="password"
```

## Usage:
```bash
./nginx_proxy_manager_cli.sh [OPTIONS]
```

## Options:
```tcl
   -d DOMAIN_NAMES                  Domain name (required)
   -i FORWARD_HOST                  IP address or domain name of the target server (required)
   -p FORWARD_PORT                  Port of the target server (required)
   -s SSL_FORCED                    Force SSL (true/false, default: false)
   -c CACHING_ENABLED               Enable caching (true/false, default: false)
   -b BLOCK_EXPLOITS                Block exploits (true/false, default: true)
   -w ALLOW_WEBSOCKET_UPGRADE       Allow WebSocket upgrade (true/false, default: false)
   -h HTTP2_SUPPORT                 Support HTTP/2 (true/false, default: true)
   -a ADVANCED_CONFIG               Advanced configuration (string)
   -e LETS_ENCRYPT_AGREE            Accept Let's Encrypt (true/false, default: false)
   -n DNS_CHALLENGE                 DNS challenge (true/false, default: false)
   --create-user username password  Create a user with a username and password
   --delete-user username           Delete a user by username
   --delete-host id                 Delete a proxy host by ID
   --list-hosts                     List the names of all proxy hosts
   --list-hosts-full                List all proxy hosts with full details
   --list-ssl-certificates          List all SSL certificates
   --list-users                     List all users
   --search-host hostname           Search for a proxy host by domain name
   --help                           Display this help
```

## Examples:
```bash
./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -s true
./nginx_proxy_manager_cli.sh --create-user newuser password123
./nginx_proxy_manager_cli.sh --list-hosts
```

![https://github.com/Erreur32/nginx-proxy-manager-API/blob/main/screen-nginx-proxy-script.png](https://github.com/Erreur32/nginx-proxy-manager-API/blob/main/screen-nginx-proxy-script.png)

## TODO:
- add setting for ADVANCED configuration in `location / { ... }`
 
