# Nginx Proxy Manager CLI Script

## Description

_by Erreur32_

🛠️ This BASH script allows you to manage Nginx Proxy Manager via the API.

🔑 Automatically generates and manages the tokens, ensuring their validity, so you don't have to worry about token expiration.

⚙️ Provides functionalities such as creating and deleting proxy hosts, managing users, displaying configurations, BACKUP! and more.

Ce script permet de gérer Nginx Proxy Manager via l'API. Il fournit des fonctionnalités telles que la création de hosts proxy, la gestion des utilisateurs, et l'affichage des configurations avec creation de BACKUP !

## Reference
![https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema)

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

## Settings
Only edit these 3 variables:

```
## Nginx proxy IP address (your Nginx IP)
NGINX_IP="127.0.0.1"
## Existing user (user and password) on NPM
API_USER="existingUser@mail.com"
API_PASS="password"
```

## Usage
```bash
./nginx_proxy_manager_cli.sh [OPTIONS]
```

## Options
```tcl
   -d DOMAIN_NAMES                 Domain name (required for creating/updating hosts)
   -i FORWARD_HOST                 IP address or domain name of the target server (required for creating/updating hosts)
   -p FORWARD_PORT                 Port of the target server (required for creating/updating hosts)
   -f FORWARD_SCHEME               Scheme for forwarding (http/https, default: http)
   -c CACHING_ENABLED              Enable caching (true/false, default: false)
   -b BLOCK_EXPLOITS               Block exploits (true/false, default: true)
   -w ALLOW_WEBSOCKET_UPGRADE      Allow WebSocket upgrade (true/false, default: true)
   -a ADVANCED_CONFIG              Advanced configuration (block of configuration settings)
   -t TOKEN_EXPIRY                 Token expiry duration (default: 1y)
   --backup                        Backup all configurations to a file
   --check-token                   Check if the current token is valid
   --create-user user pass email   Create a user with a username, password and email
   --delete-user username          Delete a user by username
   --delete-host id                Delete a proxy host by ID
   --show-host id                  Show full details for a specific host by ID
   --show-default                  Show default settings for creating hosts
   --list-hosts                    List the names of all proxy hosts
   --list-hosts-full               List all proxy hosts with full details
   --list-ssl-certificates         List all SSL certificates
   --list-users                    List all users
   --search-host hostname          Search for a proxy host by domain name
   --enable-host id                Enable a proxy host by ID
   --disable-host id               Disable a proxy host by ID
   --generate-cert domain email    Generate a Let's Encrypt certificate for the given domain and email
   --ssl-host-enable id            Enable SSL, HTTP/2, and HSTS for a proxy host (need --generate-cert first)
   --ssl-host-disable id           Disable SSL, HTTP/2, and HSTS for a proxy host
   --help                          Display this help

```

## Examples
```bash
   Backup First !
   ./nginx_proxy_manager_cli.sh --backup

   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 (check default values below)
   ./nginx_proxy_manager_cli.sh --show-default
   ./nginx_proxy_manager_cli.sh --create-user newuser password123 user@example.com
   ./nginx_proxy_manager_cli.sh --delete-user 'username'
   ./nginx_proxy_manager_cli.sh --list-hosts

   ./nginx_proxy_manager_cli.sh --generate-cert example.com user@example.com
   ./nginx_proxy_manager_cli.sh --ssl-host-enable 1

 Advanced proxy tab example:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'

```
 
# Procedure to Enable SSL for the First Time

## Generate SSL Certificate:

    ./nginx_proxy_manager_cli.sh --generate-cert example.com admin@example.com

## Enable SSL for the Host:

  Assuming the host ID is *1*, you would enable SSL for the host as follows:

    ./nginx_proxy_manager_cli.sh --ssl-host-enable 1

## Verifying the Configuration

  After running the above commands, you can verify the SSL configuration by checking the details of the proxy host.

    ./nginx_proxy_manager_cli.sh --show-host 1

This command will show the full details of the proxy host with ID *1*, including whether SSL is enabled.

By following these steps, you can enable SSL for your proxy host for the first time using Let's Encrypt.


![https://github.com/Erreur32/nginx-proxy-manager-API/blob/main/screen-nginx-proxy-default.png](https://github.com/Erreur32/nginx-proxy-manager-API/blob/main/screen-nginx-proxy-default.png)

## TODO:
- [x] add setting for ADVANCED configuration in `location / { ... }`
- [x] Add documentation on certain functions
- [x] ADD: a configuration function for Custom Locations
- [x] Backup / Export  all settings from NPM
- [ ] Domain TLS check validity
