# Nginx Proxy Manager CLI Script

## Table of Contents

1. [Description](#description)
2. [Reference API](#reference)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Settings](#settings)
6. [Usage](#usage)
7. [Options](#options)
8. [Examples](#examples)
9. [Screens](#screens)
10. [TODO](#todo)

## Description

🛠️ This BASH script enables the management of ![Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager?utm_source=nginx-proxy-manager) through its **API**.

🔑 **Automatically generates** and **manages tokens**, ensuring their validity, so you don't have to worry about token expiration.

⚙️ Provides functionalities such as creating and deleting proxy hosts, managing users, displaying configurations, creating **BACKUPS**, and more.

Ce script permet de gérer Nginx Proxy Manager via l'API. Il fournit des fonctionnalités telles que la création de hosts proxy, la gestion des utilisateurs, et l'affichage des configurations avec creation de BACKUP !

## Reference
![https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema)

## Prerequisites

And of course the excellent NPM (![Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager?utm_source=nginx-proxy-manager))

and simple dependencies:

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
# Path to store .txt files and Backups
BASE_DIR="/path/nginx_proxy_script/data"

```

## Usage
```bash
./nginx_proxy_manager_cli.sh [OPTIONS]
```

## Options
```tcl

 🌐 Host proxy creation:
   -d DOMAIN_NAMES                       Domain name (required for creating/updating hosts)
   -i FORWARD_HOST                       IP address or domain name of the target server (required for creating/updating hosts)
   -p FORWARD_PORT                       Port of the target server (required for creating/updating hosts)
   -f FORWARD_SCHEME                     Scheme for forwarding (http/https, default: http)
   -c CACHING_ENABLED                    Enable caching (true/false, default: false)
   -b BLOCK_EXPLOITS                     Block exploits (true/false, default: true)
   -w ALLOW_WEBSOCKET_UPGRADE            Allow WebSocket upgrade (true/false, default: true)
   -l CUSTOM_LOCATIONS                   Custom locations (JSON array of location objects)
   -a ADVANCED_CONFIG                    Advanced configuration (block of configuration settings)

📦 Backup and Restore:
   --backup                         Backup all configurations to a file
   --backup-id id                   Backup a single host configuration and its certificate (if exists)
   --restore                        Restore configurations from a backup file
   --restore-id id                  Restore a single host configuration and its certificate (if exists)

 🔧 Miscellaneous:
   --check-token                    Check if the current token is valid
   --create-user user pass email    Create a user with a username, password and email
   --delete-user username           Delete a user by username
   --host-delete id                      Delete a proxy host by ID
   --host-show id                        Show full details for a specific host by ID
   --show-default                   Show default settings for creating hosts
   --host-list                           List the names of all proxy hosts
   --host-list-full                      List all proxy hosts with full details
   --host-list-ssl-certificates          List all SSL certificates
   --host-list-users                     List all users
   --host-search hostname                Search for a proxy host by domain name
   --host-enable id                      Enable a proxy host by ID
   --host-disable id                     Disable a proxy host by ID
   --host-ssl-enable id                  Enable SSL, HTTP/2, and HSTS for a proxy host
   --host-ssl-disable id                 Disable SSL, HTTP/2, and HSTS for a proxy host
   --generate-cert domain email [--custom] Generate a Let's Encrypt or Custom certificate for the given domain and email

```

## Examples
```bash
  📦 Backup First !
   ./nginx_proxy_manager_cli.sh --backup

 🌐 Host Creation:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 (check default values below)
   ./nginx_proxy_manager_cli.sh --show-default
   ./nginx_proxy_manager_cli.sh --create-user newuser password123 user@example.com
   ./nginx_proxy_manager_cli.sh --delete-user 'username'
   ./nginx_proxy_manager_cli.sh --host-list
   ./nginx_proxy_manager_cli.sh --host-ssl-enable 10

 🔧 Advanced Example:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'

 🛡️ Custom Certificate:
   ./nginx_proxy_manager_cli.sh --generate-cert example.com user@example.com --custom

 🛡️  Custom locations:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'

🔖 Full options:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -f https -c true -b true -w true -a 'proxy_set_header X-Real-IP $remote_addr;' -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'

```
 

#### Enable SSL for the Host:

  Assuming the host ID is *10*, you would enable SSL for the host as follows:

    ./nginx_proxy_manager_cli.sh --host-ssl-enable 10

#### Verifying the Configuration

  After running the above commands, you can verify the SSL configuration by checking the details of the proxy host.

    ./nginx_proxy_manager_cli.sh --host-show 10

This command will show the full details of the proxy host with ID *10*, including whether SSL is enabled.

By following these steps, you can enable SSL for your proxy host for the first time using Let's Encrypt.

You should now see the parameters activated: 
  - "ssl_forced": 1,
  - "letsencrypt_agree": true,
  - "http2_support": 1

```
 ./nginx_proxy_manager_cli_.sh --host-show 10

 ✅ Nginx url: http://127.0.0.1:81/api
 ✅ The token is valid. Expiry: 2025-07-12T08:14:58.521Z

 👉 Full details for proxy host ID: 59...

{
  "id": 10,
  "created_on": "2024-07-11 13:16:34",
  "modified_on": "2024-07-13 09:42:40",
  "owner_user_id": 1,
  "domain_names": [
    "test.domain.com"
  ],
  "forward_host": "127.0.0.1",
  "forward_port": 80,
  "access_list_id": 0,
  "certificate_id": 81,
  "ssl_forced": 1,
  "caching_enabled": 0,
  "block_exploits": 1,
  "advanced_config": "",
  "meta": {
    "letsencrypt_agree": true,
    "letsencrypt_email": "",
    "nginx_online": true,
    "nginx_err": null
  },
  "allow_websocket_upgrade": 1,
  "http2_support": 1,
  "forward_scheme": "http",
  "enabled": 1,
  "locations": [],
  "hsts_enabled": 1,
  "hsts_subdomains": 0
}

```

 
## Screens:
```
# ./nginx_proxy_manager_cli.sh --backup

 ✅ Nginx url: http://192.168.1.200:81/api
 ✅ The token is valid. Expiry: 2025-07-12T08:14:58.521Z
 ✅ Full backup completed successfully in 📂 './backups'

```


![https://github.com/Erreur32/nginx-proxy-manager-API/blob/main/screen-nginx-proxy-default.png](https://github.com/Erreur32/nginx-proxy-manager-API/blob/main/screen-nginx-proxy-default.png)

## TODO:
- [x] add setting for ADVANCED configuration in npm `location / { ... }`
- [x] Add documentation on certain functions
- [x] ADD: a configuration function for Custom Locations
- [x] Backup  all settings from NPM
- [x] Export  all settings to NPM 
- [ ] Domain TLS check validity
- [ ] Better Error Handeling
- [ ] Restore Function need to be optimized
