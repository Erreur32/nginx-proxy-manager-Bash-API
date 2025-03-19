[![Release][release-shield]][release]
![Project Stage][project-stage-shield]
![Project Maintenance][maintenance-shield]
[![License][license-shield]][license]
[![Contributors][contributors-shield]][contributors]
[![Issues][issues-shield]][issue]
[![Stargazers][stars-shield]][stars]


# Nginx Proxy Manager CLI Script

## Table of Contents


1. [Description](#description)
2. [Reference API](#reference-api)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Settings](#settings)
6. [Usage](#usage)
7. [Options](#options)
8. [Examples](#examples)
   - [Info script](#info)
   - [List HOST](#list)
   - [Enable SSL](#ssl)
   - [Update specific fields of an existing proxy host](#update)  
9. [Important Notice](#-important-notice-repository-history-rewritten)
10. [TODO](#todo)

> [!WARNING]
> The  --restore command is disabled  (a fix is in progress).
> 
> V2.6.0 introduced some issues. A fix has been tested and pushed,  but user feedback is required to ensure everything works as expected with V2.7.0.

## Description
🛠️ This script allows you to efficiently manage [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager?utm_source=nginx-proxy-manager) via its **API**. It provides advanced features such as proxy host creation, user management, and configuration display, while also integrating a backup system (BACKUP) with a user-friendly interface.

It simplifies task automation, including proxy creation, SSL certificate management, and full reverse proxy administration.

⚠️ The RESTORE function is still under development. 🚧

🔑 **Automatically generates** and **manages tokens**, ensuring their validity, so you don't have to worry about token expiration.

<details>
<summary>French description:</summary>
Ce script permet de gérer Nginx Proxy Manager via son API de manière simple et efficace. Il offre des fonctionnalités avancées telles que la création de hosts proxy, la gestion des utilisateurs et l'affichage des configurations, tout en intégrant un système de sauvegarde (BACKUP) avec une interface conviviale.

Il facilite l'automatisation des tâches courantes, comme l'ajout de proxies, la gestion des certificats SSL et l'administration complète de vos reverse proxies.

⚠️ La fonction RESTORE est encore en développement. 🚧
</details>

## Reference API
[https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema)

## Prerequisites

The excellent NPM (![Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager?utm_source=nginx-proxy-manager))

Required basic dependencies. 
  > The script will automatically check if they are installed and will download them if necessary:

- `curl`
- `jq`


## Installation 
```bash
wget https://raw.githubusercontent.com/Erreur32/nginx-proxy-manager-Bash-API/main/npm-api.sh
chmod +x npm-api.sh
# Run the script.
./npm-api.sh
```


> [!NOTE]
> With the new `V2.0.0`, some command arguments have been changed to be simpler, and need to set `BASE_DIR` variable to store `Tokens` and `Backups`.


## Settings
> [!IMPORTANT]
> (Optional) You can create a configuration file named `npm-api.conf` with these 4 required variables.

To ensure the script is functional, edit these 4 variables (mandatory).

```bash
# npm-api.conf

## Nginx proxy IP address (your Nginx IP/port)
NGINX_IP="127.0.0.1"
NGINX_PORT="81"

## Existing user (user and password) on NPM
API_USER="admin@example.com"
API_PASS="changeme"

# Optional (only if you want in other /path than script directory)
# DATA_DIR="/path/nginx_backup/dir"

```

## Usage
```bash
./npm-api.sh [OPTIONS]
./npm-api.sh  --help
./npm-api.sh  --show-default 
```

> [!NOTE]  
> **New in version 2.6.0:**
> - 📊 New dashboard (by default)
> - 🔐 Improved token management
> - 📋 Enhanced command display and options
> - 🎨 More user-friendly interface with icons and colors

## NEW dashboard

```bash
 📊 NGINX - Proxy Manager - Dashboard 🔧
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ┌─────────────────┬─────────┐
 │  COMPONENT      │ STATUS  │
 ├─────────────────┼─────────┤
 │ 🌐 Proxy Hosts  │ 11      │
 │ ├─ Enabled      │ 9       │
 │ └─ Disabled     │ 2       │
 ├─────────────────┼─────────┤
 │ 🔄 Redirections │ 1       │
 │ 🔌 Stream Hosts │ 0       │
 ├─────────────────┼─────────┤
 │ 🔒 Certificates │ 1       │
 │ ├─ Valid        │ 1       │
 │ └─ Expired      │ 0       │
 ├─────────────────┼─────────┤
 │ 🔒 Access Lists │ 1       │
 │ └─ Clients      │ 0       │
 ├─────────────────┼─────────┤
 │ 👥 Users        │ 3       │
 ├─────────────────┼─────────┤
 │ ⏱️  Uptime       │ 2 days  │
 │ 📦 NPM Version  │ 2.12.3  │
 └─────────────────┴─────────┘

 💡 Use --help to see available commands
    Check --examples for more help examples

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
   -y                                    Automatic yes prompts, yes sir!

📦 Backup and Restore:
   --backup                             Backup all configurations to a file
   --backup-host id                     Backup a single host configuration and its certificate (if exists)

 🔧 Miscellaneous:
   --check-token                         Check if the current token is valid
   --create-user user pass email         Create a user with a username, password and email
   --delete-user username                Delete a user by username
   --host-delete id                      Delete a proxy host by ID
   --host-show id                        Show full details for a specific host by ID
   --show-default                        Show default settings for creating hosts
   --host-list                           List the names of all proxy hosts
   --host-list-full                      List all proxy hosts with full details
   --list-users                          List all users

   --host-search hostname                Search for a proxy host by domain name
   --host-enable id                      Enable a proxy host by ID
   --host-disable id                     Disable a proxy host by ID
   --host-ssl-enable id                  Enable SSL, HTTP/2, and HSTS for a proxy host
   --host-ssl-disable id                 Disable SSL, HTTP/2, and HSTS for a proxy host
   --list-ssl-cert                       List All SSL certificates availables (JSON)
   --generate-cert domain email          Generate certificate for the given domain and email
   --delete-cert domain                  Delete   certificate for the given domain
   --list-access                         List all available access lists (ID and name)
   --host-acl-enable id,access_list_id   Enable ACL for a proxy host by ID with an access list ID       
   --host-acl-disable id                 Disable ACL for a proxy host by ID
   --update-host id field=value          Modify any field on existing entry host
   --help                                Display this help

```

## Examples

```bash
  📦 Backup First !
   ./npm-api.sh --backup

 🌐 Host Creation:
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 (check default values below)
   ./npm-api.sh --info
   ./npm-api.sh --show-default
   ./npm-api.sh --create-user newuser password123 user@example.com
   ./npm-api.sh --delete-user 'username'
   ./npm-api.sh --host-list
   ./npm-api.sh --host-ssl-enable 10

 🤖 Automatic operations (no prompts):
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -y
   ./npm-api.sh --host-delete 42 -y
   ./npm-api.sh --host-ssl-enable 10 -y   

 🔍 Information and Status:
   ./npm-api.sh --info                   # Show script configuration and status
   ./npm-api.sh --check-token            # Verify token validity
   ./npm-api.sh --host-search domain.com # Search for a specific domain

 🔄 Host Management:
   # Enable/Disable hosts
   ./npm-api.sh --host-enable 42
   ./npm-api.sh --host-disable 42

 🛡️ Access Control Lists:
   ./npm-api.sh --list-access                   # List all access lists
   ./npm-api.sh --host-acl-enable 42,5          # Enable ACL ID 5 for host 42
   ./npm-api.sh --host-acl-disable 42           # Disable ACL for host 42

 🔒 SSL Management:
   ./npm-api.sh --list-ssl-cert                 # List all SSL certificates
   ./npm-api.sh --delete-cert domain.com        # Delete certificate for domain

 🔄 Update Specific Fields:
   # Update individual fields without recreating the entire host
   ./npm-api.sh --update-host 42 forward_scheme=https
   ./npm-api.sh --update-host 42 forward_port=8443
   ./npm-api.sh --update-host 42 block_exploits=true
   ./npm-api.sh --update-host 42 allow_websocket_upgrade=true

 🔧 Advanced Example:
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'

 🛡️ Custom Certificate:
   ./npm-api.sh --generate-cert example.com user@example.com 
   # Note: This will generate a Let's Encrypt certificate only

 🛡️  Custom locations:
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'

🔖 Full options:
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -f https -c true -b true -w true -a 'proxy_set_header X-Real-IP $remote_addr;' -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'
```

### --backup

```bash
./npm-api.sh --backup
```



 

### 💾 Backup Operations

#### Schema of the backup directory:

```bash
# Full backup of all configurations
./npm-api.sh --backup

# This will create a backup in the following structure:
📁 data/
└── 📁 backups/
    └── 📁 [IP]_[PORT]/
        ├── 📁 .access_lists/                    # Access list configurations
        ├── 📁 .Proxy_Hosts/                     # All proxy host configurations
        │   ├── 📁 [DOMAIN]/                     # Directory for each domain
        │   │   ├── 📁 logs/                     # Log directory
        │   │   ├── 📁 ssl/                      # SSL directory
        │   │   │   ├── 📄 certificate_meta.json # Certificate metadata
        │   │   │   ├── 📄 certificate.pem       # Certificate
        │   │   │   ├── 📄 chain.pem             # Chain of certificates
        │   │   │   └── 📄 private.key           # Private key
        │   │   ├── 📄 nginx.conf                # Nginx configuration
        │   │   └── 📄 proxy_config.json         # Proxy configuration
        │   ├── 📄 all_hosts_[DATE].json         # List of all hosts
        │   └── 📄 all_hosts_latest.json         # Symlink to latest backup        
        ├── 📁 .settings/                        # NPM settings
        ├── 📁 .ssl/                             # SSL certificates
        ├── 📁 .user/                            # User configurations
        └── 📄 full_config.json                  # Complete backup file
        └── 📁 token/  
            ├── 📄 token.txt                     # Authentication token
            └── 📄 expiry.txt                    # Token expiry date        
```

#### 🔄 Backup Contents

1. **Proxy Hosts** (`/.Proxy_Hosts/`)
   - Individual host configurations
   - Nginx configurations
   - Complete host list with timestamps

2. **SSL Certificates** (`/.ssl/`)
   - Certificates and private keys
   - Certificate metadata
   - Chain certificates

3. **Access Lists** (`/.access_lists/`)
   - Access list configurations
   - Client authorizations
   - Access rules

4. **Users** (`/.user/`)
   - User accounts
   - Permissions
   - Authentication settings

5. **Settings** (`/.settings/`)
   - Global NPM settings
   - System configurations
   - Default parameters

#### 🔐 Token Management

The `token/` directory contains:
- Authentication tokens
- Token expiry information
- One file per NPM instance

#### --host-update      
##### update specific fields of an existing proxy host

The `--host-update` command allows you to **update specific fields** of an existing proxy host in Nginx Proxy Manager **without recreating it**.  

Simply specify the **proxy host ID** and the **field you want to update**, like this:

```bash
./npm-api.sh --update-host 42 forward_host=new.backend.local
```
 
| Field Name               | Type      | Description                                                                 |
|--------------------------|-----------|-----------------------------------------------------------------------------|
| `domain_names`           | `array`   | List of domains handled by this proxy.                                      |
| `forward_host`           | `string`  | The destination (backend) hostname or IP.                                   |
| `forward_port`           | `integer` | The destination port (e.g., `8000`, `443`).                                 |
| `forward_scheme`         | `string`  | The scheme: `http` or `https`.                                              |
| `enabled`                | `boolean` | Whether the proxy is enabled (`true` or `false`).                           |
| `ssl_forced`             | `boolean` | Redirect all HTTP requests to HTTPS.                                        |
| `certificate_id`         | `integer` | The ID of the SSL certificate to use.                                       |
| `meta.letsencrypt_agree` | `boolean` | Agree to Let's Encrypt TOS (`true` or `false`).                             |
| `meta.dns_challenge`     | `boolean` | Use DNS challenge for SSL cert (`true` or `false`).                         |
| `allow_websocket_upgrade`| `boolean` | Enable WebSocket support (`true` or `false`).                               |
| `http2_support`          | `boolean` | Enable HTTP/2 (`true` or `false`).                                          |
| `caching_enabled`        | `boolean` | Enable caching (`true` or `false`).                                         |
| `block_exploits`         | `boolean` | Block known exploits (`true` or `false`).                                   |
| `advanced_config`        | `string`  | Custom Nginx directives (multiline string).                                 |
| `locations`              | `array`   | Custom location blocks (advanced use).                                      |



#### Verifying the Configuration

Some info of settings in the script with `./npm-api.sh --info`

#### info
```bash
./npm-api.sh --info

 🔍 Checking system dependencies and directories...
 ✅ All dependencies and directories are properly set up
    ├── System tools: OK
    ├── Directories : OK
    └── Permissions : OK

 🔑 Checking token validity...
 ✅ Token is valid
 📅 Expires: 2026-03-14T10:24:56.267Z

 Script Info:  3.0.0
 Script Variables Information:
 Config      : /home/tools/Project/nginx_proxy/npm-api.conf
 BASE  URL   : http://127.0.0.1:8099/api
 NGINX  IP   : 127.0.0.1
 USER NPM    : user@mail.com
 BACKUP DIR  : /home/tools/Project/nginx_proxy/data/127_0_0_1_8099

 📂 Backup Locations:
  • Backup: /home/tools/Project/nginx_proxy/data/127_0_0_1_8099/backups
  • Token: /home/tools/Project/nginx_proxy/data/127_0_0_1_8099/backups/token/

 📊 NGINX - Proxy Manager - Dashboard 🔧
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ┌─────────────────┬─────────┐
 │  COMPONENT      │ STATUS  │
 ├─────────────────┼─────────┤
 │ 🌐 Proxy Hosts  │ 11      │
 │ ├─ Enabled      │ 9       │
 │ └─ Disabled     │ 2       │
 ├─────────────────┼─────────┤
 │ 🔄 Redirections │ 1       │
 │ 🔌 Stream Hosts │ 0       │
 ├─────────────────┼─────────┤
 │ 🔒 Certificates │ 1       │
 │ ├─ Valid        │ 1       │
 │ └─ Expired      │ 0       │
 ├─────────────────┼─────────┤
 │ 🔒 Access Lists │ 1       │
 │ └─ Clients      │ 0       │
 ├─────────────────┼─────────┤
 │ 👥 Users        │ 3       │
 ├─────────────────┼─────────┤
 │ ⏱️  Uptime       │ 2 days  │
 │ 📦 NPM Version  │ 2.12.3  │
 └─────────────────┴─────────┘

 💡 Use --help to see available commands
    Check --examples for more help examples
```


#### **How to activate SSL ?** 

By following these steps, you can enable SSL for your proxy host for the first time using Let's Encrypt.

#### --host-list
 List all Host in one command and show ´id´ , ´status´ and ´SSL´ status:

      ./npm-api.sh --host-list

      👉 List of proxy hosts (simple)
        ID     Domain                               Status    SSL    Certificate Domain
        14     example.com                           enabled  ✘
        15     example.titi                          enabled  ✘
        1      domain.com                            disable  8      domain.com
        11     titi.eu                               enabled  ✘
        12     toutou                                disable  ✘
        13     toutoux                               enabled  ✘



#### --host-ssl-enable
##### Enable SSL for the Host

  Assuming the host ID is *1*, you would enable SSL for the host as follows:

    ./npm-api.sh --host-ssl-enable 1

##### **Other Exemple command:**

Host proxy info command `--host-show id`

```json
 ./npm-api.sh --host-show 1

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

### Important Notice: Repository History Rewritten

 ⚠️ Action Required for All Contributors (or cloned repo.)

We have performed a **force push (`git push --force`)** on this repository to remove sensitive data from the history. As a result, the commit history has been rewritten, and your local copy may be out of sync.

### 🛠️ What You Need to Do?
To avoid any issues, please follow these steps to update your local repository:

```bash
git fetch --all
git reset --hard origin/main  # Replace 'main' with your branch name if different
```
If you have local changes that you **don't want to lose**, consider making a backup before running these commands.

❓ Why Was This Done?
This action was necessary to **remove sensitive data** from the repository's history and ensure better security.
 
 
## TODO:
- [x] add setting for ADVANCED configuration in npm `location / { ... }`
- [x] Add documentation on certain functions
- [x] ADD: a configuration function for Custom Locations
- [x] Backup all settings from NPM
- [x] Add automatic confirmation with -y parameter
- [X] Clean/minimize output when using -y parameter for better script integration
- [X] Creation of ACCESS list through CLI
- [ ] Restore Function not working properly, need to find FIX


## Credits & Thanks

Special thanks to:
- [@ichbinder](https://github.com/ichbinder) for implementing the `-y` parameter for automatic confirmations

## License

MIT License - see the [LICENSE.md][license] file for details

[contributors]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/graphs/contributors
[erreur32]: https://github.com/Erreur32
[issue]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/issues
[license]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/blob/main/LICENSE.md
[maintenance-shield]: https://img.shields.io/maintenance/yes/2024.svg
[project-stage-shield]: https://img.shields.io/badge/project%20stage-stable-green.svg
[release-shield]: https://img.shields.io/badge/version-v3.0.0-blue.svg
[release]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/releases/tag/v3.0.0
[contributors-shield]: https://img.shields.io/github/contributors/Erreur32/nginx-proxy-manager-Bash-API.svg
[license-shield]: https://img.shields.io/github/license/Erreur32/nginx-proxy-manager-Bash-API.svg
[issues-shield]: https://img.shields.io/github/issues/Erreur32/nginx-proxy-manager-Bash-API.svg
[stars-shield]: https://img.shields.io/github/stars/Erreur32/nginx-proxy-manager-Bash-API.svg
[stars]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/stargazers

