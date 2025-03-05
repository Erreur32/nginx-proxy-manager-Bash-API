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
2. [Reference API](#reference)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Settings](#settings)
6. [Usage](#usage)
7. [Options](#options)
8. [Examples](#examples)
   - [Info script](#info)
   - [List HOST](#list)
   - [Enable SSL](#ssl)
   - [update specific fields of an existing proxy host](#update)  
12. [Screens](#screens)
13. [TODO](#todo)

> [!WARNING]
> The  --restore command is disabled  (a fix is in progress).
> 
> V2.6.0 introduced some issues. A fix has been tested and pushed,  but user feedback is required to ensure everything works as expected with V2.7.0.



## Description

🛠️ This BASH script enables the management of ![Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager?utm_source=nginx-proxy-manager) through its **API**.

🔑 **Automatically generates** and **manages tokens**, ensuring their validity, so you don't have to worry about token expiration.

⚙️ Provides functionalities such as creating and deleting proxy hosts, managing users, displaying configurations, creating **BACKUPS**, and more.

 

### French description:
Ce script permet de gérer Nginx Proxy Manager via l'API. Il fournit des fonctionnalités telles que la création de hosts proxy, la gestion des utilisateurs, et l'affichage des configurations avec creation de BACKUP !
La fonction RESTORE n'est pas encore terminée.

## Reference
![https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema)

## Prerequisites

The excellent NPM (![Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager?utm_source=nginx-proxy-manager))

Required basic dependencies. 
  > The script will automatically check if they are installed and will download them if necessary:

- `curl`
- `jq`


## Installation 
```bash
wget https://raw.githubusercontent.com/Erreur32/nginx-proxy-manager-Bash-API/main/nginx_proxy_manager_cli.sh
chmod +x nginx_proxy_manager_cli.sh
# Create a config file nginx_proxy_manager_cli.conf in same directory (to keep your config safe) check below.
echo -e "## Nginx proxy IP address (your Nginx IP)\nNGINX_IP=\"127.0.0.1\"\nAPI_USER=\"existingUser@mail.com\"\nAPI_PASS=\"password\"\nBASE_DIR=\"$(pwd)\"" > nginx_proxy_manager_cli.conf
./nginx_proxy_manager_cli.sh --info
```


> [!NOTE]
> With the new `V2.0.0`, some command arguments have been changed to be simpler, and need to set `BASE_DIR` variable to store `Tokens` and `Backups`.


## Settings
> [!IMPORTANT]
> (Optional) You can create a configuration file named `nginx_proxy_manager_cli.conf` with these 4 required variables.

To ensure the script is functional, edit these 4 variables (mandatory).

```bash
# nginx_proxy_manager_cli.conf

## Nginx proxy IP address (your Nginx IP)
NGINX_IP="127.0.0.1"
## Existing user (user and password) on NPM
API_USER="admin@example.com"
API_PASS="changeme"
# Path to store .txt files and Backups
BASE_DIR="/path/nginx_proxy_script/data"

```

## Usage
```bash
./nginx_proxy_manager_cli.sh [OPTIONS]
./nginx_proxy_manager_cli.sh  --help
./nginx_proxy_manager_cli.sh  --show-default 
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

🌐 Proxy Hosts:
   • Total:    42
   • Enabled:  38
   • Disabled: 4

🔄 Redirections:
   • Total: 5

🔌 Stream Hosts:
   • Total: 3

🔒 SSL Certificates:
   • Total:   15
   • Valid:   12
   • Expired: 3

👥 Users:
   • Total: 4

🆙 Server Status:
   • Uptime: 15 days
   • Version: 2.4.0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💡 Use --help to see available commands
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
   ./nginx_proxy_manager_cli.sh --backup

 🌐 Host Creation:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 (check default values below)
   ./nginx_proxy_manager_cli.sh --info
   ./nginx_proxy_manager_cli.sh --show-default
   ./nginx_proxy_manager_cli.sh --create-user newuser password123 user@example.com
   ./nginx_proxy_manager_cli.sh --delete-user 'username'
   ./nginx_proxy_manager_cli.sh --host-list
   ./nginx_proxy_manager_cli.sh --host-ssl-enable 10

 🤖 Automatic operations (no prompts):
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -y
   ./nginx_proxy_manager_cli.sh --host-delete 42 -y
   ./nginx_proxy_manager_cli.sh --host-ssl-enable 10 -y   

 🔍 Information and Status:
   ./nginx_proxy_manager_cli.sh --info                   # Show script configuration and status
   ./nginx_proxy_manager_cli.sh --check-token            # Verify token validity
   ./nginx_proxy_manager_cli.sh --host-search domain.com # Search for a specific domain

 🔄 Host Management:
   # Enable/Disable hosts
   ./nginx_proxy_manager_cli.sh --host-enable 42
   ./nginx_proxy_manager_cli.sh --host-disable 42

 🛡️ Access Control Lists:
   ./nginx_proxy_manager_cli.sh --list-access                   # List all access lists
   ./nginx_proxy_manager_cli.sh --host-acl-enable 42,5          # Enable ACL ID 5 for host 42
   ./nginx_proxy_manager_cli.sh --host-acl-disable 42           # Disable ACL for host 42

 🔒 SSL Management:
   ./nginx_proxy_manager_cli.sh --list-ssl-cert                 # List all SSL certificates
   ./nginx_proxy_manager_cli.sh --delete-cert domain.com        # Delete certificate for domain

 🔄 Update Specific Fields:
   # Update individual fields without recreating the entire host
   ./nginx_proxy_manager_cli.sh --update-host 42 forward_scheme=https
   ./nginx_proxy_manager_cli.sh --update-host 42 forward_port=8443
   ./nginx_proxy_manager_cli.sh --update-host 42 block_exploits=true
   ./nginx_proxy_manager_cli.sh --update-host 42 allow_websocket_upgrade=true

 🔧 Advanced Example:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'

 🛡️ Custom Certificate:
   ./nginx_proxy_manager_cli.sh --generate-cert example.com user@example.com 
   # Note: This will generate a Let's Encrypt certificate only

 🛡️  Custom locations:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'

🔖 Full options:
   ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080 -f https -c true -b true -w true -a 'proxy_set_header X-Real-IP $remote_addr;' -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'
```

### --backup

```bash
./nginx_proxy_manager_cli.sh --backup
```


### Schema of the backup directory:
```
📁 data/                                         # Root directory
├── 📁 backups/                                  # Backup directories
│   └── 📁 [IP]_[PORT]/                          # NPM Instance (IP:PORT)
│       ├── 📁 .access_lists/                    # Access Lists configurations
│       ├── 📁 .Proxy_Hosts/                     # Host configurations
│       │   ├── 📁 [DOMAIN]/                     # Directory for each domain
│       │   │   ├── 📁 logs/                     # Log directory
│       │   │   ├── 📁 ssl/                      # SSL directory
│       │   │   │   ├── 📄 certificate_meta.json # Certificate metadata
│       │   │   │   ├── 📄 certificate.pem       # Certificate
│       │   │   │   ├── 📄 chain.pem             # Chain of certificates
│       │   │   │   └── 📄 private.key           # Private key
│       │   │   ├── 📄 nginx.conf                # Nginx configuration
│       │   │   └── 📄 proxy_config.json         # Proxy configuration
│       │   ├── 📄 all_hosts_[DATE].json         # List of all hosts
│       │   └── 📄 all_hosts_latest.json         # Symlink to latest backup
│       ├── 📁 .settings/                        # NPM settings
│       ├── 📁 .ssl/                             # SSL certificates
│       ├── 📁 .user/                            # User configurations
│       ├── 📄 full_config_[DATE].json           # Full backup
│       └── 🔗 full_config_latest.json           # Symlink to latest backup
│
└── 📁 token/                                    # Token directory
    ├── 📄 token_[IP]_[PORT].txt                 # Authentication token
    └── 📄 expiry_[IP]_[PORT].txt                # Token expiry date
```

#### --update-host      
##### update specific fields of an existing proxy host

The `--update-host` command allows you to **update specific fields** of an existing proxy host in Nginx Proxy Manager **without recreating it**.  

Simply specify the **proxy host ID** and the **field you want to update**, like this:

```bash
./nginx_proxy_manager_cli.sh --update-host 42 forward_host=new.backend.local
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

Some info of settings in the script with `./nginx_proxy_manager_cli_.sh --info`

#### info
```bash
./nginx_proxy_manager_cli_.sh --info

Script Info:  2.3.5

Script Variables Information:
  BASE_URL    http://127.0.0.1:81/api
  NGINX_IP    127.0.0.1
  API_USER    admin@example.com
  BASE_DIR    /path/to/nginx_proxy
  BACKUP_DIR  /path/to/nginx_proxy/backups
  BACKUP HOST 40
  Token NPM   /path/to/nginx_proxy/token/token_127.0.0.1.txt

```


#### **How to activate SSL ?** 

By following these steps, you can enable SSL for your proxy host for the first time using Let's Encrypt.

#### --host-list
 List all Host in one command and show ´id´ , ´status´ and ´SSL´ status:

    ./nginx_proxy_manager_cli.sh --host-list
    
      👉 List of proxy hosts (simple)
      ID     Domain                               Status    SSL
      1      toto.fun                              enabled  ✘
      2      titi.fun                              disable  ✅
      3      tutu.fun                              enabled  ✅


#### --host-ssl-enable
##### Enable SSL for the Host

  Assuming the host ID is *1*, you would enable SSL for the host as follows:

    ./nginx_proxy_manager_cli.sh --host-ssl-enable 1

 SSl is enable successfully, check again with --host-list

     ./nginx_proxy_manager_cli.sh --host-list
    
      👉 List of proxy hosts (simple)
      ID     Domain                               Status    SSL
      1      toto.fun                              enabled  ✅
      2      titi.fun                              disable  ✅
      3      tutu.fun                              enabled  ✅


##### **Other Exemple command:**

Host proxy info command `--host-show id`


```
 ./nginx_proxy_manager_cli_.sh --host-show 1

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
![screen-nginx-proxy-default](https://github.com/user-attachments/assets/5a87bb64-c8aa-4b67-b118-9fa10423d396)

 
## TODO:
- [x] add setting for ADVANCED configuration in npm `location / { ... }`
- [x] Add documentation on certain functions
- [x] ADD: a configuration function for Custom Locations
- [x] Backup all settings from NPM
- [x] Add automatic confirmation with -y parameter
- [ ] Clean/minimize output when using -y parameter for better script integration
- [ ] Creation of ACCESS list through CLI
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
[release-shield]: https://img.shields.io/badge/version-v0.1.48-blue.svg
[release]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/releases/tag/v2.7.0
[contributors-shield]: https://img.shields.io/github/contributors/Erreur32/nginx-proxy-manager-Bash-API.svg
[license-shield]: https://img.shields.io/github/license/Erreur32/nginx-proxy-manager-Bash-API.svg
[issues-shield]: https://img.shields.io/github/issues/Erreur32/nginx-proxy-manager-Bash-API.svg
[stars-shield]: https://img.shields.io/github/stars/Erreur32/nginx-proxy-manager-Bash-API.svg
[stars]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/stargazers

