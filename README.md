[![Release][release-shield]][release]
![Project Stage][project-stage-shield]
[![License][license-shield]][license]
[![Contributors][contributors-shield]][contributors]
[![Issues][issues-shield]][issue]
[![Stargazers][stars-shield]][stars]


# Nginx Proxy Manager CLI Script V3.0.6 🚀

## Table of Contents

1. [Description](#description)
2. [Reference API](#reference-api)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Settings](#settings)
6. [Usage](#usage)
7. [Options](#options)
8. [Examples](#examples)
   - [Backup](#backup)
   - [Script Info](#script-info)
   - [Host List](#host-list)
   - [SSL Enable](#host-ssl-enable)
   - [Host Update](#host-update)
9. [Important Notice](#important-notice-repository-history-rewritten)
10. [TODO](#todo)

> [!WARNING]
> The  --restore command is disabled  (a fix is in progress).
> 

# V3.0.0 is out 🚀
Check the latest release with major improvements and fixes.

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


<details>
<summary>Required basic dependencies.</summary>
  The script will automatically check if they are installed and will download them if necessary:

- `curl`
- `jq`

</details>

## Installation 
```bash
wget https://raw.githubusercontent.com/Erreur32/nginx-proxy-manager-Bash-API/main/npm-api.sh
chmod +x npm-api.sh
# Run the script.
./npm-api.sh
```


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


## Options
```tcl

 Options available:                       (see --examples for more details)
   -y                                     Automatic yes prompts!
  --info                                  Display Script Variables Information
  --show-default                         Show  Default settings for host creation
  --check-token                           Check Check current token info
  --backup                                💾 Backup All configurations to a different files in $DATA_DIR

 Proxy Host Management:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --host-search domain                    Search Proxy host by domain name
  --host-list                             List All Proxy hosts (to find ID)
  --host-show 🆔                          Show Full details for a specific host by ID

  --host-create domain -i forward_host -p forward_port [options]

     Required:
            domain                        Domain name (required)
       -i   forward-host                  IP address or domain name of the target server (required)
       -p   forward-port                  Port of the target server (required)

     optional: (Check default settings,no argument needed if already set!)
       -f FORWARD_SCHEME                  Scheme for forwarding (http/https, default: http)
       -c CACHING_ENABLED                 Enable caching (true/false, default: false)
       -b BLOCK_EXPLOITS                  Block exploits (true/false, default: true)
       -w ALLOW_WEBSOCKET_UPGRADE         Allow WebSocket upgrade (true/false, default: true)
       -l CUSTOM_LOCATIONS                Custom locations (JSON array of location objects)
       -a ADVANCED_CONFIG                 Advanced configuration (string)

  --host-enable  🆔                       Enable Proxy host by ID
  --host-disable 🆔                       Disable Proxy host by ID
  --host-delete  🆔                       Delete Proxy host by ID
  --host-update  🆔 [field]=value         Update One specific field of an existing proxy host by ID
                                          (eg., --host-update 42 forward_host=foobar.local)

  --host-acl-enable  🆔 access_list_id    Enable ACL for Proxy host by ID with Access List ID
  --host-acl-disable 🆔                   Disable ACL for Proxy host by ID
  --host-ssl-enable  🆔 [cert_id]         Enable SSL for host ID optionally using specific certificate ID
  --host-ssl-disable 🆔                   Disable SSL, HTTP/2, and HSTS for a proxy host

  --cert-list                             List ALL SSL certificates
  --cert-show     domain Or 🆔            List SSL certificates filtered by [domain name] (JSON)
  --cert-delete   domain Or 🆔            Delete Certificate for the given 'domain'
  --cert-download 🆔 [output_dir] [cert_name]  Download certificate as ZIP with fallback support
  --cert-generate domain [email]          Generate Let's Encrypt Certificate or others Providers.
                                           • Standard domains: example.com, sub.example.com
                                           • Wildcard domains: *.example.com (requires DNS challenge)
                                           • DNS Challenge: Required for wildcard certificates
                                             - Format: dns-provider PROVIDER dns-api-key KEY
                                             - Providers: dynu, cloudflare, digitalocean, godaddy, namecheap, route53, ovh, gcloud, ...

  --user-list                             List All Users
  --user-create username password email   Create User with a username, password and email
  --user-delete 🆔                        Delete User by username

  --access-list                           List All available Access Lists (ID and Name)
  --access-list-show 🆔                   Show detailed information for specific access list
  --access-list-create                    Create Access Lists with options:
                                           • --satisfy [any|all]          Set access list satisfaction mode
                                           • --pass-auth [true|false]     Enable/disable password authentication
                                           • --users "user1,user2"        List of users (comma-separated)
                                           • --allow "ip1,ip2"            List of allowed IPs/ranges
                                           • --deny "ip1,ip2"             List of denied IPs/ranges
  --access-list-delete 🆔                 Delete Access List by access ID
  --access-list-update 🆔                 Update Access List by access ID with options:
                                           • --name "new_name"            New name for the access list
                                           • --satisfy [any|all]          Update satisfaction mode
                                           • --pass-auth [true|false]     Update password authentication
                                           • --users "user1,user2"        Update list of users
                                           • --allow "ip1,ip2"            Update allowed IPs/ranges
                                           • --deny "ip1,ip2"             Update denied IPs/ranges

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --examples                             🔖 Examples commands, more explicits
  --help                                     👉 It's me

```

## Examples

```bash
 📦 Backup First !
   ./npm-api.sh --backup

 🌐 Host Creation:
   # Basic host creation
   ./npm-api.sh --host-create domain.com -i IP -p PORT [-b true/false] [-c true/false] [-w true/false] [-h true/false]

   # Create host with SSL certificate and enable SSL (all-in-one)
   ./npm-api.sh --host-create domain.com -i IP -p PORT [options] --cert-generate --host-ssl-enable -y

   # Create host with SSL certificate and enable SSL (with specific domain)
   ./npm-api.sh --host-create domain.com -i IP -p PORT [options] --cert-generate domain.com --host-ssl-enable -y

   # Create host with custom options
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 \
     -f https \         # Forward scheme
     -b true \          # Block exploits
     -c true \          # Enable caching
     -w true \          # Enable websocket
     -h true \          # Enable HTTP/2
     -y                 # Auto confirm

 🤖 Automatic operations (no prompts):
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -y
   ./npm-api.sh --host-delete 42 -y
   ./npm-api.sh --host-ssl-enable 10 -y   

 🔍 Information and Status:
   ./npm-api.sh --info                      # Show configuration and dashboard
   ./npm-api.sh --show-default              # Show default settings
   ./npm-api.sh --check-token               # Verify token validity
   ./npm-api.sh --host-search domain.com    # Search for a specific domain
   ./npm-api.sh --host-list                 # List all hosts
   ./npm-api.sh --host-list-full            # List hosts with details
   ./npm-api.sh --host-show 42              # Show specific host details

 🔒 SSL Management:
   # List all certificates
   ./npm-api.sh --list-ssl-cert
   # Download certificate as ZIP
   ./npm-api.sh --cert-download 123
   ./npm-api.sh --cert-download 123 ./certs mydomain
   # Generate standard Let's Encrypt certificate
   ./npm-api.sh --cert-generate domain.com [email] [dns_provider] [dns_credentials] [-y]
   # Generate wildcard certificate with Cloudflare
   ./npm-api.sh --cert-generate "*.example.com" \
     --cert-email admin@example.com \
     --dns-provider cloudflare \
     --dns-credentials '{"dns_cloudflare_email":"your@email.com","dns_cloudflare_api_key":"your_api_key"}'

   # Delete certificate
   ./npm-api.sh --delete-cert domain.com        
   # Enable SSL for host
   ./npm-api.sh --host-ssl-enable HOST_ID            
   # Generate certificate and enable SSL for existing host
   ./npm-api.sh --cert-generate domain.com --host-ssl-enable -y

 🌟 Complete Examples with Wildcard Certificates:
   # Create host with wildcard certificate using Cloudflare DNS
   ./npm-api.sh --host-create "*.example.com" -i 192.168.1.10 -p 8080 \
     --cert-generate "*.example.com" \
     --cert-email admin@example.com \
     --dns-provider cloudflare \
     --dns-credentials '{"dns_cloudflare_email":"your@email.com","dns_cloudflare_api_key":"your_api_key"}' \
     --host-ssl-enable -y

   # Same with DigitalOcean DNS
   ./npm-api.sh --host-create "*.example.com" -i 192.168.1.10 -p 8080 \
     --cert-generate "*.example.com" \
     --cert-email admin@example.com \
     --dns-provider digitalocean \
     --dns-credentials '{"dns_digitalocean_token":"your_token"}' \
     --host-ssl-enable -y

   # Same with GoDaddy DNS
   ./npm-api.sh --host-create "*.example.com" -i 192.168.1.10 -p 8080 \
     --cert-generate "*.example.com" \
     --cert-email admin@example.com \
     --dns-provider godaddy \
     --dns-credentials '{"dns_godaddy_key":"your_key","dns_godaddy_secret":"your_secret"}' \
     --host-ssl-enable -y

 🛡️ Access Control Lists:
   # List all access lists
   ./npm-api.sh --list-access                   
   # Show detailed information for specific access list
   ./npm-api.sh --access-list-show 123  
   # Create a basic access list
   ./npm-api.sh --access-list-create "office" --satisfy any
   # Create access list with authentication
   ./npm-api.sh --access-list-create "secure_area" --satisfy all --pass-auth true
   # Create access list with users
   ./npm-api.sh --access-list-create "dev_team" --users "john,jane,bob" --pass-auth true
   # Create access list with IP rules
   ./npm-api.sh --access-list-create "internal" --allow "192.168.1.0/24" --deny "192.168.1.100"
   # Create comprehensive access list
   ./npm-api.sh --access-list-create "full_config" \
     --satisfy all \
     --pass-auth true \
     --users "admin1,admin2" \
     --allow "10.0.0.0/8,172.16.0.0/12" \
     --deny "10.0.0.50,172.16.1.100"
   
   # Update an existing access list
   ./npm-api.sh --access-list-update 42        
   # Delete an access list (with confirmation)
   ./npm-api.sh --access-list-delete 42        
   # Delete an access list (skip confirmation)
   ./npm-api.sh --access-list-delete 42 -y     
   # Enable ACL for a host
   ./npm-api.sh --host-acl-enable 42,5         # Enable ACL ID 5 for host 42
   # Disable ACL for a host
   ./npm-api.sh --host-acl-disable 42          # Disable ACL for host 42

 👥 User Management:
   ./npm-api.sh --create-user newuser password123 user@example.com
   ./npm-api.sh --delete-user 'username'
   ./npm-api.sh --list-users

 🔧 Advanced Examples:
   # Custom Nginx configuration
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 \
     -a 'proxy_set_header X-Real-IP $remote_addr;'

 🛡️ Custom locations:
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 \
     -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'

   # Update specific fields
   ./npm-api.sh --update-host 42 forward_scheme=https
   ./npm-api.sh --update-host 42 forward_port=8443

 
 🔖 Full options:
   ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 \
    -f https -c true -b true -w true \
    -a 'proxy_set_header X-Real-IP $remote_addr;' \
    -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'
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

 🛠️ What You Need to Do?
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

- 🙏 **Special thanks to [zafar-2020](https://github.com/zafar-2020)** for his valuable help with testing and reporting issues during the development of version 3.0.0!

## License

MIT License - see the [LICENSE.md][license] file for details

[contributors]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/graphs/contributors
[erreur32]: https://github.com/Erreur32
[issue]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/issues
[license]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/blob/main/LICENSE.md
[maintenance-shield]: https://img.shields.io/maintenance/yes/2024.svg
[project-stage-shield]: https://img.shields.io/badge/project%20stage-stable-green.svg
[release-shield]: https://img.shields.io/badge/version-v3.0.2-blue.svg
[release]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/releases/tag/v3.0.2
[contributors-shield]: https://img.shields.io/github/contributors/Erreur32/nginx-proxy-manager-Bash-API.svg
[license-shield]: https://img.shields.io/github/license/Erreur32/nginx-proxy-manager-Bash-API.svg
[issues-shield]: https://img.shields.io/github/issues/Erreur32/nginx-proxy-manager-Bash-API.svg
[stars-shield]: https://img.shields.io/github/stars/Erreur32/nginx-proxy-manager-Bash-API.svg
[stars]: https://github.com/Erreur32/nginx-proxy-manager-Bash-API/stargazers

---

## 🙏 Acknowledgments

Special thanks to [@popy2k14](https://github.com/popy2k14) for identifying and reporting the certificate download issue in [PR #20](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/pull/20). Their contribution helped improve the script's compatibility with newer NPM installations by highlighting the API changes and the need for fallback support.

