
# Nginx Proxy Manager CLI Script

_by Erreur32_

🛠️  This script allows you to manage Nginx Proxy Manager via the API.

🔑  Genrate TOKEN automaticly !! ;)

It provides functionalities such as creating/deleting proxy hosts, managing users, and displaying configurations and more.

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

![https://github.com/Erreur32/nginx-proxy-manager-API/blob/main/nginx-proxy-script.png](https://github.com/Erreur32/nginx-proxy-manager-API/blob/main/nginx-proxy-script.png)

## TODO:
- Translate all text in english :p !
