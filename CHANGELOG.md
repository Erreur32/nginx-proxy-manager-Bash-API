# Changelog

All notable changes to the npm-api.sh script will be documented in this file.

## [3.1.0] - 2025-01-27

### 🐛 Bug Fixes

- **`host_list` fails when proxy hosts have multiple domain names** ([PR #28](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/pull/28))
  - **The problem**: When a proxy host had multiple domain names (e.g., "domain1.com, domain2.com"), the `host_list()` function would fail to parse the output correctly because it used space-separated values with `read`, which broke when domain names contained spaces or commas.
  - **Why it broke**: The original implementation used `join(", ")` to combine multiple domain names, then tried to parse with `read -r id domain enabled certificate_id`, which failed when the domain string contained spaces or multiple domains.
  - **What we did**: 
    - Changed the delimiter from spaces to tabulation (`\t`) for safe parsing
    - Updated the `jq` command to use tab-separated values: `"\(.id)\t\(.domain_names | join(", "))\t..."`
    - Modified the `read` command to use `IFS=$'\t'` to properly handle tab-separated input
  - **Technical details**:
    - Tab delimiter (`\t`) is safer than spaces because domain names can contain spaces
    - Using `IFS=$'\t'` ensures proper field separation
    - This fix ensures that proxy hosts with multiple domain names are displayed correctly
  - **Examples**:
    ```bash
    # Now works correctly with multiple domains! 🎉
    ./npm-api.sh --host-list
    # Displays: "domain1.com, domain2.com" correctly in the DOMAIN column
    ```

### ✨ New Features

- **Added TARGET column to `host_list` output** ([PR #29](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/pull/29))
  - **Feature**: The `host_list` command now displays a TARGET column showing where each proxy host forwards traffic
  - **What it shows**: The TARGET column displays the forwarding configuration in the format `scheme://host:port` (e.g., `http://192.168.1.10:8080`)
  - **Why it's useful**: This allows users to quickly see the destination of each proxy host without needing to run `--host-show` for each host
  - **Technical details**:
    - Extracts `forward_scheme`, `forward_host`, and `forward_port` from the API response
    - Formats the target as `${forward_scheme:-http}://${forward_host}:${forward_port}`
    - Displays "N/A" if forwarding information is not available
    - The column is positioned between SSL and CERT DOMAIN columns for better readability
  - **Examples**:
    ```bash
    # Now shows TARGET column with forwarding information
    ./npm-api.sh --host-list
    # Output includes: ID | DOMAIN | STATUS | SSL | TARGET | CERT DOMAIN
    # TARGET shows: http://192.168.1.10:8080
    ```

### 🔧 Technical Improvements

- **Improved `host_list` function robustness**: Combined the fixes from PR #28 and PR #29 to create a more robust and informative listing function
- **Better column formatting**: Adjusted column widths to accommodate the new TARGET column while maintaining readability

## [3.0.7] - 2025-01-27

### 🐛 Bug Fixes

- **IP whitelist not showing in `--access-list-show` command** ([Issue #26](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/issues/26))
  - **The problem**: When you ran `./npm-api.sh --access-list-show 5`, it showed "No IPs whitelisted" even though IPs were actually configured. Classic! 😅
  - **Why it broke**: NPM's API changed (thanks evolving schemas...) and now you need to pass the `expand=items,clients` parameter to get all the details. Without it, the API just returns basic info without items and clients.
  - **What we did**: 
    - Added `?expand=items%2Cclients` to API calls in `access_list_show()` and `access_list_update()`
    - Improved the backup function to fetch each access list individually with the expand parameter (so we get a complete backup with all details)
  - **Technical details** (for the curious):
    - URL encoding: `items%2Cclients` = `items,clients` URL-encoded
    - Modified GET requests in `access_list_show()` and `access_list_update()`
    - Backup now fetches each access list one by one with expand to make sure we get everything
  - **Examples**:
    ```bash
    # Now it works correctly! 🎉
    ./npm-api.sh --access-list-show 5
    
    # Update also retrieves complete data
    ./npm-api.sh --access-list-update 5 --name "new_name"
    ```

- **"Unbound variable" error when you forget the ID** 
  - **The problem**: If you ran `./npm-api.sh --access-list-show` without an ID, it crashed with a nice "unbound variable" error (thanks `set -eu` doing its job a bit too well 😄)
  - **Why it broke**: We were directly assigning `$1` to a variable without checking if it existed. With `set -eu`, bash doesn't like that at all!
  - **What we did**: 
    - Added a check before assigning the variable (we check if `$# -eq 0` or if `$1` starts with `-`)
    - Added a friendly error message with examples and tips
    - Aligned with other commands (`--access-list-update`, `--access-list-delete`) for consistency
  - **Technical details**:
    - Added check: `if [ $# -eq 0 ] || [[ "$1" == -* ]]` before assignment
    - Exit with code 1 to prevent the script from continuing
  - **Examples**:
    ```bash
    # Now it shows a helpful message instead of crashing
    ./npm-api.sh --access-list-show
    
    # Correct usage
    ./npm-api.sh --access-list-show 5
    ```

### 🔧 Technical Improvements

- **API schema alignment**: Updated all access list API calls to be compatible with NPM's new schema requirements
- **Enhanced backup**: Backup now fetches each access list individually with expand, so we're sure to have all details (items and clients) in the backup
- **Better error handling**: Added validations and clearer error messages when arguments are missing

### 📝 Documentation

- More descriptive and helpful error messages
- Added examples in error messages to guide users
- Improved consistency in error handling across all access-list commands

## [3.0.6] - 2025-01-20

### 🆕 New Features

- **Added certificate download functionality with fallback support** ([PR #20](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/pull/20))
  - **Issue**: Certificate download failed on newer NPM installations due to API changes
  - **Solution**: 
    - Added `--cert-download` command to download certificates as ZIP files
    - Implemented automatic fallback from new API (JSON) to legacy API (ZIP)
    - Added support for wildcard file matching (cert*.pem, privkey*.pem, etc.)
    - Created standardized output format with .crt, .key, .chain.crt files
  - **Technical Details**:
    - New API: Uses `/nginx/certificates/{id}/certificates` endpoint with JSON response
    - Legacy API: Uses `/nginx/certificates/{id}/download` endpoint with ZIP response
    - Automatic detection of certificate files with wildcards (supports cert8.pem, cert9.pem, etc.)
    - Creates both individual files and ZIP archive for easy distribution
    - Proper error handling and cleanup of temporary files
  - **Usage Examples**:
    ```bash
    # Download certificate with default settings
    ./npm-api.sh --cert-download 123
    
    # Download to specific directory
    ./npm-api.sh --cert-download 123 ./certs
    
    # Download with custom name
    ./npm-api.sh --cert-download 123 ./certs mydomain
    ```
  - **Output Files**:
    - `{cert_name}.crt` - Certificate file
    - `{cert_name}.key` - Private key file
    - `{cert_name}.chain.crt` - Intermediate certificate (if available)
    - `{cert_name}.fullchain.crt` - Full chain certificate (if available)
    - `{cert_name}_metadata.json` - Certificate metadata
    - `{cert_name}_certificate.zip` - ZIP archive containing all files

## [3.0.5] - 2025-01-20

### 🐛 Bug Fixes

- **Fixed `-l` and `-a` options being ignored in host creation** ([Issue #22](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/issues/22))
  - **Issue**: The commands `./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr;'` and `./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'` were showing "Unknown option ignored" warnings
  - **Root Cause**: The options `-l` (custom_locations) and `-a` (advanced_config) were documented in help text but not implemented in the argument parsing for `--host-create`
  - **Solution**: 
    - Added support for `-l|--custom-locations` option in argument parsing
    - Added support for `-a|--advanced-config` option in argument parsing
    - Updated help messages to include these options in the optional parameters list
    - Added proper error handling and validation for both options
  - **Technical Details**:
    - Added `-l|--custom-locations` case in argument parsing with JSON validation
    - Added `-a|--advanced-config` case in argument parsing with string validation
    - Updated all help message sections to include the new options
    - Added example usage in error messages for better user guidance
  - **Usage Examples**:
    ```bash
    # Create host with custom locations
    ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]'
    
    # Create host with advanced configuration
    ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -a 'proxy_set_header X-Real-IP $remote_addr;'
    
    # Create host with both custom locations and advanced config
    ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080 -l '[{"path":"/api","forward_host":"192.168.1.11","forward_port":8081}]' -a 'proxy_set_header X-Real-IP $remote_addr;'
    ```

- **Fixed `--websocket` and `--cache` options not being respected in host creation** ([Issue #23](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/issues/23))
  - **Issue**: The commands `./npm-api.sh --host-create example.com -i 192.168.1.100 -p 8081 --cache true --websocket true` were not enabling caching and websocket support in NPM
  - **Root Cause**: 
    - Variable naming mismatch in argument parsing (`CACHE_ENABLED` vs `CACHING_ENABLED`, `WEBSOCKET_SUPPORT` vs `ALLOW_WEBSOCKET_UPGRADE`)
    - Incorrect default value for `ALLOW_WEBSOCKET_UPGRADE` (was `1` instead of `false`)
  - **Solution**: 
    - Fixed variable names in argument parsing to match the variables used in the JSON payload
    - Corrected default value for `ALLOW_WEBSOCKET_UPGRADE` to `false`
    - Updated function call to use correct variable names
  - **Technical Details**:
    - Changed `cache) CACHE_ENABLED="$2"` to `cache) CACHING_ENABLED="$2"`
    - Changed `websocket) WEBSOCKET_SUPPORT="$2"` to `websocket) ALLOW_WEBSOCKET_UPGRADE="$2"`
    - Updated function call parameters to use correct variable names
    - Fixed default value: `ALLOW_WEBSOCKET_UPGRADE=1` → `ALLOW_WEBSOCKET_UPGRADE=false`
  - **Usage Examples**:
    ```bash
    # Create host with caching enabled
    ./npm-api.sh --host-create example.com -i 192.168.1.100 -p 8081 --cache true
    
    # Create host with websocket support enabled
    ./npm-api.sh --host-create example.com -i 192.168.1.100 -p 8081 --websocket true
    
    # Create host with both caching and websocket support
    ./npm-api.sh --host-create example.com -i 192.168.1.100 -p 8081 --cache true --websocket true
    ```

- **Fixed `--allow` and `--deny` options not working in access-list commands** ([Issue #24](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/issues/24))
  - **Issue**: The commands `./npm-api.sh --access-list-create "test" --allow "172.0.0.0/8"` and `./npm-api.sh --access-list-update 6 --allow "172.0.0.0/8"` were failing with "Unknown option --allow" error
  - **Root Cause**: The `--allow` and `--deny` options were documented in help text but not implemented in the actual functions
  - **Solution**: 
    - Added full support for `--allow` and `--deny` options in `access_list_create()` function
    - Added full support for `--allow`, `--deny`, and `--users` options in `access_list_update()` function
    - Implemented comma-separated value parsing for multiple IPs/users
    - Added proper error handling and validation for all new options
  - **Technical Details**:
    - Added `--allow` option processing with comma-separated IP support
    - Added `--deny` option processing with comma-separated IP support  
    - Added `--users` option processing with password prompts for each user
    - Updated help messages to include all available options
    - Maintained backward compatibility with existing `--access allow|deny <ip>` syntax
  - **Usage Examples**:
    ```bash
    # Create access list with allow rules
    ./npm-api.sh --access-list-create "office" --allow "192.168.1.0/24,10.0.0.0/8"
    
    # Create access list with deny rules
    ./npm-api.sh --access-list-create "secure" --deny "192.168.1.100,10.0.0.50"
    
    # Update access list with new allow rules
    ./npm-api.sh --access-list-update 6 --allow "172.0.0.0/8"
    
    # Create access list with users and IP rules
    ./npm-api.sh --access-list-create "full_config" --users "admin1,admin2" --allow "10.0.0.0/8" --deny "10.0.0.50"
    ```

- **Fixed `--access-list-update` command not working with arguments**
  - **Issue**: The command `./npm-api.sh --access-list-update 123 --name "new_name"` was failing with "Unknown option: 123" error
  - **Root Cause**: The argument parsing for `--access-list-update` was not properly capturing the access list ID and subsequent arguments
  - **Solution**: 
    - Fixed argument parsing to properly capture the access list ID
    - Implemented proper argument storage and passing to the function
    - Corrected JSON payload structure to match API schema expectations
  - **Technical Details**:
    - Changed from interactive `read` prompts to command-line argument processing
    - Updated payload structure to use `satisfy_any` (boolean) instead of `satisfy` (string)
    - Removed unsupported fields (`auth_type`, `whitelist`) from API payload
    - Added support for `--name`, `--satisfy`, and `--pass-auth` options
  - **Usage Examples**:
    ```bash
    # Update access list name
    ./npm-api.sh --access-list-update 4 --name "new_name"
    
    # Update satisfaction mode
    ./npm-api.sh --access-list-update 4 --satisfy any
    
    # Update multiple properties
    ./npm-api.sh --access-list-update 4 --name "test_script" --satisfy any
    ```

### 🔧 Technical Improvements

- **Enhanced Argument Processing**: Improved command-line argument parsing for access list operations
- **API Schema Compliance**: Updated JSON payload structure to match official NPM API schema
- **Error Handling**: Better error messages and validation for access list operations
- **Code Consistency**: Aligned `access_list_update` function structure with `access_list_create`

### 📝 Documentation Updates

- Updated help messages and examples for `--access-list-update` command
- Added proper usage examples in error messages
- Improved command-line argument validation feedback

## [3.0.0] - 2025-03-24

### 🔄 Breaking Changes

- **Host Creation Command Simplified**
  ```diff
  - OLD: ./npm-api.sh -d example.com -i 192.168.1.10 -p 8080
  + NEW: ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080
  ```
  The `-d` option has been removed in favor of a more intuitive positional argument after `--host-create`

### New Commands (2.8.0)

- `--access-list`: List all available access lists
- `--access-list-show <id>`: Show detailed information for a specific access list
- `--access-list-create`: Create a new access list
- `--access-list-update`: Update an existing access list
- `--access-list-delete`: Delete an access list
- `--list-cert`: List certificates filtered by domain name
- `--list-cert-all`: List all SSL certificates

### New Long Options Format

- Certificate Generation:
  ```diff
  - OLD: ./npm-api.sh --cert-generate example.com admin@example.com
  + NEW: ./npm-api.sh --cert-generate example.com --cert-email admin@example.com
  ```

- Wildcard Certificate with DNS Challenge:
  ```diff
  - OLD: ./npm-api.sh --cert-generate "*.example.com" admin@example.com --dns-provider cloudflare --dns-credentials '{"dns_cloudflare_email":"your@email.com","dns_cloudflare_api_key":"your_api_key"}'
  + NEW: ./npm-api.sh --cert-generate "*.example.com" \
  +      --cert-email admin@example.com \
  +      --dns-provider cloudflare \
  +      --dns-credentials '{"dns_cloudflare_email":"your@email.com","dns_cloudflare_api_key":"your_api_key"}'
  ```

### Renamed Commands

- `--list-ssl-cert` → `--list-cert`
- `--create-user` → `--user-create`
- `--delete-user` → `--user-delete`
- `--list-users` → `--user-list`
- `--list-access` → `--access-list`
- `--update-host` → `--host-update`

### Enhanced Commands

- `--generate-cert`: Added support for wildcard certificates and DNS challenges
  - Add Wildcard support.
  - Support for multiple DNS providers (Dynu, Cloudflare, DigitalOcean, etc.)

### Syntax Changes

- Host-related commands now consistently use the `--host-` prefix
- User-related commands now consistently use the `--user-` prefix
- Certificate-related commands now consistently use the `--cert-` prefix


### ✨ New Features

- **Smart certificate management in SSL configuration**:
  - Automatic detection of existing certificates for domains
  - Automatic selection of single existing certificates
  - Selection system for multiple certificates:
    * Auto-selects most recent with `-y` flag
    * Interactive selection without `-y` flag
  - Integration with certificate generation workflow
- Enhanced SSL status display with detailed configuration state
- Improved error handling and debug information
- Configurable SSL parameters:
  * SSL Forced
  * HTTP/2 Support
  * HSTS
  * HSTS Subdomains

- **Enhanced Host Creation**
  - Simplified command syntax with positional domain argument
  - Improved parameter validation
  - Better error messages with clear examples
  - Default values for optional parameters

- **Improved Error Handling**
  - Clear error messages for missing parameters
  - Validation of domain name format
  - Parameter type checking (e.g., port numbers, boolean values)
  - Helpful usage examples in error messages

- Added comprehensive dashboard with `display_dashboard()` showing:
  - Proxy hosts status (enabled/disabled)
  - SSL certificates (valid/expired)
  - Access lists and clients
  - System statistics

- Enhanced SSL Certificate Management:
  - Improved wildcard certificate support
  - Enhanced domain validation
  - DNS challenge management for wildcard certificates
  - Support for multiple DNS providers (Cloudflare, DigitalOcean, etc.)

- **Enhanced Access List Management**:
  - Detailed view for individual access lists
  - Colored output for better readability
  - Display of users and IP counts
  - Clear visualization of allow/deny rules
  - Authentication status indicators
  - Satisfaction mode display (Any/All)
  - Proxy host count integration
  - Improved formatting and layout
  - Better error handling for null values
  - Comprehensive legend for status indicators

### 🛠️ Code Optimizations

- Removed redundant parameter validations
- Streamlined host creation logic
- Unified error message format
- Better code organization
- Enhanced Token Management:
  - Automatic validation
  - Smart renewal
  - Secure storage

- Improved Host Management Commands:
  - Enhanced display with `host_show()`
  - Better error handling
  - Advanced configuration support

- Improved access list display with:
  - Dynamic column sizing
  - Proper null value handling
  - Efficient data processing
  - Better color management
  - Enhanced table formatting

### 📚 Documentation

- Updated access list command documentation:
  - Added examples for detailed view
  - Improved command descriptions
  - Better parameter explanations

### 🔐 Security

- Enhanced input validation
- Better parameter sanitization
- Improved error handling for invalid inputs

### 🛠️ Fixes and Optimizations

- Fixed SSL certificate management bugs
- Improved user input validation
- Optimized API requests
- Enhanced HTTP error handling

### 🙏 Remerciements

Thanks to [zafar-2020](https://github.com/zafar-2020) for the testing and helpful issue reports during the development of this release!


## [2.7.0] - 2025-03-08

### Added

- DNS Challenge Support
  - Added support for multiple DNS providers (Dynu, Cloudflare, DigitalOcean, etc.)
  - Implemented automatic DNS challenge detection for wildcard certificates
  - Added validation for DNS provider and API key parameters

- Wildcard Certificate Support
  - Added ability to generate wildcard certificates (*.domain.com)
  - Automatic detection of wildcard certificate requirements
  - Enforced DNS challenge requirement for wildcard certificates

- Certificate Management Enhancements
  - Added ability to specify existing certificate by ID when enabling SSL
  - Implemented automatic certificate matching for domains
  - Added support for using wildcard certificates with host SSL configuration
  - Enhanced certificate search to match wildcard patterns

### Changed

- Command Structure
  - Modified --generate-cert command to accept DNS parameters after email:
    ```bash
    --generate-cert domain [email] [dns-provider provider dns-api-key key]
    ```
  - Updated --host-ssl-enable to accept optional certificate ID:
    ```bash
    --host-ssl-enable ID [cert_id]
    ```

- Help Documentation
  - Updated help section with detailed DNS challenge information
  - Added examples for wildcard certificates and different DNS providers
  - Improved documentation for SSL certificate management
  - Added clarification for supported DNS providers

### Improved

- Error Handling
  - Added validation for DNS challenge parameters
  - Enhanced error messages for certificate operations
  - Improved feedback for wildcard certificate requirements

- User Experience
  - Added automatic certificate selection when enabling SSL
  - Improved certificate matching logic
  - Enhanced feedback during certificate operations
  - Added clear examples for all new features

## [1.0.0] - Initial Release

- Basic SSL certificate management
- Proxy host configuration
- User list
