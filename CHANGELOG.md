# Changelog

All notable changes to the npm-api.sh script will be documented in this file.

## [3.1.0] - 2025-06-01

### 🔧 DNS Provider Improvements

#### Cloudflare Credentials Format Enhancement
- **Fixed Cloudflare credentials parsing issue** (#17)
  - ❌ **BREAKING CHANGE**: Removed JSON format support for Cloudflare credentials
  - ✅ **NEW**: Support for multiple credential formats:
    ```diff
    - OLD (JSON format - no longer supported):
    --dns-credentials '{"dns_cloudflare_email":"user@email.com","dns_cloudflare_api_key":"key"}'
    
    + NEW (Key-value formats - recommended):
    --dns-credentials "dns_cloudflare_email = user@email.com; dns_cloudflare_api_key = key"
    --dns-credentials "dns_cloudflare_email = user@email.com, dns_cloudflare_api_key = key"
    --dns-credentials "dns_cloudflare_email = user@email.com
    dns_cloudflare_api_key = key"
    ```

#### Enhanced Credential Validation
- **Improved credential parsing**: Added support for single-line and multi-line formats
- **Better error messages**: Clear format examples when credentials are invalid
- **Enhanced API validation**: Real-time Cloudflare API key verification before certificate generation
- **Flexible separators**: Support for semicolon (`;`), comma (`,`), and newline separators

#### Fixed Examples and Documentation
- 🛠️ **Updated all help examples** to use the new credential format
- 🛠️ **Fixed error messages** with correct format examples
- 🛠️ **Updated README.md** with multiple format examples

### 📝 Technical Details

#### Files Modified
- `npm-api.sh`: Updated credential parsing logic in `verify_cloudflare_api_key()` function
- `npm-api.sh`: Fixed all example commands throughout the script
- `README.md`: Updated documentation with new format examples

#### Backward Compatibility
- ⚠️ **JSON format is no longer supported** for Cloudflare credentials
- ✅ **Migration path**: Replace JSON format with key-value format using any supported separator

### 🎯 Usage Examples

#### Single-line with semicolon (recommended)
```bash
./npm-api.sh --cert-generate "*.example.com" \
  --cert-email admin@example.com \
  --dns-provider cloudflare \
  --dns-credentials "dns_cloudflare_email = user@cloudflare.com; dns_cloudflare_api_key = your_api_key"
```

#### Single-line with comma
```bash
./npm-api.sh --cert-generate "*.example.com" \
  --cert-email admin@example.com \
  --dns-provider cloudflare \
  --dns-credentials "dns_cloudflare_email = user@cloudflare.com, dns_cloudflare_api_key = your_api_key"
```

#### Multi-line format
```bash
./npm-api.sh --cert-generate "*.example.com" \
  --cert-email admin@example.com \
  --dns-provider cloudflare \
  --dns-credentials "dns_cloudflare_email = user@cloudflare.com
dns_cloudflare_api_key = your_api_key"
```

## [3.0.1] - 2025-06-01

### 🔧 FIX wrong API endpoint

  **Issue**: Script used wrong API endpoint - only updated UI, not actual nginx config.

  **Fix**: Now uses NPM's native POST /api/nginx-proxy-hosts/{id}/{enable|disable} endpoints. 🔗[issue #18](https://github.com/Erreur32/nginx-proxy-manager-Bash-API/issues/18)
 

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
