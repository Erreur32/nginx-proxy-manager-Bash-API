# Changelog

All notable changes to the nginx_proxy_manager_cli.sh script will be documented in this file.


## [2.8.0] - 2024-03-XX

### 🔄 Breaking Changes
- **Host Creation Syntax Changed**
  ```diff
  - OLD: ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080
  + NEW: ./nginx_proxy_manager_cli.sh --host-create example.com -i 192.168.1.10 -p 8080
  ```
  The `-d` option has been removed in favor of a more intuitive syntax where the domain is provided directly after `--host-create`

### ✨ New Features
- Added dashboard display when no arguments are provided
- Reorganized help menu with clear categories and emojis
- Added French translations for all user messages

### 🛠️ Improvements
- Simplified host creation and update process
- Unified JSON handling for API requests
- Better validation of input parameters
- Cleaner code organization and variable management
- Improved error handling and user feedback

### 🐛 Bug Fixes
- Fixed token validation issues
- Improved error messages for invalid commands
- Better handling of SSL certificate operations

### 📝 Documentation
- Updated help messages with clearer examples
- Added detailed usage examples for each command
- Improved command descriptions
- Better organization of command options in help menu

### 🔍 Migration Guide
If you're upgrading from version 1.x, please note:
1. Update all your scripts that use `-d` for domain creation
2. Review the new help menu (`--help`) for updated command syntax
3. Test your existing automation with the new syntax

## [2.7.0] - 2025-03-09

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
- User management
- Basic backup and restore functionality 