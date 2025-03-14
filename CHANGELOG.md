# Changelog

All notable changes to the nginx_proxy_manager_cli.sh script will be documented in this file.

## [2.8.0] - 2025-03-15

### 🔄 Breaking Changes
- **Host Creation Command Simplified**
  ```diff
  - OLD: ./npm-api.sh -d example.com -i 192.168.1.10 -p 8080
  + NEW: ./npm-api.sh --host-create example.com -i 192.168.1.10 -p 8080
  ```
  The `-d` option has been removed in favor of a more intuitive positional argument after `--host-create`

### ✨ New Features
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

### 🛠️ Code Optimizations
- Removed redundant parameter validations
- Streamlined host creation logic
- Unified error message format
- Better code organization

### 📚 Documentation
- Updated help messages with new command syntax
- Added more detailed examples
- Improved parameter descriptions
- Better organization of command options

### 🔐 Security
- Enhanced input validation
- Better parameter sanitization
- Improved error handling for invalid inputs

### 🔄 Migration Notes
To migrate to this version:
1. Update all scripts using `-d` to use `--host-create domain`
2. Review the new help menu (`--help`) for updated syntax
3. Test existing automation with new command format

### ✨ New Features
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

- New Access List Management Interface:
  - Interactive access list creation
  - Basic authentication support
  - IP whitelist management
  - Rule satisfaction options (ANY/ALL)

### 🔧 Technical Improvements
- Enhanced Token Management:
  - Automatic validation
  - Smart renewal
  - Secure storage

- Improved Host Management Commands:
  - Enhanced display with `host_show()`
  - Better error handling
  - Advanced configuration support

### 🎨 UI Enhancements
- Added color coding for better readability
- More detailed and explanatory error messages
- Improved command documentation
- New emojis for a more user-friendly interface

### 🛠️ Fixes and Optimizations
- Fixed SSL certificate management bugs
- Improved user input validation
- Optimized API requests
- Enhanced HTTP error handling

### 📚 Documentation
- Added detailed examples for each command
- Improved option documentation
- Better help and error messages

### 🔐 Security
- Enhanced user input validation
- Improved authentication token handling
- Protection against command injection

## [2.7.5] - 2025-03-08

### 🔄 Breaking Changes
- **Host Creation Syntax Changed**
  ```diff
  - OLD: ./nginx_proxy_manager_cli.sh -d example.com -i 192.168.1.10 -p 8080
  + NEW: ./nginx_proxy_manager_cli.sh --host-create example.com -i 192.168.1.10 -p 8080
  ```
  The `-d` option has been removed in favor of a more intuitive syntax where the domain is provided directly after `--host-create`

### ✨ New Features
- Change -d to --host-create for new host creation (Breaking Changes)
- Added dashboard display when no arguments are provided
- Reorganized help menu with clear categories.
- Code optimisation.

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
- User management
- Basic backup and restore functionality 