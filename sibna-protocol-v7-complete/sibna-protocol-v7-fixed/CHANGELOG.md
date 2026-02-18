# Changelog

All notable changes to this project will be documented in this file.

## [7.0.0] - 2024-02-17

### Fixed
- **Critical**: Added missing `storage_key` field to `SecureContext` struct
- **Critical**: Fixed type mismatch in `skipped_message_keys` HashMap key type
- **Critical**: Corrected function signatures in test code
- **High**: Replaced all unsafe `.unwrap()` calls with proper error handling
- **High**: Added input validation in all FFI functions
- **Medium**: Removed unused imports from crypto modules
- **Medium**: Enhanced error types with detailed context

### Security
- Added bounds checking on all array operations
- Implemented proper zeroization for sensitive data
- Added rate limiting to relay server
- Implemented secure headers middleware
- Added SQL injection prevention

### Changed
- Refactored `DoubleRatchetSession` for clearer API
- Improved serialization/deserialization for session state
- Enhanced documentation throughout the codebase

### Added
- Comprehensive error types with detailed messages
- Security audit documentation
- Docker support with multi-stage builds
- Health check endpoints

## [6.1.0] - Previous Release

### Known Issues (Fixed in 7.0.0)
- Missing `storage_key` field caused compilation failure
- Type mismatch in `skipped_message_keys`
- Test code had incorrect function signatures

---

See [SECURITY.md](./SECURITY.md) for detailed vulnerability fixes.
