# Changelog

All notable changes to the **Middleware** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Guiding Categories:**
- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

---

## [Unreleased]

### Added

- Complete responsive management dashboard with overview, analytics, activity logs, security controls, list management, and settings views.
- Live activity updates over an authenticated WebSocket connection.
- Frontend loading, empty, error, offline, and authentication states.
- API and embedded-frontend tests for access control, resolver presets, routes, views, and responsive metadata.
- Comprehensive setup, architecture, configuration, API, security, testing, and deployment documentation.

### Changed

- Integrated the dashboard directly into the Go binary for a single-artifact deployment.
- Expanded management workflows for category/source controls, custom sources, resolver selection, and enforce/monitor modes.

### Fixed

- Corrected formatted logging calls identified by static analysis.

### Security

- Added bearer-token authentication, loopback Host validation, constant-time token comparison, and WebSocket origin/subprotocol checks.

## Template

## [X.Y.Z] - DD-MM-YYYY or [Unreleased]

### Added
- [Feature description] (#IssueOrPRNumber)

### Changed
- [Changed functionality description]

### Fixed
- [Bug fix description]

### Security
- [Security fix or hardening measure]

### Removed
- [Removed Features or Dependencies in the current project or release]

### Deprecated
- [Features scheduled for removal in future versions]
---

## [v0.1] - 15-08-2026

`Added`
- Initial Git Commit with Directory structure and dependencies.

## [v0.1] - 22-08-2026

`Added`
- Security Modules, Server with interceptor.
- bash scripts for tag-releases and packages.

## [v0.1] - 31-08-2026

`Added`
- Implemented TLS SNI Parser (Parses raw TCP packet payloads to extract the target domain from the TLS handshake extension).
- Implemented Packet Handler & Inspector.
- Added TLS SNI Inspector in main.go

## [v0.1] - 14-09-2026

`Changed`
- Updated proper NFQueueHandler, HandlePacket functions.
- Updated NFQUEUE initializer and proper Handler functions on main.go.
