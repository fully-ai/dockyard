# Changelog

## [0.1.0] - 2026-11-18

### Added
- Docker Engine REST API v1.41+ client supporting Unix domain sockets (`unix:///var/run/docker.sock`) and TCP/HTTP endpoints.
- Container lifecycle management (list, inspect, create, start, stop, restart, remove), live resource usage charts (`CPU%` & `RAM%`), health checks, and multiplexed log tailing/SSE streaming.
- Image list, pull, tag, remove, and size breakdown analytics.
- Network and Volume inspection, creation, and removal.
- Docker Compose project/stack aggregation and bulk start/stop/restart actions.
- SQLite-backed RBAC (`admin`, `operator`, `viewer`), scrypt password hashing, HMAC-SHA256 JWT tokens, auth rate limiting, sensitive-mount guardrails, and persistent audit log.
