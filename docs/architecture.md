# Dockyard Architecture

Dockyard acts as an authenticated RBAC gateway and telemetry console in front of the Docker Engine REST API (`v1.41+`).

## Components

1. **Docker Engine Client (`internal/docker/client.go`)**: Speaks HTTP over Unix domain sockets (`unix:///var/run/docker.sock`) or TCP/HTTP (`DOCKER_HOST`), strips Docker's 8-byte multiplexed log headers (`DecodeDockerStream`), computes CPU delta & memory percentages from `/containers/{id}/stats`, and aggregates Docker Compose stacks via `com.docker.compose.project` labels.
2. **Auth & Rate Limiting (`internal/auth/auth.go`)**: PBKDF2-SHA256 (`120,000` iterations) password hashing, HMAC-SHA256 JWT tokens, and sliding-window IP rate limiting on login/registration.
3. **SQLite Store (`internal/store/store.go`)**: Stores users, roles (`admin`, `operator`, `viewer`), persistent `audit_logs`, and bounded 60-sample rolling `container_stats` history per container.
4. **REST API & Embedded SPA (`internal/api/`)**: Enforces role hierarchy, identifier validation regexes, and sensitive host bind-mount blocking (`/`, `/etc`, `/root`, `/var/run/docker.sock`) unless explicitly enabled.
