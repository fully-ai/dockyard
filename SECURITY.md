# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities responsibly via GitHub Security Advisories or repository issues without disclosing exploitable details publicly before a fix is released.

## Security Model & Socket Protection

Dockyard interacts with a local or remote Docker Engine API (`DOCKER_HOST`). Because access to the Docker daemon is root-equivalent on the host:

1. **Authentication & RBAC:** All `/api/*` endpoints (except `/api/health`, `/api/auth/login`, `/api/auth/register`) require a valid HMAC-SHA256 JWT token with `viewer`, `operator`, or `admin` role checks.
2. **Never Expose Unauthenticated:** Bind `DOCKYARD_ADDR` to `127.0.0.1` behind a TLS reverse proxy with strict firewalling.
3. **Identifier & Mount Guards:** Container/image/network/volume IDs and names are validated against strict allowlists, and privileged mode or sensitive host mounts (`/`, `/etc`, `/root`, `/var/run/docker.sock`) are blocked by default.
4. **Audit Logging:** Every mutating container, image, network, volume, stack, and RBAC operation is recorded in SQLite `audit_logs`.
