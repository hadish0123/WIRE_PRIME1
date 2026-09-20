# PRIMEVPN Security Baseline
- Argon2id password hashing.
- Short-lived JWT access tokens; secrets are environment-only.
- Tenant isolation is enforced server-side.
- Out-of-scope resources return 404.
- Node Agent has no arbitrary shell API.
- Configuration files are written atomically with restrictive permissions.
- Credentials and private material are not written to application logs.
- Production deployment must use TLS, strict CORS, CSRF protection for cookie authentication, rate limits, secret rotation and encrypted backups.
