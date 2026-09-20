# API Contract v1
Authentication, tenant context, authorization, validation, rate limiting and request ID are required for every /api/v1 request.
Core resources: tenants, nodes, inbounds, clients, traffic, audit.
Provisioning and credential issuance require Idempotency-Key.
FastAPI OpenAPI is the executable API contract.
