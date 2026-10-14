# P3 Security Issues - Fix Plan

## Issues Identified from Security Audit

### 1. Missing Security Headers (HIGH PRIORITY)
- **CSP (Content-Security-Policy)**: Not implemented
- **HSTS (Strict-Transport-Security)**: Not implemented for production
- **X-Frame-Options**: Not implemented
- **X-Content-Type-Options**: Not implemented
- **Referrer-Policy**: Not implemented
- **Permissions-Policy**: Not implemented

### 2. CORS Configuration (MEDIUM)
- Development-only CORS with hardcoded localhost:3000
- No production allowlist configuration
- Should be configurable per environment

### 3. JWT Algorithm Confusion Protection (MEDIUM)
- Uses HS256 only (good)
- Should explicitly validate algorithm on decode to prevent confusion attacks
- Currently passes `algorithms=[settings.algorithm]` which is correct, but should ensure no "none" algorithm

### 4. Request Size Limits (MEDIUM)
- No body size limits configured
- Should add FastAPI request size limits

### 5. Cache Control on Sensitive Endpoints (MEDIUM)
- Auth endpoints should have `Cache-Control: no-store`
- No cache control headers on sensitive responses

### 6. Cookie Security (LOW-MEDIUM)
- `secure=True` always set (needs HTTPS even in dev)
- Consider `samesite="strict"` for refresh token

### 7. HSTS in Production (LOW)
- Should add HSTS header when `app_env == "production"`

### 8. Logging Sensitive Data (LOW)
- Need to verify no passwords/tokens logged
- Audit logging already validates IPs (good)

## Fix Implementation Order

1. **Security Headers Middleware** - Add CSP, HSTS, X-Frame-Options, etc.
2. **CORS Configuration** - Make configurable per environment
3. **JWT Algorithm Validation** - Explicit allowlist
4. **Request Size Limits** - Add middleware/dependency
5. **Cache Control** - Add to sensitive endpoints
6. **Cookie Settings** - Review and adjust
7. **HSTS Production** - Conditional header
8. **Logging Review** - Verify no secrets in logs