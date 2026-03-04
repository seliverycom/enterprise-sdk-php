# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- feat: Add PSR-16 token caching with automatic refresh
  - New constructor injection on `EnterpriseClient` for `Psr\SimpleCache\CacheInterface` and `options`.
  - Tokens (access, refresh, expiry) are cached with a safety window (default 60s).
  - Service requests reuse cached tokens and refresh near expiry.
  - Cache failures are non-fatal; requests continue using fallback secret.

