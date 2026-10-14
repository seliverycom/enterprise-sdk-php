# Changelog

All notable changes to this project will be documented in this file.

## v2.0.1 - 2026-10-14

- fix: Recover once after an SDK-authenticated service request returns HTTP 401.
  - Reject the exact access token used; preserve a newer valid cached token.
  - Refresh rejected tokens, falling back to generation when refresh fails or is unusable.
  - Retry only the failed GET or POST, preserving its body, query, and caller headers.
  - Stop after a second service 401 and prevent reuse of both rejected tokens.
  - Propagate authentication failures before sending service requests; validate non-empty access tokens.
  - Preserve proactive expiry refresh and its safety window; tolerate cache failures using local tokens.
  - Keep constructor argument positions and send APIs; append optional HTTP recovery wiring and
    support an optional `http_client` Guzzle instance in `EnterpriseClient` options.
- feat: Add PSR-16 token caching with automatic refresh
  - New constructor injection on `EnterpriseClient` for `Psr\SimpleCache\CacheInterface` and `options`.
  - Tokens (access, refresh, expiry) are cached with a safety window (default 60s).
  - Service requests reuse cached tokens and refresh near expiry.
  - Cache failures are non-fatal; requests use freshly obtained access tokens.

