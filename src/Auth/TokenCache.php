<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Auth;

use Psr\SimpleCache\CacheInterface;
use Selivery\Enterprise\Models\AuthTokens;
use Throwable;

/**
 * PSR-16 backed token cache with safety window handling.
 */
final class TokenCache
{
    private ?CacheInterface $cache;
    private string $cacheKey;
    private int $safetyWindowSeconds;
    /** @var array{access_token:string,refresh_token:string,expires_at:int}|null */
    private ?array $localBundle = null;
    /** @var array<string, true> */
    private array $rejectedTokens = [];

    public function __construct(?CacheInterface $cache, string $cacheKey, int $safetyWindowSeconds = 60)
    {
        $this->cache = $cache;
        $this->cacheKey = $cacheKey;
        $this->safetyWindowSeconds = $safetyWindowSeconds;
    }

    /**
     * Save tokens to cache with TTL based on expires_at and safety window.
     */
    public function save(AuthTokens $tokens): void
    {
        if ($this->isRejected($tokens->accessToken)) {
            return;
        }
        $now = time();
        $expiresAt = $now + max(0, $tokens->sessionTtl);
        $bundle = [
            'access_token' => $tokens->accessToken,
            'refresh_token' => $tokens->refreshToken,
            'expires_at' => $expiresAt,
        ];
        $this->localBundle = $bundle;

        if ($this->cache === null) {
            return;
        }

        try {
            // Keep the full token bundle available for refresh until we explicitly rotate or invalidate it.
            $this->cache->set($this->cacheKey, $bundle);
        } catch (Throwable) {
            // Cache failures must not break requests.
        }
    }

    /**
     * Retrieve the cached bundle or null if unavailable.
     * @return array{access_token:string,refresh_token:string,expires_at:int}|null
     */
    public function get(): ?array
    {
        if ($this->cache === null) {
            return $this->localBundle;
        }
        try {
            $val = $this->cache->get($this->cacheKey);
        } catch (Throwable) {
            return $this->localBundle;
        }
        if (!is_array($val)) {
            return $this->localBundle;
        }
        // Normalize types
        $access = is_string($val['access_token'] ?? null) ? $val['access_token'] : '';
        $refresh = is_string($val['refresh_token'] ?? null) ? $val['refresh_token'] : '';
        $exp = isset($val['expires_at']) ? (int) $val['expires_at'] : 0;
        if (trim($access) === '' || $exp <= 0 || $this->isRejected($access)) {
            return $this->localBundle;
        }
        return [
            'access_token' => $access,
            'refresh_token' => $refresh,
            'expires_at' => $exp,
        ];
    }

    /**
     * Clear the cached entry.
     */
    public function invalidate(): void
    {
        $this->localBundle = null;
        if ($this->cache === null) {
            return;
        }
        try {
            $this->cache->delete($this->cacheKey);
        } catch (Throwable) {
            // ignore
        }
    }

    /**
     * Reject only the token used by the failed request, preserving newer tokens.
     * Remember rejection locally even if the cache cannot be read or deleted.
     */
    public function rejectAccessToken(string $accessToken): void
    {
        $this->rejectedTokens[hash('sha256', $accessToken)] = true;
        if (($this->localBundle['access_token'] ?? null) === $accessToken) {
            $this->localBundle = null;
        }
        if ($this->cache === null) {
            return;
        }
        try {
            $bundle = $this->cache->get($this->cacheKey);
            if (is_array($bundle) && ($bundle['access_token'] ?? null) === $accessToken) {
                $this->cache->delete($this->cacheKey);
            }
        } catch (Throwable) {
            // The local rejection still prevents reuse by this client.
        }
    }

    public function isRejected(string $accessToken): bool
    {
        return isset($this->rejectedTokens[hash('sha256', $accessToken)]);
    }

    /**
     * Returns access token if still valid, null otherwise.
     */
    public function getAccessTokenIfValid(): ?string
    {
        $bundle = $this->get();
        if ($bundle === null) {
            return null;
        }
        $now = time();
        if ($now >= ($bundle['expires_at'] - $this->safetyWindowSeconds)) {
            return null;
        }
        return $bundle['access_token'];
    }

    /**
     * Access to configured safety window for tests/consumers.
     */
    public function getSafetyWindowSeconds(): int
    {
        return $this->safetyWindowSeconds;
    }
}
