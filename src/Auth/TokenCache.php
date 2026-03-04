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
        if ($this->cache === null) {
            return;
        }

        $now = time();
        $expiresAt = $now + max(0, $tokens->sessionTtl);
        $bundle = [
            'access_token' => $tokens->accessToken,
            'refresh_token' => $tokens->refreshToken,
            'expires_at' => $expiresAt,
        ];

        // TTL should consider safety window, never negative
        $ttl = max(0, $expiresAt - $now - $this->safetyWindowSeconds);

        try {
            // PSR-16 accepts TTL in seconds (int|DateInterval). We use int seconds.
            $this->cache->set($this->cacheKey, $bundle, $ttl);
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
            return null;
        }
        try {
            $val = $this->cache->get($this->cacheKey);
        } catch (Throwable) {
            return null;
        }
        if (!is_array($val)) {
            return null;
        }
        // Normalize types
        $access = isset($val['access_token']) ? (string) $val['access_token'] : '';
        $refresh = isset($val['refresh_token']) ? (string) $val['refresh_token'] : '';
        $exp = isset($val['expires_at']) ? (int) $val['expires_at'] : 0;
        if ($access === '' || $exp <= 0) {
            return null;
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
