<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Auth;

use Selivery\Enterprise\Models\AuthTokens;
use Throwable;

/**
 * Resolves an up-to-date access token using cached tokens and refresh logic.
 */
final class TokenProvider
{
    public function __construct(
        private readonly TokenCache $cache,
        private readonly TokenRefresher $refresher,
        private readonly ?string $fallbackSecret = null,
        private readonly ?\Selivery\Enterprise\Auth\AuthClient $authClient = null,
    ) {}

    /**
     * Returns a usable access token if available. Falls back to provided secret when cache is unavailable.
     */
    public function getToken(): ?string
    {
        // If cached token is valid, use it
        $token = $this->cache->getAccessTokenIfValid();
        if (is_string($token) && $token !== '') {
            return $token;
        }

        // Otherwise, try to refresh if we have a cached bundle with refresh token
        $bundle = $this->cache->get();
        $refreshToken = $bundle['refresh_token'] ?? '';
        $accessToken = $bundle['access_token'] ?? '';

        if ($refreshToken !== '') {
            try {
                $newTokens = $this->refresher->refresh($accessToken, $refreshToken);
                $this->cache->save($newTokens);
                return $newTokens->accessToken;
            } catch (Throwable) {
                // Clear cached entry to avoid loops and fall back
                $this->cache->invalidate();
            }
        }

        // Try to generate fresh tokens when no valid/refreshable token is present
        if ($this->authClient !== null) {
            try {
                $tokens = $this->authClient->generateToken();
                // Ensure cache is updated even if AuthClient didn't save
                $this->cache->save($tokens);
                return $tokens->accessToken;
            } catch (Throwable) {
                // fall through to fallback secret
            }
        }

        // Fallback to provided secret (may be null/empty)
        return $this->fallbackSecret ?: null;
    }
}
