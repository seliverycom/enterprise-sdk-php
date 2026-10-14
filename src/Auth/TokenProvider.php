<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Auth;

use Throwable;

/**
 * Resolves an up-to-date access token using cached tokens and refresh logic.
 */
final class TokenProvider
{
    public function __construct(
        private readonly TokenCache $cache,
        private readonly TokenRefresher $refresher,
        private readonly ?\Selivery\Enterprise\Auth\AuthClient $authClient = null,
    ) {
    }

    /**
     * Returns a usable access token if available.
     */
    public function getToken(): ?string
    {
        // If cached token is valid, use it
        $token = $this->cache->getAccessTokenIfValid();
        if (is_string($token) && $token !== '') {
            return $token;
        }

        return $this->renew($this->cache->get());
    }

    public function recoverToken(string $rejectedToken): string
    {
        // Read refresh credentials before removing the rejected bundle.
        $bundle = $this->cache->get();
        $this->rejectToken($rejectedToken);
        // A concurrent rotation may have completed while rejection was recorded.
        $current = $this->cache->get();
        if ($current !== null) {
            $bundle = $current;
        }

        if ($bundle !== null && $bundle['access_token'] !== $rejectedToken
            && time() < $bundle['expires_at'] - $this->cache->getSafetyWindowSeconds()) {
            return $bundle['access_token'];
        }

        return $this->renew($bundle) ?? throw new \RuntimeException('Unable to obtain a usable access token.');
    }

    public function rejectToken(string $rejectedToken): void
    {
        $this->cache->rejectAccessToken($rejectedToken);
    }

    /** @param array{access_token:string,refresh_token:string,expires_at:int}|null $bundle */
    private function renew(?array $bundle): ?string
    {
        $refreshToken = $bundle['refresh_token'] ?? '';
        $accessToken = $bundle['access_token'] ?? '';
        $refreshFailure = null;

        if (trim($refreshToken) !== '') {
            try {
                $newTokens = $this->refresher->refresh($accessToken, $refreshToken);
                if ($this->cache->isRejected($newTokens->accessToken)) {
                    throw new \RuntimeException('Token refresh returned a rejected access token.');
                }
                $this->cache->save($newTokens);
                return $newTokens->accessToken;
            } catch (Throwable $e) {
                $refreshFailure = $e;
                $this->rejectToken($accessToken);
                $newer = $this->cache->getAccessTokenIfValid();
                if ($newer !== null) {
                    return $newer;
                }
            }
        }

        // Try to generate fresh tokens when no valid/refreshable token is present
        if ($this->authClient !== null) {
            $tokens = $this->authClient->generateToken();
            if ($this->cache->isRejected($tokens->accessToken)) {
                throw new \RuntimeException('Token generation returned a rejected access token.');
            }
            $this->cache->save($tokens);
            return $tokens->accessToken;
        }

        if ($refreshFailure !== null) {
            throw $refreshFailure;
        }

        return null;
    }
}
