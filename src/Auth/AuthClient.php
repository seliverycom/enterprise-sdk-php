<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Auth;

use Selivery\Enterprise\Http\HttpClient;
use Selivery\Enterprise\Models\AuthTokens;
use Selivery\Enterprise\Models\TokenCheck;

final class AuthClient
{
    private ?TokenCache $tokenCache = null;

    public function __construct(
        private readonly HttpClient $generateTokenHttp,
        private readonly HttpClient $authHttp,
        ?TokenCache $tokenCache = null
    ) {
        $this->tokenCache = $tokenCache;
    }

    public function setTokenCache(TokenCache $cache): self
    {
        $this->tokenCache = $cache;
        return $this;
    }

    public function generateToken(): AuthTokens
    {
        $data = $this->generateTokenHttp->postJson('/v1/auth/generate-token');
        $tokens = AuthTokens::fromArray($data);
        if ($this->tokenCache) {
            $this->tokenCache->save($tokens);
        }
        return $tokens;
    }

    public function refreshToken(string $accessToken, string $refreshToken, bool $regenerateRefresh = false, ?int $ttl = null): AuthTokens
    {
        $body = [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'regenerate_refresh' => $regenerateRefresh,
        ];
        if ($ttl !== null) {
            $body['ttl'] = $ttl;
        }
        $data = $this->authHttp->postJson('/v1/auth/refresh-token', $body);
        $tokens = AuthTokens::fromArray($data);
        if ($this->tokenCache) {
            $this->tokenCache->save($tokens);
        }
        return $tokens;
    }

    public function checkToken(string $token): TokenCheck
    {
        $data = $this->authHttp->postJson('/v1/auth/check-token', ['token' => $token]);
        return TokenCheck::fromArray($data);
    }
}
