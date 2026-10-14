<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Auth;

use Selivery\Enterprise\Http\HttpClient;
use Selivery\Enterprise\Exceptions\ApiException;
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
        $tokens = $this->parseTokens($data, '/v1/auth/generate-token');
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
        $tokens = $this->parseTokens($data, '/v1/auth/refresh-token');
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

    /** @param array<string, mixed> $data */
    private function parseTokens(array $data, string $path): AuthTokens
    {
        try {
            return AuthTokens::fromArray($data);
        } catch (\InvalidArgumentException $e) {
            throw new ApiException('Invalid authentication response from POST ' . $path . ': ' . $e->getMessage(), previous: $e);
        }
    }
}
